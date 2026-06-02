"""Watson Web — OSINT investigation dashboard with SSE progress."""

from __future__ import annotations

import asyncio
import json
import os
import queue
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, make_response, render_template, request, stream_with_context, send_file
from flask_cors import CORS

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from watson.core.engine import Engine
from watson.core.models import Finding, FindingSeverity, Report
from watson.core.memory import memory as memory_engine
from watson.core.scheduler import Scheduler
from watson.tools.registry import registry
from watson.tools import *  # noqa — register all tools

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

# ── In-memory case store (lives until server restart) ──────────────
case_store: dict[str, dict] = {}

# ── Report store ────────────────────────────────────────────────────
report_store: dict[str, str] = {}  # client_id -> markdown report

# ── Last investigation context (for conversational follow-up) ──────
last_findings: list[dict] = []
last_query: str = ""
last_conversation: list[dict] = []  # chat history for current session


# ── SSE helper ─────────────────────────────────────────────────────
class SSEManager:
    """Thread-safe SSE queue per client."""

    def __init__(self):
        self.queues: dict[str, queue.Queue] = {}

    def create(self, client_id: str) -> queue.Queue:
        q: queue.Queue = queue.Queue()
        self.queues[client_id] = q
        return q

    def send(self, client_id: str, event: str, data: dict) -> None:
        q = self.queues.get(client_id)
        if q:
            q.put((event, data))

    def remove(self, client_id: str) -> None:
        self.queues.pop(client_id, None)


sse = SSEManager()


# ── Routes ─────────────────────────────────────────────────────────
@app.route("/")
def index():
    """Main interface — chat-based OSINT agent with image upload."""
    return render_template("chat.html")


@app.route("/dashboard")
def dashboard():
    """Legacy dashboard (kept for reference)."""
    return render_template("index.html")


@app.route("/api/tools")
def api_tools():
    """List all tool categories and tools."""
    categories = []
    for cat_info in registry.list_categories():
        cat_tools = []
        for tool_name in cat_info["tools"]:
            tool = registry.get(tool_name)
            if tool:
                cat_tools.append({
                    "name": tool.name,
                    "description": tool.description,
                    "free": tool.free_tier_available,
                    "rate_limit": tool.rate_limit_rps,
                })
        categories.append({
            "category": cat_info["category"],
            "count": cat_info["tool_count"],
            "tools": cat_tools,
        })
    return jsonify({"categories": categories, "total": registry.tool_count})


@app.route("/api/investigate", methods=["POST"])
def api_investigate():
    """Run an investigation, streaming progress via SSE."""
    data = request.get_json() or {}
    query = data.get("query", "").strip()
    tools_filter = data.get("tools")  # list of category names, optional
    case_id = data.get("case_id", str(uuid.uuid4())[:8])
    client_id = data.get("client_id", str(uuid.uuid4()))

    if not query:
        return jsonify({"error": "No query provided"}), 400

    q = sse.create(client_id)

    def _run():
        result = None
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(_investigate(query, tools_filter, client_id))
        except Exception as e:
            sse.send(client_id, "error", {"message": str(e)})
        finally:
            loop.close()
            sse.send(client_id, "done", {"result": result})
            # Keep queue alive briefly so SSE consumer can drain
            time.sleep(0.5)
            sse.remove(client_id)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    return jsonify({"client_id": client_id, "case_id": case_id})


@app.route("/api/stream/<client_id>")
def api_stream(client_id: str):
    """SSE endpoint — clients connect here after POSTing /api/investigate."""

    def generate():
        q = sse.queues.get(client_id)
        if not q:
            yield f"event: error\ndata: {json.dumps({'message': 'No investigation for this client'})}\n\n"
            return

        while True:
            try:
                event, data = q.get(timeout=120)
                yield f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"
                if event == "done":
                    break
            except queue.Empty:
                yield f"event: error\ndata: {json.dumps({'message': 'Stream timeout'})}\n\n"
                break

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/api/cases", methods=["GET", "POST"])
def api_cases():
    if request.method == "POST":
        data = request.get_json() or {}
        case = {
            "id": data.get("id", str(uuid.uuid4())[:8]),
            "name": data.get("name", "Untitled Case"),
            "query": data.get("query", ""),
            "created_at": datetime.now().isoformat(),
            "status": data.get("status", "open"),
            "report": data.get("report"),
        }
        case_store[case["id"]] = case
        return jsonify(case)

    # GET — list all cases
    return jsonify(list(case_store.values()))


@app.route("/api/cases/<case_id>", methods=["GET", "DELETE", "PATCH"])
def api_case(case_id: str):
    if request.method == "GET":
        case = case_store.get(case_id)
        if not case:
            return jsonify({"error": "Case not found"}), 404
        return jsonify(case)

    if request.method == "DELETE":
        case_store.pop(case_id, None)
        return jsonify({"ok": True})

    if request.method == "PATCH":
        data = request.get_json() or {}
        case = case_store.get(case_id)
        if not case:
            return jsonify({"error": "Case not found"}), 404
        case.update(data)
        return jsonify(case)


# ── Investigation runner ───────────────────────────────────────────
async def _investigate(
    query: str, tools_filter: list[str] | None, client_id: str
) -> dict | None:
    """Run the investigation and stream progress events.
    
    UPGRADED: Uses ReasoningEngine for semantic query understanding
    before tool dispatch. Reasoning is streamed via SSE so the frontend
    can show the investigation strategy card.
    """
    from watson.core.dispatcher import Dispatcher
    from watson.core.models import FindingSource, InvestigationRequest
    from watson.core.reasoning import ReasoningEngine
    from watson.config import load_config

    # Send start event
    sse.send(client_id, "start", {
        "query": query,
        "tools": tools_filter,
        "timestamp": datetime.now().isoformat(),
    })

    sse.send(client_id, "progress", {
        "phase": "reasoning",
        "message": "Analysing query with semantic reasoning...",
    })

    # ── Check memory for past context ──────────────────────────
    past_context = memory_engine.get_context_for_target(query)
    if past_context:
        sse.send(client_id, "memory_context", {
            "past_investigations": len(past_context["past_investigations"]),
            "relevant_findings": len(past_context["relevant_findings"]),
            "entity_history": past_context["entity_history"],
        })

    # ── Set up reasoning engine ────────────────────────────────
    config = load_config()
    api_keys = config.get("watson", {}).get("api_keys", {})

    reasoning = ReasoningEngine()

    # SSE callback for reasoning results
    def on_reasoning(result):
        sse.send(client_id, "reasoning", {
            "phase": "plan_reasoning",
            "investigation_goal": result.investigation_goal,
            "key_entities": result.key_entities,
            "search_targets": result.search_targets,
            "recommended_sources": result.recommended_sources,
            "investigation_angles": result.investigation_angles,
            "target_type": result.target_type,
            "confidence": result.confidence,
        })

    # ── Determine tool categories ──────────────────────────────
    cats = None
    if tools_filter:
        cat_list = []
        for t in tools_filter:
            try:
                cat_list.append(FindingSource(t.lower()))
            except ValueError:
                pass
        if cat_list:
            cats = cat_list

    dispatcher = Dispatcher(
        api_keys=api_keys,
        reasoning_engine=reasoning,
        on_reasoning=on_reasoning,
    )
    request_obj = InvestigationRequest(query=query, tools=cats)

    tasks = dispatcher._decompose(request_obj)

    sse.send(client_id, "progress", {
        "phase": "dispatch",
        "message": f"Dispatching across {len(tasks)} tools...",
        "tool_count": len(tasks),
        "tools": [t.tool_name for t in tasks],
        "reasoning_used": reasoning.available,
        "target_type": dispatcher.last_reasoning.target_type if dispatcher.last_reasoning else "unknown",
    })

    # ── Run all tools in parallel ─────────────────────────────
    all_findings: list[Finding] = []
    tool_stats: dict[str, dict] = {}

    # Wrap _run_tool to capture SSE events
    async def _run_with_sse(task):
        tool_name = task.tool_name
        sse.send(client_id, "tool_start", {
            "tool": tool_name,
            "category": task.tool_category.value,
        })
        try:
            findings = await dispatcher._run_tool(task)
            all_findings.extend(findings)

            finding_dicts = [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "confidence": f.confidence,
                    "description": f.description[:200],
                    "evidence": f.evidence[:3],
                }
                for f in findings
            ]

            tool_stats[tool_name] = {
                "status": "success" if findings else "empty",
                "finding_count": len(findings),
                "findings": finding_dicts,
            }

            sse.send(client_id, "tool_complete", {
                "tool": tool_name,
                "category": task.tool_category.value,
                "finding_count": len(findings),
                "findings": finding_dicts,
            })
        except Exception as e:
            tool_stats[tool_name] = {"status": "error", "error": str(e)}
            sse.send(client_id, "tool_error", {
                "tool": tool_name,
                "error": str(e),
            })

    await asyncio.gather(*[_run_with_sse(task) for task in tasks])

    # ── Cross-reference (LLM-powered) ──────────────────────────
    from watson.core.crossref import CrossReferencer
    
    sse.send(client_id, "progress", {
        "phase": "crossref",
        "message": "Cross-referencing findings with LLM analysis...",
    })
    
    xref = CrossReferencer()
    cross_refs = xref.cross_reference(all_findings)
    
    sse.send(client_id, "cross_reference", {
        "connections": [
            {
                "title": cr.title,
                "description": cr.description[:300],
                "sources": cr.sources,
                "connection_type": cr.connection_type,
                "confidence": cr.confidence,
            }
            for cr in cross_refs
        ],
        "total": len(cross_refs),
        "llm_powered": xref.available,
    })

    # ── Generate report ────────────────────────────────────────
    from watson.core.reporter import Reporter
    reporter = Reporter(cross_reference=False)  # we do our own cross-ref
    report = reporter.generate(query, all_findings)
    
    # Add cross-references to the report
    for cr in xref.to_findings(cross_refs):
        report.cross_references.append(cr)

    # ── Save to memory ─────────────────────────────────────────
    findings_list = [
        {
            "id": f.id,
            "title": f.title,
            "description": f.description,
            "source": f.source.value,
            "tool": f.tool,
            "severity": f.severity.value,
            "confidence": f.confidence,
            "evidence": f.evidence,
        }
        for f in report.findings
    ]

    reasoning_dict = None
    if dispatcher.last_reasoning:
        reasoning_dict = dispatcher.last_reasoning.to_dict()

    risk = _compute_risk_score(report.by_severity)
    memory_engine.save_investigation(
        query=query,
        findings=findings_list,
        reasoning=reasoning_dict,
        target_type=dispatcher.last_reasoning.target_type if dispatcher.last_reasoning else "unknown",
        risk_level=risk["level"],
    )

    result = {
        "query": query,
        "findings": report.total_findings,
        "sources": len(report.by_source),
        "by_severity": report.by_severity,
        "by_source": report.by_source,
        "summary": report.summary,
        "generated_at": report.generated_at.isoformat(),
        "findings_list": [
            {
                "id": f.id,
                "title": f.title,
                "description": f.description,
                "source": f.source.value,
                "tool": f.tool,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "evidence": f.evidence,
            }
            for f in report.findings
        ],
        "cross_references": [
            {
                "id": cr.id,
                "title": cr.title,
                "description": cr.description,
                "evidence": cr.evidence,
            }
            for cr in report.cross_references
        ],
        "tool_stats": tool_stats,
    }

    return result


# ── LLM helper ──────────────────────────────────────────────────────
def _call_llm(api_key: str, api_base: str, model: str, system: str, prompt: str) -> str:
    """Call an OpenAI-compatible LLM API."""
    import urllib.request as ur

    if not api_key:
        raise ValueError("No API key configured. Set it in Settings (⚙).")

    base = (api_base or "https://api.deepseek.com/v1").rstrip("/")
    body = json.dumps({
        "model": model or "deepseek-chat",
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.3,
        "max_tokens": 1500,
    }).encode()

    req = ur.Request(f"{base}/chat/completions", data=body, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    })
    resp = ur.urlopen(req, timeout=60)
    data = json.loads(resp.read())
    return data["choices"][0]["message"]["content"]


# ── Conclusion + Export ─────────────────────────────────────────────
@app.route("/api/conclude", methods=["POST"])
def api_conclude():
    """Generate an AI conclusion from investigation findings."""
    data = request.get_json() or {}
    findings = data.get("findings", [])
    query = data.get("query", "")
    api_key = data.get("api_key", "")
    api_base = data.get("api_base", "")
    model = data.get("model", "deepseek-chat")

    if not findings:
        return jsonify({"error": "No findings to conclude from"}), 400

    # Build prompt
    findings_text = "\n\n".join(
        f"[{f.get('severity','?').upper()}] {f.get('title','')}\n"
        f"Source: {f.get('source','')} | Confidence: {int(f.get('confidence',0)*100)}%\n"
        f"{f.get('description','')[:300]}\n"
        f"Evidence: {', '.join(f.get('evidence',[])[:3])}"
        for f in findings[:15]
    )

    system = (
        "You are Watson, an OSINT investigation analyst. "
        "Based on raw investigation findings, write a concise executive conclusion. "
        "Structure it as:\n"
        "1. **Key Assessment** (2-3 sentences — what matters most)\n"
        "2. **Critical Findings** (bullet list of the most important items)\n"
        "3. **Risk Level** (LOW/MEDIUM/HIGH/CRITICAL with 1-line justification)\n"
        "4. **Recommended Actions** (2-3 concrete next steps)\n"
        "Be factual, concise, and avoid speculation. Use markdown."
    )

    prompt = (
        f"Investigation query: {query}\n\n"
        f"Findings ({len(findings)} total):\n{findings_text}\n\n"
        "Write the executive conclusion."
    )

    try:
        conclusion = _call_llm(api_key, api_base, model, system, prompt)
        return jsonify({"conclusion": conclusion, "model": model})
    except ValueError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        return jsonify({"error": f"LLM call failed: {str(e)}"}), 500


@app.route("/api/export/json", methods=["POST"])
def api_export_json():
    """Export case report as structured JSON intelligence brief."""
    data = request.get_json() or {}
    report = data.get("report", {})
    case_name = data.get("case_name", "investigation")
    query = data.get("query", "")
    conclusion = data.get("conclusion", "")
    synthesis = data.get("synthesis")  # optional LLM-generated narrative

    findings = report.get("findings_list", [])
    xrefs = report.get("cross_references", [])

    # Group findings by severity for the brief
    by_severity: dict[str, list] = {}
    for f in findings:
        sev = f.get("severity", "info")
        by_severity.setdefault(sev, []).append(f)

    # Extract entities mentioned across findings
    entities = _extract_entities(findings)

    # Risk score: weighted by severity counts
    risk_score = _compute_risk_score(report.get("by_severity", {}))

    export = {
        "report_type": "OSINT Intelligence Brief",
        "case": case_name,
        "query": query,
        "generated_at": datetime.now().isoformat(),
        "risk_assessment": {
            "score": risk_score["score"],
            "level": risk_score["level"],
            "justification": risk_score["justification"],
        },
        "executive_summary": synthesis.get("summary") if synthesis else _auto_summary(findings, query),
        "key_findings": [
            {
                "title": f["title"],
                "severity": f["severity"],
                "confidence": f["confidence"],
                "source": f["source"],
                "tool": f["tool"],
                "analysis": f["description"],
                "evidence": f.get("evidence", []),
            }
            for f in _prioritize_findings(findings)
        ],
        "entities": entities,
        "connections": [
            {
                "title": cr["title"],
                "insight": cr["description"],
                "evidence": cr.get("evidence", []),
            }
            for cr in xrefs
        ],
        "recommended_actions": synthesis.get("actions") if synthesis else _default_actions(findings),
        "investigation_metadata": {
            "total_findings": report.get("findings", 0),
            "sources_used": report.get("sources", 0),
            "by_severity": report.get("by_severity", {}),
            "by_source": report.get("by_source", {}),
        },
    }

    if conclusion:
        export["ai_conclusion"] = conclusion
    if synthesis:
        export["ai_synthesis"] = synthesis

    outdir = Path(__file__).parent / "exports"
    outdir.mkdir(exist_ok=True)
    fname = f"{case_name.replace(' ','_')}_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
    path = outdir / fname
    path.write_text(json.dumps(export, indent=2, default=str))

    return send_file(path, as_attachment=True, download_name=fname)


@app.route("/api/export/md", methods=["POST"])
def api_export_md():
    """Export case report as Markdown intelligence brief."""
    data = request.get_json() or {}
    report = data.get("report", {})
    case_name = data.get("case_name", "investigation")
    query = data.get("query", "")
    conclusion = data.get("conclusion", "")
    synthesis = data.get("synthesis")  # optional LLM narrative

    findings = report.get("findings_list", [])
    xrefs = report.get("cross_references", [])
    sev = report.get("by_severity", {})
    sources = report.get("by_source", {})

    # Group findings by severity
    by_severity: dict[str, list] = {}
    for f in findings:
        by_severity.setdefault(f.get("severity", "info"), []).append(f)

    risk = _compute_risk_score(sev)
    entities = _extract_entities(findings)

    now = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    md = f"""# 🕵️ WATSON OSINT Intelligence Brief

**Case:** {case_name}  
**Query:** {query}  
**Date:** {now}  
**Classification:** CONFIDENTIAL

---

## 📊 Executive Summary

"""
    if synthesis and synthesis.get("summary"):
        md += synthesis["summary"] + "\n\n"
    else:
        md += _auto_summary(findings, query) + "\n\n"

    # Risk bar
    md += f"""### Risk Assessment: {risk['level']}

| Metric | Value |
|---|---|
| Risk Score | {risk['score']}/10 |
| Critical | {sev.get('critical', 0)} |
| High | {sev.get('high', 0)} |
| Medium | {sev.get('medium', 0)} |
| Low | {sev.get('low', 0)} |
| Total Findings | {len(findings)} |
| Sources Probed | {len(sources)} |

**Justification:** {risk['justification']}

---

"""

    # Key Findings — prioritized, with analysis
    prioritized = _prioritize_findings(findings)
    if prioritized:
        md += "## 🔍 Key Findings\n\n"
        for f in prioritized:
            icon = {"critical": "🚨", "high": "🔴", "medium": "🟡", "low": "⚪", "info": "ℹ️"}.get(f["severity"], "•")
            md += f"### {icon} [{f['severity'].upper()}] {f['title']}\n\n"
            md += f"**Analysis:** {f['description']}\n\n"
            md += f"**Source:** {f['source']} ({f['tool']}) | **Confidence:** {int(f['confidence']*100)}%\n\n"
            if f.get("evidence"):
                md += "**Evidence:**\n"
                for e in f["evidence"]:
                    md += f"- [{e}]({e})\n"
                md += "\n"
            md += "\n"

    # Entities discovered
    if entities:
        md += "## 👤 Entities Identified\n\n"
        if entities.get("people"):
            md += "### People\n" + "\n".join(f"- {p}" for p in entities["people"][:10]) + "\n\n"
        if entities.get("organizations"):
            md += "### Organizations\n" + "\n".join(f"- {o}" for o in entities["organizations"][:10]) + "\n\n"
        if entities.get("domains"):
            md += "### Domains / Infrastructure\n" + "\n".join(f"- {d}" for d in entities["domains"][:10]) + "\n\n"
        if entities.get("locations"):
            md += "### Locations\n" + "\n".join(f"- {loc}" for loc in entities["locations"][:10]) + "\n\n"

    # Connections
    if xrefs:
        md += "## 🔗 Connections & Link Analysis\n\n"
        for cr in xrefs:
            md += f"### {cr['title']}\n\n"
            md += f"{cr['description']}\n\n"
            if cr.get("evidence"):
                for e in cr["evidence"]:
                    md += f"- [{e}]({e})\n"
            md += "\n"

    # AI Conclusion
    if conclusion:
        md += "## 🧠 AI Analysis\n\n"
        md += conclusion + "\n\n"

    # Synthesis
    if synthesis:
        if synthesis.get("narrative"):
            md += "## 📝 Investigative Narrative\n\n"
            md += synthesis["narrative"] + "\n\n"
        if synthesis.get("actions"):
            md += "## ⚡ Recommended Actions\n\n"
            for action in synthesis["actions"]:
                md += f"- {action}\n"
            md += "\n"
    else:
        md += "## ⚡ Recommended Actions\n\n"
        for action in _default_actions(findings):
            md += f"- {action}\n"
        md += "\n"

    # Evidence trail (appendix)
    all_evidence: list[str] = []
    for f in findings:
        all_evidence.extend(f.get("evidence", []))
    all_evidence = list(dict.fromkeys(all_evidence))  # deduplicate
    if all_evidence:
        md += "## 📎 Evidence Trail\n\n"
        grouped: dict[str, list[str]] = {}
        for url in all_evidence:
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc or url[:30]
            except Exception:
                domain = url[:30]
            grouped.setdefault(domain, []).append(url)
        for domain, urls in sorted(grouped.items()):
            md += f"### {domain}\n"
            for u in urls:
                md += f"- [{u}]({u})\n"
            md += "\n"

    # Metadata footer
    md += f"""---

## 📋 Investigation Metadata

| Field | Value |
|---|---|
| Query | {query} |
| Generated | {now} |
| Total Findings | {len(findings)} |
| Sources Used | {len(sources)} |
| Tools | Watson OSINT v1.0 |

*Generated by Watson OSINT — Bellingcat-grade investigation toolkit*
"""

    outdir = Path(__file__).parent / "exports"
    outdir.mkdir(exist_ok=True)
    fname = f"{case_name.replace(' ','_')}_{datetime.now().strftime('%Y%m%d_%H%M')}.md"
    path = outdir / fname
    path.write_text(md)

    return send_file(path, as_attachment=True, download_name=fname)


@app.route("/api/synthesize", methods=["POST"])
def api_synthesize():
    """Use LLM to generate a narrative intelligence brief from findings."""
    data = request.get_json() or {}
    findings = data.get("findings", [])
    query = data.get("query", "")
    api_key = data.get("api_key", "")
    api_base = data.get("api_base", "")
    model = data.get("model", "deepseek-chat")

    if not api_key:
        return jsonify({"error": "No API key configured"}), 401
    if not findings:
        return jsonify({"error": "No findings to synthesize"}), 400

    findings_text = "\n\n".join(
        f"[{f.get('severity','?').upper()}] {f.get('title','')}\n"
        f"Source: {f.get('source','')} | Confidence: {int(f.get('confidence',0)*100)}%\n"
        f"Analysis: {f.get('description','')[:300]}\n"
        f"Evidence: {', '.join(f.get('evidence',[])[:3])}"
        for f in findings[:20]
    )

    system = (
        "You are a senior OSINT intelligence analyst. Given raw investigation findings, "
        "produce a JSON response with three fields:\n"
        "1. \"summary\": A concise executive summary (3-4 sentences connecting the dots)\n"
        "2. \"narrative\": A 2-3 paragraph investigative narrative — tell the story these findings reveal. "
        "Connect entities, timelines, and patterns. Be factual but compelling.\n"
        "3. \"actions\": A JSON array of 4-6 concrete, actionable next steps. "
        "Each should be a specific action an investigator should take (e.g., 'Subpoena domain registrar for X', "
        "'Cross-reference phone number Y with carrier Z', 'Monitor social media account @handle for 72 hours'). "
        "Be specific, not generic.\n\n"
        "Return ONLY valid JSON, no markdown fences, no other text."
    )

    prompt = (
        f"Investigation query: {query}\n\n"
        f"Raw findings ({len(findings)} total):\n{findings_text}\n\n"
        "Synthesize these into an intelligence brief. Return JSON with summary, narrative, and actions fields."
    )

    raw = ""
    try:
        raw = _call_llm(api_key, api_base, model, system, prompt)
        # Strip markdown code fences if present
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
            if raw.endswith("```"):
                raw = raw[:-3]
            raw = raw.strip()
        synthesis = json.loads(raw)
        return jsonify(synthesis)
    except json.JSONDecodeError:
        return jsonify({"error": "LLM returned invalid JSON. Try again.", "raw": raw[:500] if 'raw' in dir() else ""}), 500
    except ValueError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        return jsonify({"error": f"Synthesis failed: {str(e)}"}), 500


# ── Export helpers ───────────────────────────────────────────────────
def _prioritize_findings(findings: list) -> list:
    """Sort findings: critical first, then by confidence."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda f: (order.get(f.get("severity", "info"), 5), -f.get("confidence", 0)))


def _compute_risk_score(by_severity: dict) -> dict:
    """Compute a weighted risk score from severity counts."""
    weights = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
    total = 0
    weighted = 0
    for sev, count in by_severity.items():
        w = weights.get(sev, 1)
        weighted += count * w
        total += count

    if total == 0:
        return {"score": 0, "level": "UNKNOWN", "justification": "No findings to assess."}

    raw_score = min(10, round(weighted / max(total, 1) * 1.5, 1))
    if raw_score >= 8:
        level = "🔴 CRITICAL"
        justification = "Multiple high-severity findings with strong evidence. Immediate action required."
    elif raw_score >= 5:
        level = "🟠 HIGH"
        justification = "Significant concerns identified. Prompt investigation and mitigation recommended."
    elif raw_score >= 3:
        level = "🟡 MEDIUM"
        justification = "Notable findings warranting attention. Monitor and follow up."
    else:
        level = "🟢 LOW"
        justification = "Limited findings of concern. Routine monitoring sufficient."

    return {"score": raw_score, "level": level, "justification": justification}


def _extract_entities(findings: list) -> dict:
    """Extract potential entities from finding titles and descriptions."""
    import re
    people: set[str] = set()
    orgs: set[str] = set()
    domains: set[str] = set()
    locations: set[str] = set()

    # Email patterns → people
    email_re = re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+')
    # Domain patterns
    domain_re = re.compile(r'(?:[\w-]+\.)+[a-z]{2,}')
    # Capitalized names (heuristic)
    name_re = re.compile(r'\b([A-Z][a-z]+(?:\s[A-Z][a-z]+)+)\b')

    for f in findings:
        text = f.get("title", "") + " " + f.get("description", "")
        for email in email_re.findall(text):
            people.add(email)
        for domain in domain_re.findall(text):
            if len(domain) > 5 and not domain.startswith("http"):
                domains.add(domain)
        for name in name_re.findall(text):
            if not any(w.lower() in {"the", "and", "for", "with", "from", "this", "that"} for w in name.split()):
                people.add(name)

    return {
        k: sorted(list(v))
        for k, v in {"people": people, "organizations": orgs, "domains": domains, "locations": locations}.items()
        if v
    }


def _auto_summary(findings: list, query: str) -> str:
    """Generate a basic auto-summary without LLM."""
    if not findings:
        return f"No actionable findings discovered for query: \"{query}\"."
    high = sum(1 for f in findings if f.get("severity") in ("critical", "high"))
    total = len(findings)
    sources = len({f.get("source") for f in findings})
    return (
        f"Investigation of \"{query}\" yielded {total} findings across {sources} sources, "
        f"including {high} high or critical items. "
        f"Key areas of concern involve {', '.join(list(dict.fromkeys(f.get('source','?') for f in findings[:5])))}. "
        f"Review findings below for detailed analysis and recommended actions."
    )


def _default_actions(findings: list) -> list:
    """Generate default recommended actions from finding patterns."""
    actions = []
    sources = {f.get("source") for f in findings}
    has_people = "people" in sources
    has_websites = "websites" in sources
    has_corporate = "corporate" in sources
    has_social = "social_media" in sources
    high_count = sum(1 for f in findings if f.get("severity") in ("critical", "high"))

    if high_count > 0:
        actions.append(f"Escalate {high_count} high/critical findings to security team for immediate triage")
    if has_websites:
        actions.append("Perform deeper WHOIS history analysis and check for associated domains")
    if has_people:
        actions.append("Cross-reference identified individuals against sanctions lists and adverse media")
    if has_corporate:
        actions.append("Pull full corporate filings and check for beneficial ownership chains")
    if has_social:
        actions.append("Monitor identified social media accounts for 30-day pattern analysis")
    actions.append("Archive all evidence URLs with timestamps for chain of custody")
    actions.append("Schedule 7-day follow-up investigation to track changes")

    return actions[:6]


# ── Bellingcat Toolkit Endpoints ────────────────────────────────────
@app.route("/api/bellingcat/summary")
def api_bellingcat_summary():
    """Return Bellingcat toolkit summary (338 tools across 24 categories)."""
    from watson.bellingcat_registry import registry as bc_registry
    return jsonify(bc_registry.summary())


@app.route("/api/bellingcat/tools")
def api_bellingcat_tools():
    """List all Bellingcat tools, optionally filtered by category."""
    from watson.bellingcat_registry import registry as bc_registry
    category = request.args.get("category")
    search = request.args.get("search")
    bc_registry.load()

    if category:
        tools = bc_registry.get_category(category)
    elif search:
        tools = bc_registry.search(search, limit=50)
    else:
        tools = bc_registry.tools

    return jsonify({
        "count": len(tools),
        "tools": [
            {
                "category": t.category,
                "name": t.name,
                "url": t.url,
                "description": t.description,
                "cost": t.cost,
                "details": t.details,
                "is_free": t.is_free,
            }
            for t in tools
        ],
    })


@app.route("/api/bellingcat/categories")
def api_bellingcat_categories():
    """List all Bellingcat categories with tool counts."""
    from watson.bellingcat_registry import registry as bc_registry
    bc_registry.load()
    return jsonify({
        "categories": bc_registry.categories,
        "total_tools": len(bc_registry.tools),
        "target_types": list(bc_registry.classify.__code__.co_consts),  # fallback
        "by_category": {
            cat: len(bc_registry.get_category(cat))
            for cat in bc_registry.categories
        },
    })


@app.route("/api/bellingcat/classify", methods=["POST"])
def api_bellingcat_classify():
    """Classify a target and return relevant Bellingcat tools."""
    from watson.bellingcat_registry import registry as bc_registry
    from watson.tools.bellingcat import BellingcatToolkit

    data = request.get_json(force=True, silent=True) or {}
    query = data.get("query", "")

    if not query:
        return jsonify({"error": "Missing query"}), 400

    toolkit = BellingcatToolkit()
    target_type = toolkit._classify_target(query, "")
    tools = bc_registry.tools_for_target(target_type)
    categories = bc_registry.classify(target_type)
    url_templates = bc_registry.get_url_templates()

    # Build parameterized URLs for this query
    ready_urls = {}
    for t in tools:
        url = bc_registry.build_url(t.name, query)
        if url:
            ready_urls[t.name] = url

    return jsonify({
        "query": query,
        "target_type": target_type,
        "category_count": len(categories),
        "categories": categories,
        "tool_count": len(tools),
        "ready_urls": ready_urls,
        "ready_count": len(ready_urls),
        "tools": [
            {
                "name": t.name,
                "category": t.category,
                "description": t.description,
                "cost": t.cost,
                "is_free": t.is_free,
                "url": t.url,
                "details": t.details,
                "ready_url": ready_urls.get(t.name),
            }
            for t in tools[:50]
        ],
    })


@app.route("/api/bellingcat/investigate", methods=["POST"])
def api_bellingcat_investigate():
    """Run a full Bellingcat investigation — SSE stream like /api/investigate."""
    from watson.tools.bellingcat import BellingcatToolkit

    data = request.get_json(force=True, silent=True) or {}
    query = data.get("query", "")
    client_id = data.get("client_id", "bellingcat-" + str(uuid.uuid4())[:8])

    if not query:
        return jsonify({"error": "Missing query"}), 400

    client_id = "bc-" + client_id

    def generate():
        sse.create(client_id)
        q = sse.queues[client_id]

        async def run():
            toolkit = BellingcatToolkit()
            findings = await toolkit.investigate(query, data.get("context", ""))
            for f in findings:
                sse.send(client_id, "finding", {
                    "id": f.id,
                    "source": f.source.value if hasattr(f.source, "value") else str(f.source),
                    "tool": f.tool,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence,
                    "confidence": f.confidence,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "metadata": f.metadata,
                })
            sse.send(client_id, "done", {
                "total_findings": len(findings),
                "query": query,
            })

        import asyncio
        loop = asyncio.new_event_loop()
        loop.run_until_complete(run())
        loop.close()

    thread = threading.Thread(target=generate, daemon=True)
    thread.start()

    @stream_with_context
    def stream():
        q = sse.queues.get(client_id)
        if not q:
            return

        import queue as qmod
        while True:
            try:
                event, data = q.get(timeout=120)
                yield f"event: {event}\ndata: {json.dumps(data)}\n\n"
                if event == "done":
                    break
            except qmod.Empty:
                yield f"event: heartbeat\ndata: {{}}\n\n"
            except GeneratorExit:
                break
        sse.remove(client_id)

    return Response(
        stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── Agent (Chat + Autonomous Investigation) ────────────────────────
@app.route("/chat")
def chat_view():
    """Serve the chat-based agent interface."""
    resp = make_response(render_template("chat.html"))
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.route("/api/agent/investigate", methods=["POST"])
def api_agent_investigate():
    """Start autonomous investigation — returns client_id for SSE stream."""

    data = request.get_json(force=True, silent=True) or {}
    query = data.get("query", "")
    depth = data.get("depth", 2)
    context = data.get("context", "")
    image_path = data.get("image_path", None)

    if not query:
        return jsonify({"error": "Missing query"}), 400

    client_id = "agent-" + str(uuid.uuid4())[:8]
    q = sse.create(client_id)

    def generate():
        def push(event_type, data):
            sse.send(client_id, event_type, data)
        try:
            events = asyncio.run(_run_agent(query, depth, context, push, image_path))
        except Exception as e:
            sse.send(client_id, "error", {"message": str(e)})
        finally:
            time.sleep(0.5)
            sse.send(client_id, "_close", {})

    thread = threading.Thread(target=generate, daemon=True)
    thread.start()

    return jsonify({"client_id": client_id, "status": "started"})


async def _run_agent(query: str, depth: int, context: str = "", on_event=None, image_path: str = None) -> list[dict]:
    """Run the agent investigation (async, invoked from a thread)."""
    from watson.agent import OSINTAgent
    from watson.config import load_config
    
    # Load API keys from config.toml (newscatcher, opensanctions, haveibeenpwned, etc.)
    config = load_config()
    api_keys = config.get("watson", {}).get("api_keys", {})
    
    agent = OSINTAgent(depth=depth, api_keys=api_keys)
    return await agent.investigate(query, context=context, on_event=on_event, image_path=image_path)


@app.route("/api/agent/chat", methods=["POST"])
def api_agent_chat():
    """Chat with Watson about investigation findings using LLM.

    Body: {"message": "tell me about...", "findings": [...], "history": [...]}
    Returns: {"reply": "..."}
    """
    data = request.get_json(force=True, silent=True) or {}
    message = data.get("message", "").strip()
    findings = data.get("findings", [])
    history = data.get("history", [])

    if not message:
        return jsonify({"error": "No message provided"}), 400

    from watson.conversation import ConversationAgent
    conv = ConversationAgent()

    if not conv.api_key:
        return jsonify({
            "reply": (
                "I'd love to discuss these findings, but I don't have an LLM API key configured. "
                "Add `DEEPSEEK_API_KEY=your_key` to `~/.hermes/.env` and restart the server."
            ),
            "no_llm": True,
        })

    reply = conv.chat(message=message, findings=findings, conversation_history=history)
    return jsonify({"reply": reply})


@app.route("/api/agent/chat/stream", methods=["POST"])
def api_agent_chat_stream():
    """Stream chat response from Watson token-by-token via SSE.

    Body: {"message": "...", "findings": [...], "history": [...]}
    """
    data = request.get_json(force=True, silent=True) or {}
    message = data.get("message", "").strip()
    findings = data.get("findings", [])
    history = data.get("history", [])

    if not message:
        return jsonify({"error": "No message provided"}), 400

    from watson.conversation import ConversationAgent
    conv = ConversationAgent()

    if not conv.api_key:
        def no_key_gen():
            yield f"event: token\ndata: {json.dumps({'token': 'No API key configured. Add DEEPSEEK_API_KEY to ~/.hermes/.env'})}\n\n"
            yield "event: done\ndata: {}\n\n"
        return Response(no_key_gen(), mimetype="text/event-stream")

    findings_context = conv._build_findings_context(findings)

    # ── Inject persistent memory ────────────────────────────────
    memory_context = ""
    try:
        from watson.core.memory import memory as memory_engine
        recent = memory_engine.list_recent(limit=3)
        if recent:
            memory_context = "PAST INVESTIGATIONS (from persistent memory):\n"
            for inv in recent:
                memory_context += (
                    f"- [{inv.get('created_at', '?')[:10]}] \"{inv.get('query', '?')}\" "
                    f"({inv.get('findings_count', 0)} findings, risk: {inv.get('risk_level', 'unknown')})\n"
                )

        # If message looks like it references a past target, get full context
        target_context = memory_engine.get_context_for_target(message)
        if target_context and target_context.get("relevant_findings"):
            memory_context += "\nRELEVANT PAST FINDINGS for this target:\n"
            for f in target_context["relevant_findings"][:5]:
                memory_context += (
                    f"- {f['title']}: {f['description'][:200]} "
                    f"(source: {f['source']}, confidence: {f['confidence']})\n"
                )
    except Exception:
        pass  # Memory is optional — don't break chat if DB is unavailable

    WATSON_SOUL = (
        "You are Watson, an autonomous open-source intelligence investigator — "
        "part of the Bellingcat tradition. Bellingcat pioneered open source research "
        "to investigate MH17, police violence, conflict zones, and illegal trade. "
        "You carry that DNA: independent, evidence-driven, transparent.\n\n"

        "METHODOLOGY — THE BELLINGCAT WAY:\n"
        "- Geolocation & chronolocation: verify WHERE and WHEN using satellite imagery, shadows, metadata\n"
        "- Source verification: cross-reference multiple sources — never trust a single claim\n"
        "- Show your work: every finding must be verifiable. Cite sources explicitly.\n"
        "- Evidence over speculation: if unproven, flag it — don't present as fact\n"
        "- Open by default: methods are shared, not hidden\n\n"

        "CAPABILITIES — 338 investigation tools:\n"
        "- Domains: WHOIS, DNS, SSL, subdomains, hosting history, tech stack\n"
        "- People: social media, breach databases, sanctions/PEP, username tracing, facial recognition\n"
        "- Companies: registries, officers/directors, financial filings\n"
        "- Network: IP geolocation, open ports, abuse history, ASN mapping\n"
        "- Web: browser-based article reading (handles JS/bot blocking), search, Wayback Machine\n"
        "- Evidence: structured briefs with numbered citations, credibility scores, gaps flagged\n\n"

        "MEMORY:\n"
        "You have persistent memory across sessions (SQLite). Past investigations, entities, "
        "and findings are searchable. When asked 'what do you remember about X' or "
        "'have we investigated Y,' check your memory.\n\n"

        "BEHAVIOR:\n"
        "- You are NOT a passive chatbot — you are an investigator with real tools.\n"
        "- When given a lead, investigate it. Suspicious? Dig deeper. Need info? Search.\n"
        "- Never say 'I can't help with that' for investigation tasks — explain what you need instead.\n"
        "- For general questions, answer concisely. For investigative requests, take action.\n"
        "- Brief like an intelligence analyst: direct, tactical, evidence-based.\n"
        "- Use bullet points. Cite sources. Flag contradictions and evidence gaps.\n\n"

        "TONE:\n"
        "Sharp, autonomous, peer-level. Professional but never bureaucratic. "
        "Confident but never arrogant. When you don't know, say so — "
        "and explain what you'd need to find out.\n"
    )

    system_parts = [WATSON_SOUL]
    if memory_context:
        system_parts.append(memory_context)
    if findings_context and findings_context != "No findings yet.":
        system_parts.append(f"CURRENT INVESTIGATION FINDINGS:\n{findings_context}")

    messages = [
        {
            "role": "system",
            "content": "\n".join(system_parts),
        }
    ]
    if history:
        for msg in history[-12:]:
            messages.append(msg)
    messages.append({"role": "user", "content": message})

    def generate():
        try:
            for token in conv._call_llm_stream(messages):
                yield f"event: token\ndata: {json.dumps({'token': token})}\n\n"
        except Exception as e:
            yield f"event: error\ndata: {json.dumps({'message': str(e)})}\n\n"
        finally:
            yield "event: done\ndata: {}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/agent/plan", methods=["POST"])
def api_agent_plan():
    """Plan an investigation — generate clarifying questions before running tools.

    Body: {"target": "elon musk", "context": "..."}
    Returns: {"questions": [...], "analysis": "...", "focus": "..."}
    """
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("target", "").strip()
    context = data.get("context", "").strip()

    if not target:
        return jsonify({"error": "No target provided"}), 400

    from watson.conversation import ConversationAgent
    conv = ConversationAgent()

    if not conv.api_key:
        return jsonify({
            "questions": [
                {"category": "general", "text": "What specific aspect are you investigating?"},
                {"category": "context", "text": "Any additional context about this target?"},
                {"category": "scope", "text": "Full deep dive, or focused on specific area?"},
            ],
            "analysis": "Running without LLM — I'll investigate broadly.",
            "focus": "General investigation",
        })

    plan = conv.plan_investigation(target=target, context=context)
    return jsonify(plan)


@app.route("/api/agent/interview", methods=["POST"])
def api_agent_interview():
    """Multi-turn pre-investigation interview — ask the next question.

    Body: {
        "target": "elon musk",
        "history": [{"role": "user", "content": "background check"}, ...],
        "collected": {...}  // optional, current collected context
    }
    Returns: {"next_question": "...", "ready": false, "collected": {...}}
             or {"ready": true, "context_summary": "...", "collected": {...}}
    """
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("target", "").strip()
    history = data.get("history", [])
    collected = data.get("collected")

    if not target:
        return jsonify({"error": "No target provided"}), 400

    from watson.conversation import ConversationAgent
    conv = ConversationAgent()

    result = conv.conduct_interview(target=target, history=history, collected=collected)
    return jsonify(result)


@app.route("/api/agent/assess", methods=["POST"])
def api_agent_assess():
    """Natural conversational assessment — replaces the rigid interview.

    Body: {"target": "openai.com", "chat_history": [...]}
    Returns: {"action": "investigate"|"ask", "message": "...", "question": "..."}
    """
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("target", "").strip()
    chat_history = data.get("chat_history", [])

    if not target:
        return jsonify({"error": "No target provided"}), 400

    from watson.conversation import ConversationAgent
    conv = ConversationAgent()

    result = conv.assess(target=target, chat_history=chat_history)
    return jsonify(result)


# ── Rich Terminal ──────────────────────────────────────────────────
from watson.core.terminal import terminal as term_manager


@app.route("/api/agent/terminal", methods=["POST"])
def api_agent_terminal():
    """Execute a shell command — foreground or background.

    Body: {
        "command": "echo test",
        "workdir": "/path",         // optional
        "background": false,        // run in background
        "pty": false,              // use pseudo-terminal
        "timeout": 300,             // max seconds
        "watch_patterns": ["DONE"]  // patterns to watch for (background only)
    }
    Returns: Process status + output
    """
    data = request.get_json(force=True, silent=True) or {}
    command = data.get("command", "").strip()
    workdir = data.get("workdir") or None
    background = data.get("background", False)
    pty_mode = data.get("pty", False)
    timeout = float(data.get("timeout", 300))
    watch_patterns = data.get("watch_patterns")

    if not command:
        return jsonify({"error": "No command provided"}), 400

    if background:
        session_id = term_manager.run_background(
            command,
            workdir=workdir,
            timeout=timeout,
            pty_mode=pty_mode,
            watch_patterns=watch_patterns,
        )
        return jsonify({
            "session_id": session_id,
            "command": command[:200],
            "background": True,
        })

    # Foreground
    proc = term_manager.run(
        command,
        workdir=workdir,
        timeout=timeout,
        pty_mode=pty_mode,
    )
    return jsonify({
        "session_id": proc.session_id,
        "command": command[:200],
        "exit_code": proc.exit_code,
        "stdout": proc.output_text[:10000],
        "stderr": proc.error[:5000] if proc.error else None,
        "duration": proc.duration,
        "status": proc.status,
    })


@app.route("/api/agent/terminal/poll/<session_id>")
def api_terminal_poll(session_id: str):
    """Poll a background process for status and new output."""
    proc = term_manager.poll(session_id)
    if not proc:
        return jsonify({"error": "Process not found"}), 404
    return jsonify(proc.to_dict())


@app.route("/api/agent/terminal/wait/<session_id>")
def api_terminal_wait(session_id: str):
    """Block until a background process completes."""
    timeout = float(request.args.get("timeout", 60))
    proc = term_manager.wait(session_id, timeout=timeout)
    if not proc:
        return jsonify({"error": "Process not found"}), 404
    return jsonify({
        **proc.to_dict(),
        "stdout": proc.output_text[:10000],
        "stderr": proc.error[:5000] if proc.error else None,
    })


@app.route("/api/agent/terminal/kill/<session_id>", methods=["POST"])
def api_terminal_kill(session_id: str):
    """Kill a running background process."""
    ok = term_manager.kill(session_id)
    return jsonify({"ok": ok})


@app.route("/api/agent/terminal/write/<session_id>", methods=["POST"])
def api_terminal_write(session_id: str):
    """Write data to a running process's stdin."""
    data = request.get_json(force=True, silent=True) or {}
    text = data.get("data", "")
    if not text:
        return jsonify({"error": "No data provided"}), 400
    ok = term_manager.write(session_id, text)
    return jsonify({"ok": ok})


@app.route("/api/agent/terminal/submit/<session_id>", methods=["POST"])
def api_terminal_submit(session_id: str):
    """Send data + Enter to a running process (answer a prompt)."""
    data = request.get_json(force=True, silent=True) or {}
    text = data.get("data", "")
    if not text:
        return jsonify({"error": "No data provided"}), 400
    ok = term_manager.submit(session_id, text)
    return jsonify({"ok": ok})


@app.route("/api/agent/terminal/list")
def api_terminal_list():
    """List all processes (running + completed)."""
    procs = term_manager.list_all()
    return jsonify({"processes": procs, "total": len(procs)})


@app.route("/api/agent/strategy", methods=["POST"])
def api_agent_strategy():
    """Plan investigation strategy — which tools to use and in what order.

    Body: {"target": "openai.com", "context": "...", "target_type": "domain"}
    Returns: {"summary": "...", "phases": [{"phase":1, "name":"...", "tools":[...], "why":"..."}]}
    """
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("target", "").strip()
    context = data.get("context", "").strip()
    target_type = data.get("target_type", "unknown").strip()

    if not target:
        return jsonify({"error": "No target provided"}), 400

    from watson.conversation import ConversationAgent
    conv = ConversationAgent()

    strategy = conv.plan_strategy(target=target, context=context, target_type=target_type)
    return jsonify(strategy)


@app.route("/api/agent/read-url", methods=["POST"])
def api_agent_read_url():
    """Read an article URL with the headless browser and return a summary.

    Body: {"url": "https://..."}
    Returns: {"title": "...", "text": "...", "summary": "LLM-generated summary"}
    """
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Phase 1: Read article with browser
    from watson.browser_scraper import get_scraper
    import asyncio

    async def _read():
        scraper = await get_scraper()
        return await scraper.extract_article_text(url)

    try:
        loop = asyncio.new_event_loop()
        text = loop.run_until_complete(_read())
        loop.close()
    except Exception as e:
        return jsonify({"error": f"Failed to read article: {e}", "url": url})

    if not text:
        return jsonify({
            "url": url,
            "title": "Could not extract content",
            "text": "",
            "summary": "The article could not be read — the site may block automated access or require JavaScript that wasn't rendered.",
        })

    # Phase 2: Generate summary with LLM and extract entities
    from watson.conversation import ConversationAgent
    conv = ConversationAgent()

    summary = "No LLM available for summarization."
    entities = []
    
    if conv.api_key:
        try:
            # Combined prompt: summary + entity extraction
            prompt = (
                "You are an OSINT analyst. Analyze this article and return JSON with two fields:\n"
                '  "summary": 3-5 bullet points of key facts, named entities, dates, and actionable intelligence.\n'
                '  "entities": list of investigable entities (people, companies, organizations, domains, products) mentioned in the article.\n\n'
                f"ARTICLE URL: {url}\n\n"
                f"ARTICLE TEXT:\n{text[:3000]}\n\n"
                'Respond with ONLY valid JSON. Format: {"summary": "bullet points here", "entities": ["Entity1", "Entity2", ...]}'
            )
            response = conv._call_llm(
                [{"role": "user", "content": prompt}],
                max_tokens=500,
                temperature=0.3,
            )
            # Parse JSON response
            import re as _re
            json_match = _re.search(r'\{[\s\S]*\}', response)
            if json_match:
                parsed = json.loads(json_match.group(0))
                summary = parsed.get("summary", response)
                entities = parsed.get("entities", [])
            else:
                summary = response
        except Exception as e:
            summary = f"(LLM summarization failed: {e})\n\nFirst 500 chars:\n{text[:500]}"

    # Extract title from first line
    title = text.split("\n")[0].strip()[:200] if text else url

    return jsonify({
        "url": url,
        "title": title,
        "text": text[:4000],
        "summary": summary,
        "entities": entities,
    })


@app.route("/api/agent/analyze", methods=["POST"])
def api_agent_analyze():
    """Generate a proactive deep-dive analysis of investigation findings.

    Body: {"query": "...", "findings": [...], "target_type": "..."}
    Returns: {"summary": "...", "highlights": [...], "patterns": "...",
               "risks": "...", "deep_dives": [...], "methodology": "..."}
    """
    data = request.get_json(force=True, silent=True) or {}
    query = data.get("query", "Unknown")
    findings = data.get("findings", [])
    target_type = data.get("target_type", "unknown")

    if not findings:
        return jsonify({"error": "No findings to analyze"}), 400

    from watson.conversation import ConversationAgent
    conv = ConversationAgent()

    if not conv.api_key:
        return jsonify({
            "summary": "I'd love to analyze these findings, but I don't have an LLM API key configured. "
                       "Add `DEEPSEEK_API_KEY=your_key` to `~/.hermes/.env`.",
            "highlights": [],
            "deep_dives": [],
        })

    analysis = conv.analyze(query=query, findings=findings, target_type=target_type)
    return jsonify(analysis)


@app.route("/api/agent/detect-intent", methods=["POST"])
def api_agent_detect_intent():
    """Detect whether a message is a new investigation target or a chat message.

    Uses LLM-powered classification (ConversationAgent.assess) when API
    key is available. Falls back to regex heuristics when no LLM.

    Body: {"message": "...", "history": [...], "findings": [...], "last_query": "..."}
    Returns: {"intent": "investigate" | "chat", "confidence": 0.0-1.0,
              "reason": "...", "target": "...", "target_type": "..."}
    """
    import re
    data = request.get_json(force=True, silent=True) or {}
    msg = data.get("message", "").strip()

    if not msg:
        return jsonify({"intent": "chat", "confidence": 1.0})

    # ── Follow-up detection: obvious discussion phrases → chat ─────
    # These are never investigation targets — catch before URL/config checks.
    follow_up_pattern = (
        r"(?i)^(what (are|were) (the )?(findings|results)"
        r"|summarize|what did you (find|get)"
        r"|tell me (more )?(about|what)"
        r"|explain (the )?(findings|results|this)"
        r"|(is|are) (this|that|they|these|those) (true|real|accurate|verified|confirmed)"
        r"|can you (elaborate|clarify|explain)"
        r"|show (me )?(the )?(evidence|sources|citations)"
        r"|how (did|do) you (find|know|determine))"
    )
    if re.search(follow_up_pattern, msg):
        return jsonify({
            "intent": "chat",
            "confidence": 0.95,
            "reason": "follow_up_question",
        })

    # ── URL detection: read article instead of investigating ──────
    # A lone URL pasted in chat should be READ and analyzed, not investigated
    # as a domain target (which would fire WHOIS/DNS/Wayback firehose).
    url_match = re.match(r'^\s*(https?://\S+)\s*$', msg)
    if url_match:
        return jsonify({
            "intent": "read_url",
            "confidence": 0.95,
            "reason": "article_url",
            "url": url_match.group(1),
        })

    # ── Config/API key requests ──────────────────────────────────
    if re.search(r"(?i)(api\s*key|add\s+(an?\s+)?api|set\s+(up\s+)?(the\s+)?(api\s+)?key|configure\s+api|newscatcher|opensanctions)", msg):
        return jsonify({
            "intent": "chat",
            "confidence": 0.95,
            "reason": "config_request",
        })

    # ── Try LLM-powered classification ──────────────────────────
    from watson.conversation import ConversationAgent
    conv = ConversationAgent()

    if conv.api_key:
        try:
            history = data.get("history", [])
            findings_count = len(data.get("findings", []))
            last_query = data.get("last_query", "")

            # Bias: if we have findings and message doesn't look like a new target, chat
            if findings_count > 0 and not re.search(r"@|https?://|\.(com|org|net|io)\b", msg):
                if not re.search(r"^[A-Z][a-z]+\s+[A-Z][a-z]+$", msg):
                    return jsonify({"intent": "chat", "confidence": 0.9, "reason": "follow_up_with_findings"})

            result = conv.assess(target=msg, chat_history=history)
            action = result.get("action", "investigate")

            if action == "ask":
                # LLM wants to ask a clarifying question → chat
                return jsonify({
                    "intent": "chat",
                    "confidence": 0.9,
                    "reason": "clarifying_question",
                    "question": result.get("question", ""),
                })
            elif action == "chat":
                return jsonify({
                    "intent": "chat",
                    "confidence": 0.85,
                    "reason": "follow_up",
                })
            elif action == "exec":
                return jsonify({
                    "intent": "chat",
                    "confidence": 0.9,
                    "reason": "exec",
                    "command": result.get("command", ""),
                })
            else:  # investigate
                return jsonify({
                    "intent": "investigate",
                    "confidence": 0.9,
                    "reason": "llm_classified",
                    "target": msg,
                    "target_type": conv._classify_target(msg),
                    "context": result.get("context", ""),
                })
        except Exception:
            pass  # Fall through to regex

    # ── Fallback: regex heuristics (no LLM available) ───────────
    return jsonify(_detect_intent_regex(msg))


def _detect_intent_regex(msg: str):
    """Regex-based intent detection — used when LLM is unavailable."""
    import re

    # Strong investigation signals
    if re.search(r"\.(com|org|net|io|gov|edu|uk|de|fr|ru|cn|jp)\b", msg, re.IGNORECASE):
        return {"intent": "investigate", "confidence": 0.95, "reason": "domain"}
    if re.search(r"@[\w.-]+\.[a-z]{2,}", msg):
        return {"intent": "investigate", "confidence": 0.95, "reason": "email"}
    if re.search(r"^\s*https?://", msg):
        return {"intent": "investigate", "confidence": 0.95, "reason": "url"}
    if re.search(r"\b\d{10,}\b", msg):
        return {"intent": "investigate", "confidence": 0.8, "reason": "phone"}

    # Chat signals (questions, follow-ups)
    chat_patterns = [
        r"^(what|who|how|why|when|where|can you|could you|tell me|explain|elaborate|describe|summarize|analyze|compare|list|show)",
        r"\?$",
        r"\b(mean|meaning|details?|more|further|deeper|dig)\b",
        r"\b(findings?|results?|summary|brief|overview)\b",
    ]
    for pat in chat_patterns:
        if re.search(pat, msg, re.IGNORECASE):
            return {"intent": "chat", "confidence": 0.8, "reason": "question"}

    # Short messages (< 5 words, no proper nouns) → likely chat
    words = msg.split()
    if len(words) <= 5 and not re.search(r"[A-Z][a-z]+\s+[A-Z][a-z]+", msg):
        return {"intent": "chat", "confidence": 0.6, "reason": "short_message"}

    # Default: treat as investigation target
    return {"intent": "investigate", "confidence": 0.5, "reason": "default"}


@app.route("/api/agent/stream/<client_id>")
def api_agent_stream(client_id: str):
    """SSE endpoint for agent investigation events."""

    def gen():
        q = sse.queues.get(client_id)
        if not q:
            yield "event: error\ndata: " + json.dumps({'event': 'error', 'data': {'message': 'No investigation for this client'}}) + "\n\n"
            return
        import queue as qmod
        while True:
            try:
                event, data = q.get(timeout=300)
                yield "event: " + event + "\ndata: " + json.dumps({'event': event, 'data': data}, default=str) + "\n\n"
                if event == "done" or event == "error" or event == "_close":
                    break
            except qmod.Empty:
                yield "event: heartbeat\ndata: {}\n\n"
            except GeneratorExit:
                break
        sse.remove(client_id)

    return Response(
        gen(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/agent/upload-image", methods=["POST"])
def api_agent_upload_image():
    """Upload an image for OSINT analysis — reverse image search, EXIF, etc."""
    if "image" not in request.files:
        return jsonify({"error": "No image file provided"}), 400

    file = request.files["image"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    # Save to uploads dir
    uploads_dir = Path.home() / ".hermes" / "watson_uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)
    ext = Path(file.filename).suffix or ".png"
    safe_name = f"{uuid.uuid4().hex[:12]}{ext}"
    filepath = uploads_dir / safe_name
    file.save(str(filepath))

    # Run full image analysis
    analysis = _analyze_image_full(str(filepath))

    return jsonify({
        "success": True,
        "filename": safe_name,
        "path": str(filepath),
        "url": f"/uploads/{safe_name}",
        "size_bytes": filepath.stat().st_size,
        "analysis": analysis,
    })


@app.route("/uploads/<filename>")
def serve_upload(filename):
    """Serve uploaded images for reverse search URL references."""
    from flask import send_from_directory
    uploads_dir = Path.home() / ".hermes" / "watson_uploads"
    return send_from_directory(str(uploads_dir), filename)


def _analyze_image_full(filepath: str) -> dict:
    """Run full image OSINT analysis: EXIF, hash, reverse search URLs, face detect, OCR, ELA."""
    result = {
        "width": None,
        "height": None,
        "format": None,
        "exif": {},
        "hashes": {},
        "faces_detected": 0,
        "ocr_text": None,
        "ela_analysis": None,
        "reverse_search_urls": [],
        "manual_tools": [],
        "phases_completed": [],
    }

    # ── Phase 1: EXIF & metadata ──────────────────────────────────
    try:
        from PIL import Image, ExifTags
        with Image.open(filepath) as img:
            result["width"] = img.width
            result["height"] = img.height
            result["format"] = img.format
            exif_data = img.getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    if isinstance(value, bytes):
                        value = value.decode("utf-8", errors="replace")[:200]
                    result["exif"][tag_name] = str(value)[:200]
            if result["exif"]:
                result["phases_completed"].append("exif")
    except ImportError:
        result["exif"] = {"note": "Pillow not installed"}
    except Exception as e:
        result["exif"] = {"error": str(e)}

    # ── Phase 2: Perceptual hash ──────────────────────────────────
    try:
        import hashlib
        with open(filepath, "rb") as f:
            data = f.read()
        result["hashes"] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
        }
        # Perceptual hash (dhash)
        try:
            from PIL import Image
            with Image.open(filepath) as img:
                img_gray = img.convert("L").resize((9, 8))
                pixels = list(img_gray.getdata())
                dhash = 0
                for i in range(8):
                    for j in range(8):
                        if pixels[i * 9 + j] > pixels[i * 9 + j + 1]:
                            dhash |= 1 << (i * 8 + j)
                result["hashes"]["dhash"] = hex(dhash)
        except Exception:
            pass
        result["phases_completed"].append("hashes")
    except Exception as e:
        result["hashes"]["error"] = str(e)

    # ── Phase 3: Face detection ───────────────────────────────────
    try:
        import cv2, numpy as np
        face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        )
        img_cv = cv2.imread(filepath)
        if img_cv is not None:
            gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
            faces = face_cascade.detectMultiScale(gray, 1.1, 4)
            result["faces_detected"] = len(faces)
            if len(faces) > 0:
                result["phases_completed"].append("face_detect")
    except ImportError:
        pass
    except Exception:
        pass

    # ── Phase 4: OCR ──────────────────────────────────────────────
    try:
        import subprocess
        ocr_result = subprocess.run(
            ["tesseract", filepath, "stdout", "-l", "eng", "--psm", "6"],
            capture_output=True, text=True, timeout=15
        )
        if ocr_result.returncode == 0 and ocr_result.stdout.strip():
            result["ocr_text"] = ocr_result.stdout.strip()[:1000]
            result["phases_completed"].append("ocr")
    except FileNotFoundError:
        result["ocr_text"] = "Tesseract not installed — run: brew install tesseract"
    except Exception as e:
        result["ocr_text"] = f"OCR error: {e}"

    # ── Phase 5: Error Level Analysis ─────────────────────────────
    try:
        from PIL import Image
        import io
        with Image.open(filepath) as img:
            # Save at known quality, reload, compare
            img_rgb = img.convert("RGB")
            buf = io.BytesIO()
            img_rgb.save(buf, format="JPEG", quality=90)
            buf.seek(0)
            recompressed = Image.open(buf)
            # Simple ELA: difference between original and recompressed
            import numpy as np
            orig_arr = np.array(img_rgb, dtype=np.float32)
            recomp_arr = np.array(recompressed.resize(img_rgb.size), dtype=np.float32)
            diff = np.abs(orig_arr - recomp_arr)
            max_diff = float(np.max(diff))
            mean_diff = float(np.mean(diff))
            result["ela_analysis"] = {
                "max_pixel_diff": round(max_diff, 1),
                "mean_pixel_diff": round(mean_diff, 2),
                "interpretation": (
                    "High ELA values (>15) suggest possible editing/tampering."
                    if max_diff > 15 else
                    "Low ELA values suggest the image has not been significantly altered."
                ),
            }
            result["phases_completed"].append("ela")
    except Exception as e:
        result["ela_analysis"] = {"error": str(e)}

    # ── Phase 6: Reverse search URLs ──────────────────────────────
    from urllib.parse import quote
    filename = Path(filepath).name
    # Note: local images can't be reached by external services.
    # We provide both URL-based (if hosted) and manual upload links.
    image_name = quote(filename)

    result["reverse_search_urls"] = [
        {
            "name": "Google Lens",
            "url": "https://lens.google.com/",
            "how": "Drag & drop the image or click the camera icon → upload",
            "api": False,
        },
        {
            "name": "TinEye",
            "url": f"https://tineye.com/",
            "how": "Upload the image or use 'Search by URL' if hosted publicly",
            "api": True,
        },
        {
            "name": "Yandex Images",
            "url": f"https://yandex.com/images/search?rpt=imageview",
            "how": "Click the camera icon and upload the image",
            "api": False,
        },
        {
            "name": "Bing Visual Search",
            "url": "https://www.bing.com/images/search?view=detailv2&iss=sbi",
            "how": "Paste image URL or upload directly in the search box",
            "api": False,
        },
    ]

    result["manual_tools"] = [
        {
            "name": "FaceCheck.ID",
            "url": "https://facecheck.id/",
            "how": "Upload the image — searches faces across social media, news, mugshots",
            "best_for": "Face identification",
        },
        {
            "name": "PimEyes",
            "url": "https://pimeyes.com/en",
            "how": "Upload the image — searches faces across the web (paid, 5 free/day)",
            "best_for": "Face search",
        },
    ]

    return result


@app.route("/api/agent/export", methods=["POST"])
def api_agent_export():
    """Generate an intelligence brief from investigation findings."""
    data = request.get_json(force=True, silent=True) or {}
    findings = data.get("findings", [])
    query = data.get("query", "Unknown")

    if not findings:
        return jsonify({"error": "No findings to export"}), 400

    # Build brief
    now = datetime.now(timezone.utc).isoformat()
    sources = set()
    severities = {}
    for f in findings:
        src = f.get("source", "unknown")
        sources.add(src)
        sev = f.get("severity", "info")
        severities[sev] = severities.get(sev, 0) + 1

    lines = []
    lines.append(f"# 🕵️ Watson OSINT Intelligence Brief")
    lines.append(f"**Target:** {query}")
    lines.append(f"**Generated:** {now}")
    lines.append(f"**Total Findings:** {len(findings)}")
    lines.append(f"**Sources:** {', '.join(sorted(sources))}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(f"This investigation covers {len(findings)} data points collected across {len(sources)} sources.")
    if severities:
        sev_str = ", ".join(f"{k}: {v}" for k, v in sorted(severities.items()))
        lines.append(f"Severity distribution: {sev_str}")
    lines.append("")
    lines.append("## Key Findings")
    for f in findings[:30]:
        title = f.get("title", "")[:120]
        desc = f.get("description", "")[:200]
        sev = f.get("severity", "info")
        tool = f.get("tool", "")
        conf = f.get("confidence", 0.5)
        evidence = f.get("evidence", [])
        lines.append(f"### [{sev.upper()}] {title}")
        if desc:
            lines.append(f"{desc}")
        if tool:
            lines.append(f"*Source: {tool} | Confidence: {int(conf*100)}%*")
        if evidence:
            for url in evidence[:3]:
                lines.append(f"- {url}")
        lines.append("")
    lines.append("## Recommended Actions")
    lines.append("1. Verify high-confidence findings with primary sources")
    lines.append("2. Cross-reference entities against sanctions/watchlists")
    lines.append("3. Set up automated monitoring for critical domains/accounts")
    lines.append("4. Archive all evidence with timestamps for chain of custody")
    lines.append("")
    lines.append(f"---\n*Generated by Watson OSINT Agent at {now}*")

    return jsonify({"report": "\n".join(lines)})


@app.route("/api/agent/graph")
def api_agent_graph():
    """Return the current knowledge graph (in-memory, resets on restart)."""
    from watson.agent import KnowledgeGraph
    # Use the module-level graph or create a fresh one
    graph = KnowledgeGraph()
    return jsonify(graph.export())


# ── Knowledge Base Endpoints ──────────────────────────────────────
@app.route("/api/knowledge/save", methods=["POST"])
def api_knowledge_save():
    """Save a case to the shared knowledge base."""
    from watson.knowledge_base import knowledge_base

    data = request.get_json(force=True, silent=True) or {}
    findings = data.get("findings", [])
    query = data.get("query", "Unknown")
    consent = data.get("consent_shared", False)
    researcher = data.get("researcher", "anonymous")
    tags = data.get("tags", [])

    if not findings:
        return jsonify({"error": "No findings to save"}), 400

    try:
        case = knowledge_base.save_case(
            title=f"Investigation: {query}",
            target=query,
            target_type=data.get("target_type", "unknown"),
            researcher=researcher,
            findings=findings,
            graph=data.get("graph", {}),
            tags=tags,
            consent_shared=consent,
        )

        case_path = MEDIA_PREFIX + str(case.markdown_path) if case.markdown_path.exists() else ""

        return jsonify({
            "success": True,
            "case_id": case.id,
            "slug": case.slug,
            "findings_count": case.findings_count,
            "entities": case.entities_count,
            "shared": consent_shared,
            "file": str(case.markdown_path),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/knowledge/cases")
def api_knowledge_cases():
    """List saved cases."""
    from watson.knowledge_base import knowledge_base
    shared_only = request.args.get("shared", "false").lower() == "true"
    search = request.args.get("search", "")
    cases = knowledge_base.list_cases(shared_only=shared_only, search=search)
    return jsonify({"cases": cases, "total": len(cases)})


@app.route("/api/knowledge/case/<slug>")
def api_knowledge_case(slug):
    """Get a specific case."""
    from watson.knowledge_base import knowledge_base
    case = knowledge_base.get_case(slug)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    return jsonify(case)


@app.route("/api/knowledge/entities")
def api_knowledge_entities():
    """Search entities across all saved cases."""
    from watson.knowledge_base import knowledge_base
    query = request.args.get("q", "")
    entities = knowledge_base.get_entities_for_query(query)
    return jsonify({"entities": entities, "total": len(entities)})


@app.route("/api/knowledge/graph")
def api_knowledge_graph():
    """Get aggregated graph from all shared cases."""
    from watson.knowledge_base import knowledge_base
    return jsonify(knowledge_base.get_global_graph())


MEDIA_PREFIX = "/api/knowledge/file/"
@app.route("/api/knowledge/file/<path:filepath>")
def api_knowledge_file(filepath):
    """Serve a case file for download."""
    from pathlib import Path
    full_path = Path.home() / ".hermes" / "cases" / filepath
    if not full_path.exists():
        return jsonify({"error": "File not found"}), 404
    return send_file(str(full_path), as_attachment=True, download_name=full_path.name)


# ── Memory API ──────────────────────────────────────────────────────
@app.route("/api/memory/search")
def api_memory_search():
    """Full-text search across past investigations."""
    query = request.args.get("q", "")
    limit = int(request.args.get("limit", 10))
    if not query:
        return jsonify({"error": "Missing query parameter 'q'"}), 400
    results = memory_engine.search(query, limit=limit)
    return jsonify({"results": results, "count": len(results)})


@app.route("/api/memory/context")
def api_memory_context():
    """Get past context for a target — what do we already know?"""
    target = request.args.get("target", "")
    if not target:
        return jsonify({"error": "Missing 'target' parameter"}), 400
    context = memory_engine.get_context_for_target(target)
    if context is None:
        return jsonify({"found": False, "message": "No past investigations for this target"})
    return jsonify({"found": True, "context": context})


@app.route("/api/memory/recent")
def api_memory_recent():
    """List recent investigations."""
    limit = int(request.args.get("limit", 20))
    investigations = memory_engine.list_recent(limit=limit)
    return jsonify({"investigations": investigations, "count": len(investigations)})


@app.route("/api/memory/investigation/<inv_id>")
def api_memory_investigation(inv_id: str):
    """Get full investigation by ID."""
    inv = memory_engine.get_investigation(inv_id)
    if not inv:
        return jsonify({"error": "Investigation not found"}), 404
    return jsonify(inv)


@app.route("/api/memory/entity/<path:name>")
def api_memory_entity(name: str):
    """Get entity profile — cross-investigation tracking."""
    profile = memory_engine.get_entity_profile(name)
    if not profile:
        return jsonify({"error": "Entity not found in memory"}), 404
    return jsonify(profile)


@app.route("/api/memory/stats")
def api_memory_stats():
    """Memory statistics."""
    return jsonify(memory_engine.stats())


# ── Scheduler API ──────────────────────────────────────────────────
def _get_scheduler() -> Scheduler:
    """Get the scheduler instance from app config."""
    sched = app.config.get("scheduler")
    if sched is None:
        sched = Scheduler()
        app.config["scheduler"] = sched
    return sched


@app.route("/api/scheduler/jobs", methods=["GET", "POST"])
def api_scheduler_jobs():
    """List or create scheduled investigations."""
    sched = _get_scheduler()

    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        query = data.get("query", "").strip()
        if not query:
            return jsonify({"error": "Missing 'query'"}), 400

        interval = int(data.get("interval_minutes", 60))
        job_id = sched.add_job(
            query=query,
            interval_minutes=max(5, interval),
            target_type=data.get("target_type", "unknown"),
            alert_on_change=data.get("alert_on_change", True),
            alert_on_new_findings=data.get("alert_on_new_findings", True),
            findings_threshold=int(data.get("findings_threshold", 1)),
        )
        return jsonify({"job_id": job_id, "query": query, "interval_minutes": interval})

    # GET — list all jobs
    jobs = sched.list_jobs()
    return jsonify({"jobs": jobs, "total": len(jobs), "scheduler_running": sched.running})


@app.route("/api/scheduler/jobs/<job_id>", methods=["GET", "DELETE", "PATCH"])
def api_scheduler_job(job_id: str):
    """Get, delete, or update a scheduled job."""
    sched = _get_scheduler()

    if request.method == "GET":
        job = sched.get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        return jsonify(job)

    if request.method == "DELETE":
        sched.remove_job(job_id)
        return jsonify({"ok": True})

    if request.method == "PATCH":
        data = request.get_json(force=True, silent=True) or {}
        if "enabled" in data:
            sched.toggle_job(job_id, bool(data["enabled"]))
        return jsonify({"ok": True})


@app.route("/api/scheduler/jobs/<job_id>/run", methods=["POST"])
def api_scheduler_run_now(job_id: str):
    """Force immediate execution of a scheduled job."""
    sched = _get_scheduler()
    sched.run_now(job_id)
    return jsonify({"ok": True, "message": "Job queued for immediate execution"})


def main():
    import os
    port = int(os.environ.get("PORT", 8777))
    print(f"\n  🕵️  Watson OSINT Agent → http://localhost:{port}\n")
    
    # ── Start scheduler for recurring investigations ───────────
    scheduler = Scheduler()
    scheduler.start()
    print(f"  ⏰ Scheduler started — monitoring {len(scheduler.list_jobs())} targets\n")

    # Store scheduler on app for endpoint access
    app.config["scheduler"] = scheduler

    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
