"""Intelligence synthesis — turn gathered findings into an analyst's brief.

This is the step that separates Watson from a clipping service. The reasoning
loop gathers sources; synthesis READS them and produces:

  - Executive summary (2-3 sentences: what's the bottom line)
  - Key risk themes (grouped: antitrust, labor, tax, data/privacy, sanctions…)
  - Severity per theme (HIGH / MEDIUM / LOW) with the evidence behind it
  - Notable entities (people, orgs, regulators involved)
  - Evidence gaps (what couldn't be verified)
  - Source list with credibility

Every claim is grounded in a finding — synthesis NEVER invents facts.
"""

from __future__ import annotations

import json
import logging

# Try to import Finding from wherever it lives
try:
    from watson.agents.protocol import Finding
except ImportError:
    try:
        from watson.engine import Finding
    except ImportError:
        from dataclasses import dataclass

        @dataclass
        class Finding:
            title: str = ""
            description: str = ""
            source_url: str = ""
            source_type: str = ""
            confidence: float = 0.5
            raw_data: dict | None = None

logger = logging.getLogger("watson.synthesis")

_SYNTHESIS_PROMPT = """You are an intelligence analyst writing a due-diligence brief.

TARGET: {query}
TARGET TYPE: {target_type}
FOCUS: {focus}

You have gathered the following raw findings (sources already read). Synthesize
them into a structured intelligence brief. Use ONLY information present in these
findings — do NOT add outside knowledge or invent facts. If something is unclear
or unverified, say so.

{target_specific_guidance}

FINDINGS:
{findings}

{resolved_entities}

Produce STRICT JSON (no markdown fences) with this shape:
{{
  "executive_summary": "2-3 sentence bottom line for a decision-maker",
  "risk_themes": [
    {{"theme": "Antitrust / Competition", "severity": "HIGH|MEDIUM|LOW",
      "summary": "what the evidence shows", "source_titles": ["..."]}}
  ],
  "notable_entities": [
    {{"name": "...", "role": "regulator|executive|company|court|cybercriminal", "context": "..."}}
  ],
  "evidence_gaps": ["what could not be verified or is missing"],
  "recommended_next_steps": [
    {{"entity": "the specific target (wallet, domain, name, IP, etc.) — NOT the full instruction",
      "action": "what to do with it (trace, investigate, search, etc.)",
      "tool_hint": "best tool category (blockchain, sanctions, corporate, domain, social, web)"}}
  ]
}}

Rules:
- 2-5 risk themes, ordered by severity.
- severity reflects evidence strength + impact, not your opinion.
- notable_entities: real orgs/people/regulators that appear in the findings.
- Be specific: name the regulator, the amount, the year when the finding states it.
- If findings are thin, say so in executive_summary and keep themes minimal.
- CRITICAL for recommended_next_steps: do NOT suggest steps that were ALREADY
  executed. The tools listed below already ran — recommending them again is wrong.
  Only suggest genuinely new follow-up vectors that haven't been tried.

TOOLS ALREADY EXECUTED (do NOT re-recommend these):
{executed_tools}
"""

_TARGET_GUIDANCE = {
    "person": (
        "PERSON INVESTIGATION GUIDANCE:\n"
        "- The goal is to IDENTIFY this individual: who they are, what they do, their affiliations,\n"
        "  professional background, and digital footprint.\n"
        "- LinkedIn, ResearchGate, GitHub, Behance, Twitter profiles ARE substantive findings —\n"
        "  they establish identity, career, and expertise. Do NOT dismiss these as 'not intelligence.'\n"
        "- Social media profiles, professional pages, and news mentions are the PRIMARY deliverables\n"
        "  for a person investigation — not a failure or thin result.\n"
        "- Risk themes are OPTIONAL for persons. If no sanctions/criminal findings exist, that's\n"
        "  NORMAL for most people. Don't fabricate risk themes to fill space.\n"
        "- The executive summary should state WHO this person is (role, org, location) based on\n"
        "  available findings, even if partial."
    ),
    "email": (
        "EMAIL INVESTIGATION GUIDANCE:\n"
        "- Identify the person behind the email, their affiliations, breach history, and accounts.\n"
        "- Breach data, social profiles, and username pivots are substantive findings."
    ),
    "domain": (
        "DOMAIN INVESTIGATION GUIDANCE:\n"
        "- Focus on infrastructure: WHOIS, DNS, TLS certs, subdomain enumeration, technologies.\n"
        "- Identify the organization behind the domain and assess its legitimacy."
    ),
    "company": (
        "COMPANY INVESTIGATION GUIDANCE:\n"
        "- Focus on corporate structure, ownership, regulatory actions, sanctions, controversies.\n"
        "- Executive leadership, subsidiaries, and legal risks are key."
    ),
    "wallet": (
        "WALLET INVESTIGATION GUIDANCE:\n"
        "- Trace transactions, identify counterparties, check sanctions lists, and assess risk.\n"
        "- Exchange interactions and token holdings are substantive."
    ),
}

_PERSON_DEEP_GUIDANCE = (
    "PERSON DEEP INVESTIGATION GUIDANCE:\n"
    "- This is a CRIMINAL/LEGAL investigation. Look for: criminal charges, convictions, sentences,\n"
    "  court cases, arrests, indictments, Interpol notices, sanctions (OFAC/UN/EU), asset freezes,\n"
    "  travel bans, organized crime connections, cartel affiliations, prison records, wanted status.\n"
    "- Wikipedia, sanctions databases, and crime/legal news articles ARE the primary evidence.\n"
    "- Risk themes ARE expected — criminal/legal findings ARE the deliverable. Rank by severity.\n"
    "- The executive summary should state who this person is, their criminal/legal status,\n"
    "  and key charges/sanctions with dates and jurisdictions.\n"
    "- If no criminal findings were found, state that clearly — do not fabricate."
)

_PERSON_DUE_DILIGENCE_GUIDANCE = (
    "PERSON DUE DILIGENCE GUIDANCE:\n"
    "- This is a PROFESSIONAL/BUSINESS investigation. Focus on: employment history, board positions,\n"
    "  business affiliations, corporate connections, professional reputation.\n"
    "- Also check for: lawsuits, regulatory actions, fines, penalties, adverse media,\n"
    "  fraud allegations, ethics violations, professional misconduct.\n"
    "- Risk themes may include regulatory risk, reputational risk, litigation risk.\n"
    "- The executive summary should state who this person is professionally, their role,\n"
    "  and any adverse findings that would concern a business partner or employer."
)


def _format_executed_tools(executed: set[tuple[str, str]] | None) -> str:
    """Format executed tool+target pairs for injection into the synthesis prompt."""
    if not executed:
        return "(no tools were executed — this was a direct analysis)"
    lines = []
    for tool, target in sorted(executed):
        lines.append(f"  • {tool}: {target[:120]}")
    return "\n".join(lines) if lines else "(no tools executed)"


def _format_resolved_entities(resolved: list | None) -> str:
    """Format resolved entities for the synthesis prompt."""
    if not resolved:
        return ""
    lines = ["RESOLVED ENTITIES (cross-referenced, deduplicated):"]
    for e in resolved:
        # ResolvedEntity is a dataclass — use getattr, not .get()
        name = getattr(e, "canonical_name", None) or getattr(e, "canonical", str(e))
        etype = getattr(e, "entity_type", None) or getattr(e, "etype", "unknown")
        confidence = getattr(e, "confidence", 0)
        src_count = getattr(e, "total_sources", None)
        if src_count is None:
            src_findings = getattr(e, "source_findings", None)
            src_count = len(src_findings) if src_findings else len(getattr(e, "finding_ids", []))
        aliases = getattr(e, "aliases", [])
        lines.append(
            f"  • {name} [{etype}] — confidence {confidence:.0%}, "
            f"{src_count} sources"
        )
        if aliases:
            lines.append(f"    aliases: {', '.join(list(aliases)[:5])}")
    return "\n".join(lines)


def _findings_block(findings, max_chars: int = 6000) -> str:
    """Build a condensed findings block for the synthesis prompt. 
    Caps at max_chars and prioritizes findings with source URLs."""
    # Sort: findings with URLs first (higher quality), then by confidence
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            not (getattr(f, "source_url", "") or ""),
            -(getattr(f, "confidence", 0.5) or 0.5)
        )
    )
    lines = []
    total = 0
    for i, f in enumerate(sorted_findings, 1):
        title = getattr(f, "title", str(f)[:100]) or ""
        desc = getattr(f, "description", "") or ""
        desc = desc.replace("\n", " ").replace("**Extracted text", "").lstrip("(")
        chunk = f"[{i}] {title}\n    {desc[:400]}\n"
        if total + len(chunk) > max_chars:
            break
        lines.append(chunk)
        total += len(chunk)
    return "\n".join(lines)


def _deterministic_person_brief(query: str, findings: list) -> dict:
    """Build a person identity brief from findings WITHOUT an LLM.
    
    Extracts: name variants, professional profiles (LinkedIn, GitHub, etc.),
    content mentions (articles, posts), and gaps. Never gaslights.
    """
    import re as _re
    
    profiles: list[dict] = []
    mentions: list[dict] = []
    name_variants = set()
    
    for f in findings:
        title = getattr(f, "title", "") or ""
        desc = getattr(f, "description", "") or ""
        url = getattr(f, "source_url", "") or ""
        combined = f"{title} {desc}"
        
        # Extract name variants — prioritize ones matching the query terms
        query_parts = set(query.lower().split())
        for match in _re.finditer(r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b', combined):
            name = match.group(1)
            name_parts = set(name.lower().split())
            if name_parts & query_parts:
                name_variants.add(name)
        
        # Detect professional profiles by URL pattern
        if any(domain in url for domain in [
            'linkedin.com/in/', 'linkedin.com/posts/', 
            'github.com/', 'twitter.com/', 'x.com/',
            'researchgate.net/profile/', 'behance.net/',
        ]):
            followers_match = _re.search(r'([\d,]+)\s*(?:followers|Posts)', combined)
            profiles.append({
                "url": url, "title": title[:120],
                "followers": followers_match.group(1) if followers_match else None,
            })
        
        # Detect content mentions by keyword
        if any(kw in combined.lower() for kw in ['author', 'editor', 'analyst', 'journalist', 
                                                    'founder', 'defense', 'tech', 'security']):
            mentions.append({"url": url, "title": title[:120], "snippet": desc[:200] if desc else ""})
    
    # Determine best name: prefer longest variant matching all query words
    name_str = query
    if name_variants:
        query_words = set(query.lower().split())
        for v in sorted(name_variants, key=len, reverse=True):
            if query_words.issubset(set(v.lower().split())):
                name_str = v
                break
        else:
            name_str = max(name_variants, key=len)
    pc, mc = len(profiles), len(mentions)
    
    if pc >= 2:
        sources = [p['url'].split('/')[2] for p in profiles[:3]]
        topics = set()
        for m in mentions:
            for kw in ['defense', 'security', 'tech', 'startup', 'founder', 'editor', 'analyst']:
                if kw in m['title'].lower() or kw in m['snippet'].lower():
                    topics.add(kw)
        summary = (f"{name_str} has a verified digital footprint with {pc} professional profiles "
                   f"and {mc} content mentions. Sources: {', '.join(sources)}. "
                   + (f"Topics: {', '.join(sorted(topics))}." if topics else ""))
    elif pc == 1:
        summary = (f"{name_str} has a limited digital footprint — one profile found. "
                   f"{mc} content mentions. Further investigation recommended.")
    else:
        # Count actual unique URLs checked (not total findings — those include tool output noise)
        urls_checked = len(set(
            f.source_url for f in findings
            if hasattr(f, 'source_url') and f.source_url
        ))
        sources_text = f"{urls_checked} sources checked" if urls_checked else "sources checked"
        
        # Detect location confusion — if findings look like business/geographic results
        combined_text = " ".join(
            (getattr(f, "title", "") + " " + getattr(f, "description", "")).lower()
            for f in findings
        )
        location_keywords = ["comune", "municipality", "province", "via ", "p.iva",
                             "impresa", "telefono", "orari", "cap ", "business directory"]
        looks_like_location = any(kw in combined_text for kw in location_keywords)
        
        if looks_like_location:
            summary = (f"No person found for '{name_str}'. "
                       f"Results suggest this may be a geographic location or business name, "
                       f"not an individual. {sources_text}. "
                       f"Try re-running with a different query or check for name variants.")
        else:
            summary = (f"No professional profiles found for {name_str}. "
                       f"{sources_text}. Possible private individual, pseudonym, or name collision.")
    
    return {
        "executive_summary": summary[:500],
        "risk_themes": [],
        "notable_entities": [{"name": name_str, "role": "person", 
                              "context": f"Profiles: {pc}, Mentions: {mc}"}],
        "evidence_gaps": [g for g in [
            "No verified employer or organization" if not any(
                'company' in str(m).lower() or 'firm' in str(m).lower() for m in mentions
            ) else None,
            "Limited digital footprint — try alternative spellings" if pc < 2 else None,
        ] if g],
        "recommended_next_steps": (
            [{"entity": p['url'], "action": "View profile", "tool_hint": "social"} for p in profiles[:3]]
            + [{"entity": m['url'], "action": "Read article", "tool_hint": "web"} for m in mentions[:2]]
        ),
        "_synthesized": True, "_deterministic": True,
    }

async def synthesize_brief(
    query: str,
    focus: str,
    findings: list,
    call_llm,
    target_type: str = "",
    executed_tools: set[tuple[str, str]] | None = None,
    resolved_entities: list | None = None,
    investigation_mode: str = "",
    graph_context: dict | None = None,
) -> dict | None:
    """Produce a structured intelligence brief from findings. Returns dict or None."""
    # Filter out pure fetch-failures
    real = []
    for f in findings:
        title = getattr(f, "title", "")
        if not title.lower().startswith(("could not read",)):
            real.append(f)
    usable = real or findings
    
    if not usable:
        return None

    # ── Inject graph context into findings for cross-case intelligence ──
    if graph_context and graph_context.get("known_entities"):
        from ..core.models import Finding, FindingSeverity, FindingSource
        known = graph_context["known_entities"]
        cases = graph_context.get("relevant_cases", [])
        for ent in known[:5]:
            usable.append(Finding(
                id=f"graph-{ent.get('id', ent.get('value', 'unknown'))[:20]}",
                source=FindingSource.OSINT,
                tool="knowledge_graph",
                title=f"📊 [Graph] Known entity: {ent.get('value', '')[:120]}",
                description=f"Previously found in case(s): {', '.join(cases[:3])}. "
                            f"Type: {ent.get('type', 'unknown')}. "
                            f"Confidence: PRIMARY (community graph — cross-case intelligence).",
                evidence=[],
                confidence=1.0,
                severity=FindingSeverity.INFO,
            ))

    # Person targets: deterministic extraction for background_check and due_diligence.
    # Deep investigation (criminal/sanctions/court targets) needs LLM synthesis —
    # the deterministic brief only knows about LinkedIn/GitHub profiles, not sanctions,
    # indictments, or cartel affiliations. Deep investigation findings ARE the deliverable.
    if target_type == "person" and investigation_mode != "deep_investigation":
        return _deterministic_person_brief(query, usable)
    
    # Non-person targets: LLM synthesis

    target_guidance = _TARGET_GUIDANCE.get(target_type, "") if target_type else ""
    
    # Deep investigation on persons: use criminal/legal guidance, not generic identity
    if target_type == "person" and investigation_mode == "deep_investigation":
        target_guidance = _PERSON_DEEP_GUIDANCE

    prompt = _SYNTHESIS_PROMPT.format(
        query=query,
        target_type=target_type or "unknown",
        focus=focus or "general due diligence",
        target_specific_guidance=target_guidance,
        findings=_findings_block(usable),
        resolved_entities=_format_resolved_entities(resolved_entities),
        executed_tools=_format_executed_tools(executed_tools),
    )

    try:
        raw = await call_llm(prompt, timeout=180, max_tokens=1500)
        if not raw:
            logger.info("synthesis: first LLM attempt empty, retrying")
            raw = await call_llm(prompt, timeout=180, max_tokens=1500)
    except TypeError:
        try:
            raw = await call_llm(prompt, timeout=60)
        except TypeError:
            raw = await call_llm(prompt)
    except Exception as e:
        logger.warning("synthesis_llm_failed: %s", e)
        raw = None

    if not raw:
        return _fallback_brief(query, usable)

    brief = _parse_json(raw)
    if not brief or "executive_summary" not in brief:
        return _fallback_brief(query, usable)

    brief["_synthesized"] = True
    return brief


def _parse_json(text: str) -> dict | None:
    import re
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                return None
    return None


def _fallback_brief(query: str, findings: list) -> dict:
    """Deterministic structural brief when the LLM is unavailable.
    Extracts real data from findings instead of just giving up."""
    import re as _re
    
    sources = []
    titles = []
    for f in findings:
        url = getattr(f, "source_url", "") or (getattr(f, "raw_data", {}) or {}).get("url", "")
        if not url:
            m = _re.search(r"https?://\S+", f"{getattr(f, 'title', '')} {getattr(f, 'description', '')}")
            if m:
                url = m.group(0).rstrip(".,)")
        if url and url not in sources:
            sources.append(url)
        title = getattr(f, "title", "")
        if title and not title.lower().startswith(("check_", "could not read")):
            titles.append(title[:150])
    
    # Build a real summary from what was found
    top_titles = titles[:8]
    summary_parts = [f"Watson gathered {len(findings)} sources ({len(sources)} verified URLs) on '{query}'."]
    if top_titles:
        summary_parts.append("Key findings include: " + "; ".join(top_titles[:5]))
    
    # Detect themes from titles
    theme_keywords = {
        "Regulatory / Legal": ["sanction", "fine", "settlement", "regulator", "sec", "cftc", "doj",
                                "lawsuit", "indictment", "charged", "plead guilty", "convicted"],
        "Corporate / Leadership": ["ceo", "founder", "executive", "board", "chairman", "director",
                                    "resigned", "appointed", "named"],
        "Financial": ["revenue", "profit", "loss", "billion", "million", "funding", "valuation"],
        "Crime / Investigation": ["criminal", "arrest", "prison", "jail", "fraud", "money laundering",
                                   "investigation", "probe"],
    }
    themes = []
    all_titles_text = " ".join(titles).lower()
    for theme, keywords in theme_keywords.items():
        if any(kw in all_titles_text for kw in keywords):
            themes.append(theme)
    
    return {
        "executive_summary": " ".join(summary_parts),
        "risk_themes": [{"theme": t, "severity": "MEDIUM",
                         "summary": "Detected in findings — review sources for details",
                         "source_titles": []} for t in themes] if themes else [],
        "notable_entities": [],
        "evidence_gaps": ["LLM synthesis unavailable — themes detected from finding titles only. "
                         "Re-run for full AI analysis."],
        "recommended_next_steps": [{"entity": u, "action": "Review source", "tool_hint": "web"}
                                   for u in sources[:5]],
        "_synthesized": False,
        "_sources": sources[:15],
    }


def brief_to_markdown(brief: dict, query: str) -> str:
    """Render a brief dict as a readable markdown report."""
    out = [f"# Intelligence Brief: {query}", ""]
    out.append(f"**Bottom line:** {brief.get('executive_summary', 'N/A')}")
    out.append("")

    themes = brief.get("risk_themes", [])
    if themes:
        out.append("## Risk Themes")
        for t in themes:
            sev = t.get("severity", "?")
            badge = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(sev, "⚪")
            out.append(f"### {badge} {t.get('theme', 'Theme')} — {sev}")
            out.append(t.get("summary", ""))
            srcs = t.get("source_titles", [])
            if srcs:
                out.append("Sources: " + "; ".join(srcs[:4]))
            out.append("")

    ents = brief.get("notable_entities", [])
    if ents:
        out.append("## Notable Entities")
        for e in ents:
            out.append(f"- **{e.get('name','?')}** ({e.get('role','?')}): {e.get('context','')}")
        out.append("")

    gaps = brief.get("evidence_gaps", [])
    if gaps:
        out.append("## Evidence Gaps")
        for g in gaps:
            out.append(f"- 🔍 {g}")
        out.append("")

    nxt = brief.get("recommended_next_steps", [])
    if nxt:
        out.append("## Recommended Next Steps")
        for n in nxt:
            if isinstance(n, dict):
                out.append(f"- **{n.get('entity','?')}**: {n.get('action','?')} [{n.get('tool_hint','?')}]")
            else:
                out.append(f"- {n}")
        out.append("")

    return "\n".join(out)
