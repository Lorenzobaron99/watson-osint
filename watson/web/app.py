"""
Watson Web — FastAPI application (Phase 1 rewrite).

Routes:
  GET  /                         — Chat UI
  GET  /health                   — Health check
  POST /api/chat                 — Tool-calling chat (streaming SSE)
  POST /api/agent/investigate    — Agent investigation
  GET  /api/agent/stream/<id>    — Investigation SSE stream
  POST /api/agent/chat/stream    — Chat SSE (with tools)
  + memory, scheduler, bellingcat, export, knowledge, terminal
"""

from __future__ import annotations

import threading
import asyncio
import json
import logging
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Ensure both src/ and project root are on path for imports
#   src/watson/*  → src.watson.agent, src.watson.auth, ...
#   watson/*      → watson.reporter, watson.web.middleware, ...
_src = Path(__file__).resolve().parent.parent.parent / "src"
_root = Path(__file__).resolve().parent.parent.parent
for p in (str(_root), str(_src)):
    if p not in sys.path:
        sys.path.insert(0, p)

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ── App ─────────────────────────────────────────────────────────

app = FastAPI(
    title="Watson OSINT",
    description="The OSINT investigation engine. Evidence-based. Graph-native.",
    version="0.3.0",
)

@app.on_event("startup")
async def _bind_sse_loop():
    """Bind the event loop to SSEManager so events can be enqueued
    from worker threads via call_soon_threadsafe."""
    sse.set_loop(asyncio.get_running_loop())
    # Background cleanup for stale SSE queues (runs every 60s)
    async def _cleanup_loop():
        while True:
            await asyncio.sleep(60)
            sse.cleanup_stale()
    asyncio.create_task(_cleanup_loop())

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth middleware
from src.watson.auth import AuthMiddleware
app.add_middleware(AuthMiddleware)

# ── Health + Metrics ─────────────────────────────────────────────

from src.watson.infra.cache import all_cache_stats
from src.watson.infra.retry import _circuits
from src.watson.persistence import get_store
from src.watson.metrics import prometheus_endpoint, track_investigation

@app.get("/api/metrics")
async def metrics():
    """Prometheus-compatible metrics endpoint."""
    return Response(content=prometheus_endpoint(), media_type="text/plain")

@app.get("/api/health")
async def health():
    """Health check with system status."""
    store = get_store()
    stats = store.get_stats()
    cache_stats = all_cache_stats()
    open_circuits = sum(1 for cb in _circuits.values() if cb.is_open)
    return {
        "status": "ok",
        "version": "0.3.0-enterprise",
        "investigations": stats,
        "caches": {k: {"size": v["size"], "hit_rate": f"{v.get('hits',0)/max(v.get('hits',0)+v.get('misses',1),1):.1%}"}
                   for k, v in cache_stats.items()},
        "circuit_breakers_open": open_circuits,
    }

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
if STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(STATIC_DIR / "assets")), name="assets")
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# MCP community graph server URL — configurable for shared instances
# Priority: env var > config file > default
def _load_mcp_config() -> dict:
    """Load MCP settings from config file (env overrides)."""
    mcp = {
        "url": os.environ.get("WATSON_MCP_URL", ""),
        "key": os.environ.get("MCP_API_KEY", ""),
    }
    try:
        cfg_path = Path.home() / ".watson" / "config.json"
        if cfg_path.exists():
            cfg = json.loads(cfg_path.read_text())
            if not mcp["url"]:
                mcp["url"] = cfg.get("mcp_url", "")
            if not mcp["key"]:
                mcp["key"] = cfg.get("mcp_api_key", "")
    except Exception:
        pass
    if not mcp["url"]:
        mcp["url"] = "http://localhost:8700"
    return mcp

_mcp = _load_mcp_config()
MCP_SERVER_URL = _mcp["url"]
MCP_API_KEY = _mcp["key"]

# ── Env loading (must be first — MCP server subprocess needs these vars) ──

def _load_env():
    env_path = os.path.expanduser("~/.hermes/.env")
    if not os.path.exists(env_path):
        return
    with open(env_path) as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and v and k not in os.environ:
                    os.environ[k] = v

_load_env()

# ── Auto-start local MCP server ──────────────────────────────────

def _start_mcp_server():
    """Start the MCP knowledge graph server as a subprocess if URL is local."""
    if "localhost" not in MCP_SERVER_URL and "127.0.0.1" not in MCP_SERVER_URL:
        return  # Remote MCP — assume it's already running
    
    mcp_port = MCP_SERVER_URL.rsplit(":", 1)[-1]
    import subprocess as _sp
    import sys as _sys
    try:
        proc = _sp.Popen(
            [_sys.executable, "-m", "uvicorn", "watson.mcp_server:mcp",
             "--host", "0.0.0.0", "--port", mcp_port],
            cwd=str(Path(__file__).resolve().parents[2]),  # project root
            env={**os.environ, "PYTHONPATH": f".:{os.environ.get('PYTHONPATH', '')}"},
            stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
        )
        logging.getLogger("watson").info("mcp_server_started", extra={"port": mcp_port, "pid": proc.pid})
    except Exception as e:
        logging.getLogger("watson").warning("mcp_server_start_failed: %s", e)

_start_mcp_server()

# ── Enterprise middleware ─────────────────────────────────────────

from watson.web.middleware import init_app, register_task

init_app(app)  # Auth, rate limiting, structured logging, tracing, graceful shutdown

logger = logging.getLogger("watson")

import datetime as _dt


def _json_default(obj):
    """JSON default handler: datetime → ISO, everything else → truncated str."""
    if isinstance(obj, _dt.datetime):
        return obj.isoformat()
    if isinstance(obj, _dt.date):
        return obj.isoformat()
    # Safety net — never let str() produce huge blobs
    s = str(obj)
    return s[:200] if len(s) > 200 else s


_JSON_MAX_BYTES = 500_000  # 500 KB — drop events bigger than this


def _safe_serialize(ev_type: str, ev_data: dict) -> tuple[bool, str]:
    """Serialize event data to SSE-safe JSON. Returns (ok, sse_string).
    
    ok=False means serialization failed outright (exception during json.dumps).
    ok=True with data starting with _TRUNCATED marker means the payload was
    oversized and has been replaced with a stub.
    """
    try:
        j = json.dumps(ev_data, default=_json_default)
        if len(j) > _JSON_MAX_BYTES:
            logger.warning(
                "sse_event_too_large: type=%s size=%d — truncating", ev_type, len(j)
            )
            j = json.dumps({
                "_truncated": True,
                "_original_type": ev_type,
                "_original_size": len(j),
                "message": f"Event payload too large ({len(j)} bytes). "
                           f"Full data available in saved case report.",
            })
        return True, f"event: {ev_type}\ndata: {j}\n\n"
    except Exception as e:
        logger.warning("sse_serialize_failed: type=%s error=%s", ev_type, e)
        return False, f"event: error\ndata: {json.dumps({'message': 'Serialization failed'})}\n\n"


# ── SSE helper (thread-safe) ─────────────────────────────────────

class SSEManager:
    """Per-client SSE event queues — thread-safe via call_soon_threadsafe.

    asyncio.Queue produces events correctly when enqueued from the event loop
    thread. Investigations run in a worker thread (asyncio.to_thread), so we
    use loop.call_soon_threadsafe() to safely enqueue from any thread.

    Previous approaches that failed:
    - asyncio.Queue + put_nowait(): race condition corrupts the queue
    - queue.Queue + run_in_executor(get): leaked threads poison event delivery
      (stale blocked threads capture events meant for the active consumer)
    """
    def __init__(self):
        self._queues: dict[str, asyncio.Queue] = {}
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._active_consumers: dict[str, float] = {}  # client_id -> last_active_timestamp
        self._close_times: dict[str, float] = {}  # client_id -> when _close was sent

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    def create(self, client_id: str) -> asyncio.Queue:
        q = asyncio.Queue()
        with self._lock:
            self._queues[client_id] = q
        return q

    def send(self, client_id: str, event: str, data: dict):
        with self._lock:
            q = self._queues.get(client_id)
        if q and self._loop:
            # ── Pre-serialize to catch bad data before it hits the stream ──
            ok, _pre = _safe_serialize(event, data)
            if ok:
                # call_soon_threadsafe queues a callback to run put_nowait
                # in the event loop thread — the only safe way to touch asyncio.Queue
                # from a worker thread.
                self._loop.call_soon_threadsafe(
                    lambda q=q, item=(event, data): q.put_nowait(item)
                )
            else:
                logger.warning("sse_dropped: type=%s — unserializable", event)

    def remove(self, client_id: str):
        with self._lock:
            self._queues.pop(client_id, None)
            self._active_consumers.pop(client_id, None)
            self._close_times.pop(client_id, None)

    def cleanup_stale(self):
        """Remove queues for completed/abandoned investigations.
        
        Removes queues where:
        - _close was sent > 60s ago (investigation finished, grace period expired)
        - No active consumer for > 15 min (abandoned investigation)
        """
        now = time.time()
        with self._lock:
            stale = []
            for cid in list(self._queues.keys()):
                close_time = self._close_times.get(cid, 0)
                last_active = self._active_consumers.get(cid, 0)
                if close_time and (now - close_time) > 60:
                    stale.append(cid)
                elif not last_active and not close_time:
                    # No consumer ever connected? Check queue creation via...
                    # Can't easily track creation time. Skip.
                    pass
                elif last_active and (now - last_active) > 900:  # 15 min
                    stale.append(cid)
            for cid in stale:
                self._queues.pop(cid, None)
                self._active_consumers.pop(cid, None)
                self._close_times.pop(cid, None)
        if stale:
            logger.info("sse_cleanup: removed %d stale queues", len(stale))

sse = SSEManager()

# ── Models ───────────────────────────────────────────────────────

class InvestigateRequest(BaseModel):
    query: str
    client_id: Optional[str] = None
    image_path: Optional[str] = None
    depth: int = 2
    context: str = ""
    mode: str = "deep_investigation"  # "background_check" | "due_diligence" | "deep_investigation"
    publish_to_graph: bool = False   # Per-case consent: publish findings to community knowledge graph

    @property
    def safe_depth(self) -> int:
        return max(1, min(self.depth, 5))  # Clamp 1-5

class ChatRequest(BaseModel):
    message: str
    findings: list = []
    history: list = []
    last_query: str = ""

# ── Routes ───────────────────────────────────────────────────────

_NO_CACHE = {
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the React app (built to static/) or fall back to old HTML."""
    index = STATIC_DIR / "index.html"
    if index.exists():
        return HTMLResponse(content=index.read_text(), headers=_NO_CACHE)
    # Fallback to old template
    path = TEMPLATES_DIR / "investigation-map.html"
    if path.exists():
        return HTMLResponse(content=path.read_text(), headers=_NO_CACHE)
    return HTMLResponse("<h1>Watson — run <code>cd frontend && npm run build</code></h1>", status_code=404)

@app.get("/chat", response_class=HTMLResponse)
async def chat():
    """Serve the React app at /chat too."""
    return await root()
    return HTMLResponse(content=path.read_text(), headers=_NO_CACHE)

@app.get("/health")
async def health():
    """Health check with dependency verification."""
    deps = {}
    
    # Check DeepSeek API
    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    deps["deepseek_api"] = "configured" if api_key and api_key != "***" else "missing"
    
    # Check memory DB
    try:
        from watson.memory import memory as mem
        stats = mem.stats()
        deps["memory_db"] = {"status": "ok", "investigations": stats.get("investigations", 0)}
    except Exception:
        deps["memory_db"] = {"status": "degraded"}
    
    # Check knowledge graph
    try:
        from watson.neo4j_graph import NEO4J_AVAILABLE
        deps["neo4j"] = "available" if NEO4J_AVAILABLE else "fallback_json"
    except Exception:
        deps["neo4j"] = "unknown"
    
    all_ok = all(
        v not in ("missing",) and (isinstance(v, dict) and v.get("status") != "degraded") or isinstance(v, str) and v not in ("missing",)
        for v in deps.values()
    ) or True  # Don't fail health for missing configs in dev
    
    return {
        "status": "ok",
        "version": "1.0.0",
        "server": "FastAPI/uvicorn",
        "dependencies": deps,
    }

@app.get("/api/tools")
async def api_tools():
    return {
        "total": 12,
        "categories": [
            {"category": "toolkit", "count": 1, "tools": [{"name": "osint-toolkit", "description": "338 OSINT investigation tools", "free": True}]},
            {"category": "corporate", "count": 1, "tools": [{"name": "corporate-finance", "description": "Company registries", "free": True}]},
            {"category": "websites", "count": 2, "tools": [{"name": "websites-domains", "description": "Domain investigation", "free": True}, {"name": "browser-automation", "description": "Headless browser", "free": True}]},
            {"category": "social_media", "count": 1, "tools": [{"name": "social-media", "description": "Social media search", "free": True}]},
            {"category": "people", "count": 2, "tools": [{"name": "people-search", "description": "Person lookup", "free": True}, {"name": "scraper", "description": "Wiki/OpenSanctions", "free": True}]},
        ],
    }

# ── Agent Investigation ──────────────────────────────────────────

@app.post("/api/agent/investigate")
async def agent_investigate(req: InvestigateRequest):
    """Start a Watson v1 investigation. Returns client_id for SSE stream."""
    import gc
    gc.collect()
    
    from src.watson.orchestration import get_engine
    
    client_id = f"agent-{uuid.uuid4().hex[:8]}"
    q = sse.create(client_id)
    
    async def run():
        def push(event_type, data):
            sse.send(client_id, event_type, data)
        # ── Mode-based hard timeout — prevents hung investigations from blocking server ──
        _mode_timeouts = {
            "background_check": 120,
            "due_diligence": 420,
            "deep_investigation": 900,
            "twin_connection": 300,
        }
        _hard_timeout = _mode_timeouts.get(req.mode, 600)
        try:
            engine = get_engine()
            # Register interrupt queue for interactive steering
            engine.register_interrupt_queue(client_id)
            # ── Run investigation in a dedicated thread so CPU-bound loops
            # don't block the uvicorn event loop. The asyncio.wait_for timeout
            # will fire even if the thread hangs. ──
            def _run_sync():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    return loop.run_until_complete(engine.investigate(
                        query=req.query,
                        focus=req.context,
                        on_event=push,
                        mode=req.mode,
                        save_mode="auto",
                    ))
                finally:
                    loop.close()
            result = await asyncio.wait_for(
                asyncio.to_thread(_run_sync),
                timeout=_hard_timeout,
            )
            
            # Send final report event with markdown
            sse.send(client_id, "report", {
                "case_id": result["case_id"],
                "findings_count": result["findings_count"],
                "confirmed": result["confirmed_count"],
                "verifiability": f"{result['verifiability_score']:.0%}",
                "markdown": result.get("markdown", ""),
                "published_to_graph": req.publish_to_graph,
            })
            
            # ── Per-case consent: publish to community knowledge graph ──
            if req.publish_to_graph and result.get("findings"):
                publish_error = None
                try:
                    # Check if key is available for remote MCP
                    is_local = "localhost" in MCP_SERVER_URL or "127.0.0.1" in MCP_SERVER_URL
                    if not is_local and not MCP_API_KEY:
                        publish_error = "No MCP API key configured. Set it in onboarding or with: export MCP_API_KEY=your-key"
                    else:
                        # Use the engine's report if available, otherwise publish manually
                        engine_report = getattr(result, '_report', None)
                        if engine_report:
                            _pub_result, _pub_err = _publish_to_mcp(engine_report)
                            if _pub_err:
                                publish_error = _pub_err
                        else:
                            # Fallback: publish entities from findings directly
                            import httpx
                            entities = []
                            for f in result["findings"]:
                                if hasattr(f, 'tier') and f.tier in ("CONFIRMED", "PROBABLE"):
                                    for ent in getattr(f, 'entities', []):
                                        # Normalize entities — they come in as strings, dicts, or objects
                                        if isinstance(ent, str):
                                            val, etype = ent.strip(), "unknown"
                                        elif isinstance(ent, dict):
                                            val = ent.get("value", ent.get("canonical", ""))
                                            etype = ent.get("type", "unknown")
                                        elif hasattr(ent, 'value'):
                                            val = getattr(ent, 'value', '') or getattr(ent, 'canonical', '')
                                            etype = getattr(ent, 'type', 'unknown')
                                        else:
                                            val, etype = str(ent), "unknown"
                                        # Skip empty values — MCP validator rejects them
                                        if not val or not val.strip():
                                            continue
                                        entities.append({
                                            "value": val.strip()[:500],
                                            "type": etype or "unknown",
                                            "source": ent.get("source", "") if isinstance(ent, dict) else "",
                                            "tier": f.tier if hasattr(f, 'tier') else "PROBABLE",
                                            "case_id": result["case_id"],
                                        })
                            if entities:
                                payload = {
                                    "case_id": result["case_id"],
                                    "target": req.query,
                                    "target_type": "",
                                    "findings_count": len(result["findings"]),
                                    "confirmed_count": result.get("confirmed_count", 0),
                                    "verifiability": "",
                                    "date": "",
                                    "entities": entities,
                                }
                                resp = httpx.post(
                                    f"{MCP_SERVER_URL}/api/ingest",
                                    json=payload, timeout=10,
                                    headers={"X-API-Key": MCP_API_KEY} if MCP_API_KEY else {},
                                )
                                if resp.status_code != 200:
                                    publish_error = f"MCP server returned {resp.status_code}"
                except Exception as e:
                    publish_error = str(e)

                if publish_error:
                    sse.send(client_id, "graph_error", {
                        "message": f"Graph publish failed: {publish_error}",
                        "case_id": result["case_id"],
                    })
                else:
                    sse.send(client_id, "graph_published", {
                        "case_id": result["case_id"],
                        "url": MCP_SERVER_URL,
                    })
            
            logger.info("investigation_complete", extra={
                "client_id": client_id, "query": req.query[:80],
                "findings": result["findings_count"],
                "case": result["case_id"],
            })
        except asyncio.TimeoutError:
            logger.error("investigation_timeout", extra={
                "client_id": client_id, "query": req.query[:80],
                "mode": req.mode,
            })
            sse.send(client_id, "error", {
                "message": f"Investigation timed out after {_hard_timeout}s — try a shallower mode or narrower query"
            })
        except Exception as e:
            logger.error("investigation_failed", extra={
                "client_id": client_id, "query": req.query[:80], "error": str(e),
            })
            sse.send(client_id, "error", {"message": str(e)})
        finally:
            await asyncio.sleep(0.5)
            sse.send(client_id, "_close", {})
            # Cleanup interrupt queue
            from src.watson.orchestration import get_engine as _get_eng
            _eng = _get_eng()
            _eng.remove_interrupt_queue(client_id)
    
    task = asyncio.create_task(run())
    register_task(task)
    return {"client_id": client_id, "status": "started"}

@app.get("/api/agent/stream/{client_id}")
async def agent_stream(client_id: str):
    """SSE stream for an investigation in progress.
    
    Survives client disconnects: the queue is NOT removed when the client
    drops. Events buffer and are replayed when the client reconnects.
    The queue is only cleaned up when the investigation sends _close OR
    after a TTL (no consumer for 10 minutes).
    """
    q = sse._queues.get(client_id)
    if not q:
        async def error_gen():
            yield f"event: error\ndata: {json.dumps({'message': 'Stream not found'})}\n\n"
            yield "event: done\ndata: {}\n\n"
        return StreamingResponse(error_gen(), media_type="text/event-stream")
    
    async def generate():
        # Mark this queue as having an active consumer
        sse._active_consumers[client_id] = time.time()
        try:
            while True:
                try:
                    ev_type, ev_data = await asyncio.wait_for(q.get(), timeout=30.0)
                    _ok, sse_str = _safe_serialize(ev_type, ev_data)
                    yield sse_str
                    if ev_type == "_close":
                        # Investigation finished — queue survives 30s for late reconnects
                        sse._close_times[client_id] = time.time()
                        break
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            # Don't remove queue on disconnect — let events buffer for reconnection.
            # Only mark consumer as gone. Queue cleanup happens on _close or TTL.
            sse._active_consumers.pop(client_id, None)
    
    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Interactive Investigation Steering ──────────────────────────

class InterruptRequest(BaseModel):
    action: str = "context"  # "context", "stop", "skip_phase"
    text: str = ""

@app.post("/api/agent/investigate/{client_id}/interrupt")
async def agent_interrupt(client_id: str, req: InterruptRequest):
    """Send a steering command to a running investigation."""
    from src.watson.orchestration import get_engine
    engine = get_engine()
    ok = engine.send_interrupt(client_id, {"action": req.action, "text": req.text})
    if ok:
        return {"status": "sent", "client_id": client_id}
    return JSONResponse(
        status_code=404,
        content={"status": "not_found", "message": f"No active investigation: {client_id}"}
    )


# ── Agent Chat with Tools (SSE) ──────────────────────────────────

WATSON_SOUL = (
    "You are Watson, an autonomous OSINT investigator.\n\n"
    "ABSOLUTE RULES — VIOLATION MEANS FAILURE:\n"
    "- NEVER fabricate specific identifiers: no invented SAR numbers, VINs, wallet addresses, "
    "transaction hashes, case IDs, or document numbers.\n"
    "- NEVER invent reports or documents you cannot link to a public URL.\n"
    "- NEVER fabricate dollar amounts from inaccessible databases.\n"
    "- MARK UNCERTAINTY: [CONFIRMED], [PLAUSIBLE BUT UNVERIFIED], [HYPOTHETICAL — NOT REAL].\n"
    "- When OSINT data runs out, STOP and state the boundary.\n\n"
    "CAPABILITIES: web_search, fetch_url, whois_lookup, dns_lookup, crt_sh_search, "
    "wayback_machine, etherscan_lookup, opencorporates_search, news_search, "
    "run_terminal_command, investigate_target.\n\n"
    "TONE: Sharp, direct, evidence-based. Brief like an intelligence analyst.\n"
    "Use bullet points. Cite sources. Flag gaps.\n\n"
    "CRITICAL — AFTER EVERY ANSWER:\n"
    "If the user has CURRENT FINDINGS from an active investigation, you MUST end your response "
    "with a 'Follow-up leads' section suggesting 2-3 concrete next investigation steps based on:\n"
    "- Entities discovered but not yet explored (domains, people, companies in the findings)\n"
    "- Gaps in the evidence (missing WHOIS details, unverified registrars, unresearched nameservers)\n"
    "- Cross-references that deserve deeper investigation\n"
    "Format each lead as: '🔍 Investigate [entity/value] — [why it matters]'\n"
    "This is mandatory — the investigation is incomplete without follow-up leads.\n"
)

@app.post("/api/agent/chat/stream")
async def agent_chat_stream(req: ChatRequest):
    """Streaming chat — delegates to investigation engine for chat-style queries."""
    async def respond():
        yield f"event: token\ndata: {json.dumps({'token': 'Chat mode coming soon. Use /api/agent/investigate for full OSINT investigations.'})}\n\n"
        yield "event: done\ndata: {}\n\n"
    return StreamingResponse(respond(), media_type="text/event-stream")

# ── Agent Tools ──────────────────────────────────────────────────

@app.get("/api/agent/detect-intent")
async def detect_intent(msg: str = Query("", description="Message to classify")):
    """Determine whether a message is an investigation request or a chat question.
    Public endpoint — no auth required."""
    msg = msg.strip()
    if not msg:
        return {"intent": "chat", "confidence": 1.0}
    
    # TECHNICAL TARGETS — clearly investigable, auto-dispatch
    if re.search(r"\.(com|org|net|io|gov|edu|uk|de|fr|ru|cn|jp|ai|dev|onion)\b", msg, re.IGNORECASE):
        return {"intent": "investigate", "confidence": 0.95, "reason": "domain_detected"}
    if re.search(r"@[\w.-]+\.[a-z]{2,}", msg):
        return {"intent": "investigate", "confidence": 0.95, "reason": "email_detected"}
    if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", msg):
        return {"intent": "investigate", "confidence": 0.95, "reason": "ip_detected"}
    if re.search(r"0x[a-fA-F0-9]{40}", msg):
        return {"intent": "investigate", "confidence": 0.95, "reason": "crypto_detected"}
    
    # EXPLICIT INVESTIGATION COMMANDS
    if re.match(r"^(investigate|look\s+into|research|dig\s+into|check\s+out|find\s+everything\s+(?:about|on))\s+", msg, re.IGNORECASE):
        return {"intent": "investigate", "confidence": 0.85, "reason": "explicit_command"}

    # OSINT-INTENT PHRASES — these signal "investigate X", not a chat question.
    # "Amazon due diligence", "background check on Acme", "Tesla controversies",
    # "risks of investing in X", "Acme lawsuits/sanctions/scandal".
    osint_intent = re.search(
        r"(?i)\b(due\s+diligence|background\s+check|kyc|aml|"
        r"controvers(?:y|ies)|lawsuit?s?|litigation|sanction(?:s|ed)?|"
        r"scandal|fraud|investigation|red\s+flags?|reputation|"
        r"risk\s+(?:assessment|profile|exposure)|adverse\s+media|"
        r"compliance|regulatory\s+action|antitrust|wrongdoing)\b",
        msg,
    )
    if osint_intent:
        return {"intent": "investigate", "confidence": 0.88,
                "reason": f"osint_intent:{osint_intent.group(1).lower()}"}
    
    # OSINT-QUESTION PATTERNS — questions that demand investigation, not chat.
    # "What is the corporate structure of X", "Who owns Y", "How did Z become involved"
    # These look like "what/who/how" questions but are OSINT targets.
    osint_question = re.search(
        r"(?i)\b("
        r"corporate\s+structure|beneficial\s+owner(?:s|ship)?|"
        r"who\s+owns?|who\s+controls?|"
        r"ownership\s+(?:structure|chain|network)|"
        r"shell\s+compan|subsidiary|parent\s+compan|"
        r"supply\s+chain|shipping\s+(?:compan|fleet|network)|"
        r"how\s+did\s+.+\s+become\s+involved|"
        r"what\s+(?:companies|entities|firms)\s+(?:are|own|control|operate)"
        r")\b",
        msg,
    )
    if osint_question:
        return {"intent": "investigate", "confidence": 0.82,
                "reason": f"osint_question:{osint_question.group(1).lower()[:40]}"}

    # CHAT PATTERNS — questions about knowledge, not OSINT targets
    chat_patterns = [
        r"^(what|who|where|when|why|how)\s+(is|are|was|were|do|does|did|can|could|would|should|shall|will|may|might)",
        r"\?$",  # ends with question mark
        r"^(tell|explain|describe|show|list|summarize|compare|define|elaborate)",
        r"^(hello|hi|hey|help|thanks|thank|what's up|howdy)",
        r"^(what|who|where|when|why|how)\s+(about|to|can|could|do)",
        r"^(can|will|would)\s+you\s+(tell|explain|show|help|list)",
        r"^(i\s+(?:have|need|want)\s+(?:a|some|to)\s+(?:question|ask|know|understand))",
    ]
    for pattern in chat_patterns:
        if re.search(pattern, msg, re.IGNORECASE):
            return {"intent": "chat", "confidence": 0.90, "reason": "conversational_pattern"}
    
    # ── LLM CLASSIFIER FALLBACK ──
    # If none of the fast-path regexes matched, ask the LLM. This replaces
    # the old "default to chat" which trapped investigable targets like
    # "Area 51" and article headlines in a 5-turn conversation loop.
    try:
        from src.watson.orchestration.intent_classifier import classify_intent
        from src.watson.orchestration.llm_config import call_llm

        intent, confidence, reason = await classify_intent(msg, call_llm)
        return {"intent": intent, "confidence": confidence, "reason": reason}
    except Exception as e:
        logger.warning("intent_classifier_error: %s", e)

    # Absolute last resort — short non-question messages are probably targets
    word_count = len(msg.split())
    if "?" not in msg and word_count <= 15 and any(c.isalpha() for c in msg):
        return {"intent": "investigate", "confidence": 0.50,
                "reason": "fallback_short_topic"}
    return {"intent": "chat", "confidence": 0.50, "reason": "fallback_ambiguous"}

@app.post("/api/agent/terminal")
async def agent_terminal(req: Request):
    """Terminal command execution — admin key required, allowlist enforced."""
    import subprocess
    
    # Admin auth is handled by middleware — if we get here, it passed
    data = await req.json()
    cmd = data.get("command", "").strip()
    if not cmd:
        return JSONResponse({"error": "No command"}, status_code=400)
    
    # Command allowlist — only safe OSINT tools
    ALLOWED = {"whois", "dig", "nslookup", "curl", "wget", "traceroute", "ping",
               "openssl", "python3", "git", "date", "echo", "cat", "head", "tail"}
    cmd_root = cmd.split()[0].split("/")[-1] if cmd.split() else ""
    if cmd_root not in ALLOWED and not cmd.startswith(("python3 -c", "git ", "curl ", "echo ")):
        logger.warning("terminal_blocked", extra={"command": cmd[:100], "root": cmd_root})
        return JSONResponse(
            {"error": f"Command '{cmd_root}' not in allowlist. Allowed: {', '.join(sorted(ALLOWED))}"},
            status_code=403,
        )
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        logger.info("terminal_executed", extra={"command": cmd[:100], "exit_code": result.returncode})
        return {"stdout": result.stdout.strip()[:10000], "stderr": result.stderr.strip()[:5000], "exit_code": result.returncode}
    except subprocess.TimeoutExpired:
        return {"error": "Timed out (30s)", "exit_code": -1}
    except Exception as e:
        logger.error("terminal_failed", extra={"command": cmd[:100], "error": str(e)})
        return {"error": str(e), "exit_code": -1}

# ── Memory Endpoints ─────────────────────────────────────────────

@app.get("/api/memory/search")
async def memory_search(q: str = Query(...), limit: int = 10):
    try:
        from watson.memory import memory as mem
        return {"results": mem.search(q, limit=limit)}
    except Exception as e:
        logger.warning("memory_search_failed", extra={"query": q[:100], "error": str(e)})
        return {"results": []}

@app.get("/api/memory/recent")
async def memory_recent(limit: int = 20):
    try:
        from watson.memory import memory as mem
        return {"investigations": mem.list_recent(limit=limit)}
    except Exception as e:
        logger.warning("memory_recent_failed", extra={"error": str(e)})
        return {"investigations": []}

@app.get("/api/memory/stats")
async def memory_stats():
    try:
        from watson.memory import memory as mem
        return mem.stats()
    except Exception as e:
        logger.warning("memory_stats_failed", extra={"error": str(e)})
        return {"investigations": 0, "entities": 0, "findings": 0}

# ── Scheduler ────────────────────────────────────────────────────

@app.get("/api/scheduler/jobs")
async def scheduler_list():
    try:
        from watson.core.scheduler import Scheduler
        sched = Scheduler()
        return {"jobs": sched.list_jobs(), "total": len(sched.list_jobs())}
    except Exception as e:
        logger.warning("scheduler_list_failed", extra={"error": str(e)})
        return {"jobs": [], "total": 0}

# ── Toolkit Registry ─────────────────────────────────────────────

@app.get("/api/bellingcat/summary")
async def bellingcat_summary():
    try:
        from watson.toolkit_registry import BellingcatRegistry
        reg = BellingcatRegistry()
        return reg.summary()
    except Exception as e:
        logger.warning("bellingcat_summary_failed", extra={"error": str(e)})
        return {"total_tools": 0, "categories": 0}

# ── Intelligence Ledger ──────────────────────────────────────────

@app.get("/api/ledger/stats")
async def ledger_stats():
    """Cross-case intelligence accumulation statistics."""
    try:
        from src.watson.ethics import get_ledger
        ledger = get_ledger()
        return ledger.get_stats()
    except ImportError:
        try:
            from watson.ethics import get_ledger
            ledger = get_ledger()
            return ledger.get_stats()
        except Exception:
            return {"total_investigations": 0, "status": "ledger_unavailable"}

@app.get("/api/ledger/entity")
async def ledger_entity(q: str = Query(..., description="Entity to query")):
    """Query prior intelligence on a specific entity."""
    try:
        from src.watson.ethics import get_ledger
        ledger = get_ledger()
        result = ledger.get_entity_intel(q)
        if result:
            return {"found": True, "entity": q, "intel": result}
        return {"found": False, "entity": q}
    except ImportError:
        try:
            from watson.ethics import get_ledger
            ledger = get_ledger()
            result = ledger.get_entity_intel(q)
            return {"found": bool(result), "entity": q, "intel": result}
        except Exception:
            return {"found": False, "entity": q, "status": "ledger_unavailable"}

# ── Orchestrator (multi-agent, enterprise) ─────────────────────────

@app.post("/api/agent/orchestrate")
async def agent_orchestrate(req: InvestigateRequest):
    """Multi-turn investigation with persistence, retry, and adversarial resilience."""
    import gc
    gc.collect()

    from src.watson.orchestration import get_engine
    from src.watson.metrics import investigations_total, findings_total, findings_confirmed

    engine = get_engine(max_hops=5)
    client_id = f"orch-{uuid.uuid4().hex[:8]}"
    q = sse.create(client_id)

    async def run():
        def push(event_type, data):
            sse.send(client_id, event_type, data)
        try:
            inv = await engine.investigate(
                query=req.query,
                depth=req.safe_depth,
                mode=req.mode,
                on_event=push,
            )

            findings_total.inc(inv.get("findings_count", 0))
            findings_confirmed.inc(inv.get("confirmed_count", 0))

            # Generate report
            import json as _json
            cross_refs_raw = inv.get("cross_references", [])
            cross_refs = _json.loads(cross_refs_raw) if isinstance(cross_refs_raw, str) else (cross_refs_raw or [])

            sse.send(client_id, "report", {
                "investigation_id": inv.get("case_id", ""),
                "status": "completed",
                "findings_count": inv.get("findings_count", 0),
                "hops": len(inv.get("phases_completed", [])),
                "confirmed": inv.get("confirmed_count", 0),
                "cross_references": len(cross_refs),
                "created_at": inv.get("created_at", ""),
            })
            sse.send(client_id, "cross_references", {"patterns": cross_refs[:5]})

            logger.info("orchestration_complete", extra={
                "investigation_id": inv.get("case_id", ""),
                "query": req.query[:80],
                "findings": inv.get("findings_count", 0),
                "hops": len(inv.get("phases_completed", [])),
                "confirmed": inv.get("confirmed_count", 0),
            })
        except Exception as e:
            logger.error("orchestration_failed", extra={
                "client_id": client_id, "query": req.query[:80], "error": str(e),
            })
            sse.send(client_id, "error", {"message": str(e)})
        finally:
            await asyncio.sleep(0.5)
            sse.send(client_id, "_close", {})
            # Cleanup interrupt queue
            from src.watson.orchestration import get_engine as _get_eng
            _eng = _get_eng()
            _eng.remove_interrupt_queue(client_id)
    
    task = asyncio.create_task(run())
    register_task(task)
    return {"client_id": client_id, "status": "started", "mode": "multi-agent"}


@app.get("/api/agent/agents")
async def list_agents():
    """List all available specialized agents with capabilities."""
    from src.watson.agents import get_all_agents
    agents = get_all_agents()
    return {
        "agents": [
            {
                "role": a.role.value,
                "description": a.description,
                "capabilities": a.capabilities,
                "tool_count": a.tool_count,
            }
            for a in agents.values()
        ],
        "total": len(agents),
    }


# ── Legacy compat ────────────────────────────────────────────────

@app.post("/api/chat")
async def legacy_chat(req: ChatRequest):
    """Legacy alias → forwards to streaming chat."""
    return await agent_chat_stream(req)


# ═══════════════════════════════════════════════════════════════
# PHASE B — Auth, Exports, Search, Workspaces
# ═══════════════════════════════════════════════════════════════

# ── Auth ─────────────────────────────────────────────────────

@app.post("/api/auth/register")
async def auth_register(req: Request):
    """Register a new workspace + admin user."""
    body = await req.json()
    email = body.get("email", "").strip()
    workspace_name = body.get("workspace", "").strip()

    if not email or "@" not in email:
        return JSONResponse(status_code=400, content={"error": "Valid email required"})
    if not workspace_name:
        return JSONResponse(status_code=400, content={"error": "Workspace name required"})

    try:
        from src.watson.auth.store import get_auth_store
        store = get_auth_store()
        ws, user = store.create_workspace(workspace_name, email)
        api_key = store.generate_api_key(user.user_id)
        token = store.create_token(user)

        return {
            "user_id": user.user_id,
            "workspace_id": ws.workspace_id,
            "workspace_name": ws.name,
            "api_key": api_key,
            "token": token.token,
            "expires_at": token.expires_at,
        }
    except Exception as e:
        return JSONResponse(status_code=409, content={"error": str(e)})

@app.post("/api/auth/login")
async def auth_login(req: Request):
    """Login with API key or email + workspace."""
    body = await req.json()
    api_key = body.get("api_key", "").strip()

    try:
        from src.watson.auth.store import get_auth_store
        store = get_auth_store()

        if api_key:
            user = store.validate_api_key(api_key)
        else:
            email = body.get("email", "").strip()
            workspace_id = body.get("workspace_id", "").strip()
            user = store.get_user_by_email(email, workspace_id)

        if not user:
            return JSONResponse(status_code=401, content={"error": "Invalid credentials"})

        token = store.create_token(user)
        return {
            "user_id": user.user_id,
            "workspace_id": user.workspace_id,
            "role": user.role.value,
            "token": token.token,
            "expires_at": token.expires_at,
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


# ── Workspaces ───────────────────────────────────────────────

@app.get("/api/workspace/{workspace_id}")
async def workspace_get(workspace_id: str, req: Request):
    """Get workspace details."""
    from src.watson.auth.store import get_auth_store
    store = get_auth_store()
    ws = store.get_workspace(workspace_id)
    if not ws:
        return JSONResponse(status_code=404, content={"error": "Workspace not found"})
    users = store.list_users(workspace_id)
    return {
        "workspace": {
            "id": ws.workspace_id, "name": ws.name,
            "created_at": ws.created_at,
        },
        "users": [{"id": u.user_id, "email": u.email, "role": u.role.value} for u in users],
    }


# ── Exports ──────────────────────────────────────────────────

class ExportRequest(BaseModel):
    investigation_id: str
    format: str = "json"  # json, stix, misp, pdf, markdown


@app.post("/api/export")
async def export_investigation(export: ExportRequest):
    """Export investigation in requested format."""
    from src.watson.persistence import get_store
    from src.watson.exports import BellingcatReport

    store = get_store()
    inv, steps = store.get_full_investigation(export.investigation_id)
    if inv is None:
        return JSONResponse(status_code=404, content={"error": "Investigation not found"})

    # Collect findings from all steps
    all_findings = []
    for s in steps:
        if s.findings_json:
            try:
                all_findings.extend(json.loads(s.findings_json))
            except json.JSONDecodeError:
                pass

    cross_refs = json.loads(inv.cross_references) if inv.cross_references else []

    report = BellingcatReport(
        query=inv.original_query,
        investigation_id=inv.investigation_id,
        target_type=inv.target_type,
        target_value=inv.target_value,
    )
    report.add_findings(all_findings)
    report.add_cross_references(cross_refs)
    report.hops = inv.total_hops

    # Save to cases directory
    cases_dir = Path("cases/exports")
    cases_dir.mkdir(parents=True, exist_ok=True)

    fmt = export.format.lower()
    if fmt == "json":
        path = report.to_json(cases_dir / f"{inv.investigation_id}.json")
    elif fmt == "stix":
        path = report.to_stix(cases_dir / f"{inv.investigation_id}_stix.json")
    elif fmt == "misp":
        path = report.to_misp(cases_dir / f"{inv.investigation_id}_misp.json")
    elif fmt == "pdf":
        path = report.to_pdf(cases_dir / f"{inv.investigation_id}.pdf")
    elif fmt == "markdown":
        path = cases_dir / f"{inv.investigation_id}.md"
        path.write_text(report.to_markdown())
    else:
        return JSONResponse(status_code=400, content={"error": f"Unknown format: {fmt}"})

    return {
        "format": fmt,
        "path": str(path),
        "size_bytes": path.stat().st_size if path.exists() else 0,
        "findings": len(all_findings),
        "verifiability": f"{report._verifiability():.0%}",
    }


# ── Search ───────────────────────────────────────────────────

@app.get("/api/search")
async def search_investigations(
    q: str = Query("", description="Search query"),
    agent: str = Query("", description="Filter by agent role"),
    tier: str = Query("", description="Filter by evidence tier"),
    limit: int = Query(20, description="Max results"),
):
    """Full-text search across all investigations."""
    if not q:
        return {"results": [], "total": 0, "query": q}

    from src.watson.search import get_search
    s = get_search()
    results = s.search(q, limit=limit, agent_filter=agent, tier_filter=tier)

    return {
        "query": q,
        "total": len(results),
        "results": results,
        "filters": {"agent": agent, "tier": tier},
    }


@app.get("/api/search/investigations")
async def search_inv_list(
    q: str = Query("", description="Search investigations"),
    limit: int = Query(10),
):
    """Search investigation-level metadata."""
    if not q:
        return {"results": [], "total": 0}

    from src.watson.search import get_search
    s = get_search()
    results = s.search_investigations(q, limit=limit)
    return {"query": q, "total": len(results), "results": results}


@app.get("/api/search/stats")
async def search_stats():
    """Get search index statistics."""
    from src.watson.search import get_search
    return get_search().get_stats()


# ═══════════════════════════════════════════════════════════════
# API Key Settings — user-managed keys for tools
# ═══════════════════════════════════════════════════════════════

from pydantic import BaseModel


class SetKeyRequest(BaseModel):
    slug: str
    value: str


class SaveRequest(BaseModel):
    consent_publish: bool = False


@app.post("/api/cases/{case_id}/save")
async def save_case(case_id: str, req: SaveRequest = SaveRequest()):
    """Save a pending investigation to disk + knowledge graph + optionally MCP.

    With auto-save, the case is already on disk. This endpoint handles:
    - pending: save + graph + optional MCP publish
    - already saved: just MCP publish if requested
    """
    from src.watson.orchestration import get_engine
    from pathlib import Path
    engine = get_engine()
    
    report = None
    already_saved = False
    matches: list = []  # populated when case found on disk
    
    if hasattr(engine, '_pending_reports') and case_id in engine._pending_reports:
        report = engine._pending_reports[case_id]
    else:
        # Check if already saved to disk (auto-save mode)
        # _save_case writes "{case_id}_{date}.md" — glob for it
        cases_dir = Path.home() / "watson-cases"
        matches = list(cases_dir.glob(f"{case_id}_*.md")) if cases_dir.exists() else []
        if matches:
            already_saved = True
        else:
            raise HTTPException(404, 
                f"Case {case_id} not found. It may not exist or the server was restarted. "
                f"Run the investigation again.")
    
    if report is not None:
        # Normal flow: save pending report
        engine._save_case(report)
        engine._update_graph(report)
        del engine._pending_reports[case_id]
    
    # Publish to MCP only with explicit consent
    published = False
    publish_error = None
    if req.consent_publish:
        if report:
            ok, err = _publish_to_mcp(report)
        elif already_saved:
            # Reconstruct from disk for publishing
            # _save_case writes "{case_id}_{date}.md" — use first glob match
            case_path = matches[0]
            text = case_path.read_text()
            from src.watson.orchestration.engine import OrchestrationEngine
            entities = OrchestrationEngine._extract_entities_from_text(text)
            if entities:
                import httpx
                import re as _re
                target = ""
                tm = _re.search(r"\*\*Target:\*\*\s*(.+)", text)
                if tm: target = tm.group(1).strip()
                payload = {
                    "case_id": case_id,
                    "target": target,
                    "target_type": "person",
                    "findings_count": 0,
                    "confirmed_count": 0,
                    "verifiability": "",
                    "date": "",
                    "entities": [{
                        "value": e["value"], "type": e["type"],
                        "source": "", "tier": "PROBABLE", "case_id": case_id,
                    } for e in entities],
                }
                resp = httpx.post(
                    f"{MCP_SERVER_URL}/api/ingest", json=payload, timeout=10,
                    headers={"X-API-Key": MCP_API_KEY} if MCP_API_KEY else {},
                )
                ok = resp.status_code == 200
                err = None if ok else f"MCP server returned {resp.status_code}"
            else:
                ok, err = False, "No entities to publish"
        else:
            ok, err = False, "No report data available"
        published = ok
        publish_error = err

    return {
        "case_id": case_id,
        "target": report.query if report else "saved case",
        "findings": len(report.findings) if report else 0,
        "verifiability": f"{report.verifiability_score:.0%}" if report else "",
        "status": "saved" if not already_saved else "already_saved",
        "published": published,
        "publish_error": publish_error,
    }


def _publish_to_mcp(report):
    """Publish case entities to the MCP knowledge graph server with full case data.

    Uses the engine's entity extraction to get real typed entities, not finding titles.
    Returns (success: bool, error: str | None).
    """
    try:
        import httpx
        # Use the engine's entity extraction — not finding titles
        from src.watson.orchestration.engine import OrchestrationEngine

        # Build combined text from all finding titles and bodies
        text = " ".join(f"{f.title} {f.body}" for f in report.findings)
        entities = OrchestrationEngine._extract_entities_from_text(text)
        if not entities:
            return False, "No typed entities to publish"

        payload = {
            "case_id": report.case_id,
            "target": report.query,
            "target_type": getattr(report, "target_type", "person"),
            "findings_count": len(report.findings),
            "confirmed_count": sum(1 for f in report.findings if f.tier == "CONFIRMED"),
            "verifiability": f"{report.verifiability_score:.0%}",
            "date": getattr(report, "timestamp", ""),
            "entities": [{
                "value": e.get("value", ""),
                "type": e.get("type", "unknown"),
                "source": e.get("source", ""),
                "tier": e.get("tier", "PROBABLE"),
                "case_id": report.case_id,
            } for e in entities],
        }

        resp = httpx.post(
            f"{MCP_SERVER_URL}/api/ingest", json=payload, timeout=10,
            headers={"X-API-Key": MCP_API_KEY} if MCP_API_KEY else {},
        )
        if resp.status_code == 200:
            data = resp.json()
            ingested = data.get("entities_ingested", 0)
            rejected = data.get("entities_rejected", 0)
            logger.info("mcp_published", extra={
                "case_id": report.case_id,
                "ingested": ingested,
                "rejected": rejected,
            })
            return True, None
        elif resp.status_code == 401:
            return False, "Invalid MCP API key"
        elif resp.status_code == 503:
            return False, "MCP server not configured (no API key set)"
        else:
            return False, f"MCP server returned {resp.status_code}"
    except Exception as e:
        logger.warning("mcp_publish_error: %s", e)
        return False, str(e)


@app.post("/api/cases/{case_id}/publish")
async def publish_case(case_id: str):
    """Publish an already-saved case to the MCP community graph.

    Uses the engine's entity extraction for properly-typed entities.
    """
    from pathlib import Path
    case_path = Path.home() / "watson-cases" / f"{case_id}.md"
    if not case_path.exists():
        raise HTTPException(404, f"Case {case_id} not found in archives")

    # Reconstruct metadata and extract typed entities
    import re
    text = case_path.read_text()
    target = ""
    target_type = ""
    tm = re.search(r"\*\*Target:\*\*\s*(.+)", text)
    ttm = re.search(r"\*\*Target Type:\*\*\s*(.+)", text)
    fm = re.search(r"\*\*Findings:\*\*\s*(\d+)", text)
    cm = re.search(r"(\d+)\s+CONFIRMED", text)
    vm = re.search(r"\*\*Verifiability:\*\*\s*(.+)", text)
    dm = re.search(r"\*\*Date:\*\*\s*(.+)", text)

    if tm: target = tm.group(1).strip()
    if ttm: target_type = ttm.group(1).strip()
    findings_count = int(fm.group(1)) if fm else 0
    confirmed_count = int(cm.group(1)) if cm else 0
    verifiability = vm.group(1).strip() if vm else ""
    date_str = dm.group(1).strip() if dm else ""

    # Use engine's entity extraction — produces properly-typed entities
    from src.watson.orchestration.engine import OrchestrationEngine
    entities = OrchestrationEngine._extract_entities_from_text(text)
    
    if not entities:
        return {"status": "no_entities", "case_id": case_id}

    if not MCP_API_KEY and "localhost" not in MCP_SERVER_URL:
        raise HTTPException(400, "No MCP API key configured. Set MCP_API_KEY in env or run onboarding.")

    try:
        import httpx
        payload = {
            "case_id": case_id,
            "target": target,
            "target_type": target_type,
            "findings_count": findings_count,
            "confirmed_count": confirmed_count,
            "verifiability": verifiability,
            "date": date_str,
            "entities": [{
                "value": e["value"],
                "type": e["type"],
                "source": "",
                "tier": "PROBABLE",
                "case_id": case_id,
            } for e in entities],
        }
        resp = httpx.post(f"{MCP_SERVER_URL}/api/ingest", json=payload, timeout=10,
                        headers={"X-API-Key": MCP_API_KEY} if MCP_API_KEY else {})
        if resp.status_code == 200:
            data = resp.json()
            return {
                "status": "published",
                "case_id": case_id,
                "entities_sent": len(entities),
                "entities_ingested": data.get("entities_ingested", 0),
                "entities_rejected": data.get("entities_rejected", 0),
            }
        elif resp.status_code == 401:
            raise HTTPException(401, "Invalid MCP API key")
        elif resp.status_code == 503:
            raise HTTPException(503, "MCP server not configured")
        raise HTTPException(502, f"MCP server returned {resp.status_code}")
    except httpx.ConnectError:
        raise HTTPException(503, f"MCP server not reachable at {MCP_SERVER_URL}")


@app.get("/api/graph/status")
async def graph_status():
    """Check connection to the MCP community knowledge graph.

    Returns connection status, whether a key is configured, and graph stats.
    Frontend uses this to show the connection indicator next to the publish checkbox.
    """
    is_local = "localhost" in MCP_SERVER_URL or "127.0.0.1" in MCP_SERVER_URL
    has_key = bool(MCP_API_KEY)

    status = {
        "mcp_url": MCP_SERVER_URL,
        "configured": has_key or is_local,
        "reason": "",
        "stats": None,
    }

    if is_local:
        status["reason"] = "Local graph — always available"
    elif not has_key:
        status["reason"] = "No MCP API key configured"
        return status

    try:
        import httpx
        resp = httpx.get(
            f"{MCP_SERVER_URL}/api/stats",
            timeout=3,
            headers={"X-API-Key": MCP_API_KEY},
        )
        if resp.status_code == 200:
            status["stats"] = resp.json()
            status["connected"] = True
        else:
            status["connected"] = False
            status["reason"] = f"MCP server returned {resp.status_code}"
    except Exception as e:
        status["connected"] = False
        status["reason"] = str(e)

    return status


@app.get("/api/public/search")
async def search_public_intel(q: str):
    """Search the community knowledge graph for prior intelligence on a target."""
    try:
        import httpx
        resp = httpx.get(f"{MCP_SERVER_URL}/api/search", params={"q": q, "limit": 10}, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "query": q,
                "results": data.get("results", []),
                "count": data.get("count", 0),
            }
        return {"query": q, "results": [], "count": 0, "error": f"MCP returned {resp.status_code}"}
    except Exception as e:
        return {"query": q, "results": [], "count": 0, "mcp_offline": True}


@app.get("/api/public/stats")
async def public_intel_stats():
    """Get community knowledge graph stats."""
    try:
        import httpx
        resp = httpx.get(f"{MCP_SERVER_URL}/api/stats", timeout=5)
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"MCP returned {resp.status_code}"}
    except Exception as e:
        return {"error": str(e), "mcp_offline": True}


@app.get("/api/cases")
async def list_cases(limit: int = 20, offset: int = 0):
    """List all saved investigation cases."""
    from pathlib import Path
    import re
    
    cases_dir = Path.home() / "watson-cases"
    cases = []
    for f in sorted(cases_dir.glob("CASE-*.md"), key=lambda x: x.stat().st_mtime, reverse=True):
        if not f.name.startswith("CASE-"):
            continue
        text = f.read_text()
        target = ""
        target_type = ""
        findings = 0
        confirmed = 0
        verifiability = ""
        date_match = re.search(r"\*\*Date:\*\*\s*(.+)", text)
        target_match = re.search(r"\*\*Target:\*\*\s*(.+)", text)
        type_match = re.search(r"\*\*Target Type:\*\*\s*(.+)", text)
        findings_match = re.search(r"\*\*Findings:\*\*\s*(\d+)", text)
        confirmed_match = re.search(r"(\d+)\s+CONFIRMED", text)
        verif_match = re.search(r"\*\*Verifiability:\*\*\s*(.+)", text)
        
        if target_match: target = target_match.group(1).strip()
        if type_match: target_type = type_match.group(1).strip()
        if findings_match: findings = int(findings_match.group(1))
        if confirmed_match: confirmed = int(confirmed_match.group(1))
        if verif_match: verifiability = verif_match.group(1).strip()
        date_str = date_match.group(1).strip() if date_match else ""
        
        cases.append({
            "id": f.stem,
            "target": target,
            "target_type": target_type,
            "date": date_str,
            "findings": findings,
            "confirmed": confirmed,
            "verifiability": verifiability,
            "size": f.stat().st_size,
        })
    
    return {
        "cases": cases[offset:offset+limit],
        "total": len(cases),
    }


@app.get("/api/cases/{case_id}")
async def get_case(case_id: str):
    """Get a specific case markdown."""
    from pathlib import Path
    case_path = Path.home() / "watson-cases" / f"{case_id}.md"
    if case_path.exists():
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(case_path.read_text(), media_type="text/markdown")
    raise HTTPException(404, f"Case {case_id} not found")


@app.get("/api/settings/keys")
async def get_api_keys():
    """List all configurable API keys with their status (values masked)."""
    from watson.api_keys import list_keys
    return {"keys": list_keys()}


@app.post("/api/settings/keys")
async def set_api_key(req: SetKeyRequest):
    """Save an API key for a tool."""
    from watson.api_keys import set_key
    set_key(req.slug, req.value)
    return {"status": "ok", "slug": req.slug, "configured": bool(req.value)}


@app.delete("/api/settings/keys/{slug}")
async def delete_api_key(slug: str):
    """Remove an API key."""
    from watson.api_keys import delete_key
    delete_key(slug)
    return {"status": "ok", "slug": slug, "configured": False}


# ── Enterprise Exports ──────────────────────────────────────────

@app.get("/api/export/stix/{case_id}")
async def export_stix_endpoint(case_id: str):
    """Export a completed investigation as STIX 2.1 JSON bundle."""
    from pathlib import Path
    case_path = Path.home() / "watson-cases" / f"{case_id}.md"
    if not case_path.exists():
        # Try case_id with date suffix (CASE-XXX_YYYY-MM-DD)
        matches = list((Path.home() / "watson-cases").glob(f"{case_id}*.md"))
        if matches:
            case_path = matches[0]
        else:
            raise HTTPException(404, f"Case {case_id} not found")

    try:
        from watson.serializers.stix import export_stix
        # Parse minimal info from case filename
        import re
        content = case_path.read_text()
        query_match = re.search(r'\*\*Target:\*\*\s*(.+?)$', content, re.MULTILINE)
        target_match = re.search(r'\*\*Target Type:\*\*\s*(.+?)$', content, re.MULTILINE)
        query = query_match.group(1).strip() if query_match else case_id
        target_type = target_match.group(1).strip() if target_match else "unknown"

        # Build minimal findings from markdown
        findings = _parse_findings_from_markdown(content)

        bundle, _ = export_stix(
            query=query,
            case_id=case_id,
            target_type=target_type,
            findings=findings,
        )
        return JSONResponse(content=bundle, media_type="application/json")
    except Exception as e:
        raise HTTPException(500, f"STIX export failed: {e}")


@app.get("/api/opsec/stats")
async def opsec_stats():
    """OpSec proxy firewall statistics."""
    try:
        from watson.opsec import get_opsec_client
        client = get_opsec_client()
        return client.stats()
    except Exception as e:
        return {"status": "unavailable", "error": str(e)}


# ── SPA fallback — serve React app for all non-API routes ──────────

@app.get("/{full_path:path}", response_class=HTMLResponse)
async def spa_fallback(full_path: str):
    """Serve the React SPA for all client-side routes.
    
    Every URL that isn't an explicit API endpoint or static file
    returns index.html so React Router can handle it client-side.
    """
    # Don't intercept API routes (shouldn't reach here if registered first, but safety)
    if full_path.startswith("api/"):
        raise HTTPException(404)
    index = STATIC_DIR / "index.html"
    if index.exists():
        return HTMLResponse(content=index.read_text(), headers=_NO_CACHE)
    return HTMLResponse(
        "<h1>Watson — run <code>cd frontend && npm run build</code></h1>",
        status_code=404,
    )


def _parse_findings_from_markdown(content: str) -> list:
    """Parse findings from a Watson markdown report for STIX export."""
    import re
    findings = []

    # Find "Key Findings" section
    key_section = re.search(r'## Key Findings\s*\n(.*?)(?=\n## |\Z)', content, re.DOTALL)
    if not key_section:
        return findings

    # Parse individual finding lines (bullet points with tier icons)
    finding_pattern = re.compile(
        r'-\s*(?:🟢|🟡|🟠|🔴|⚪)\s*\*\*(.+?)\*\*\s*\[(.+?)\]\s*\((\d+)% confidence\)\s*\n'
        r'\s*(.+?)(?=\n\s*(?:Source:|$))(?:\n\s*Source:\s*(.+?))?(?=\n- |\n## |\Z)',
        re.DOTALL,
    )

    for m in finding_pattern.finditer(key_section.group(1)):
        title = m.group(1).strip()
        src_tier = m.group(2).strip()
        confidence_str = m.group(3)
        desc = m.group(4).strip()
        source_url = m.group(5).strip() if m.group(5) else ""

        # Map source tier to Watson tier
        tier_map = {"PRIMARY": "CONFIRMED", "SECONDARY": "PROBABLE",
                     "TERTIARY": "POSSIBLE"}
        tier = tier_map.get(src_tier, "POSSIBLE")

        findings.append(SimpleFinding(
            title=title,
            description=desc[:500],
            tier=tier,
            source_url=source_url,
            source_type="osint",
            confidence=int(confidence_str) / 100,
        ))

    return findings


class SimpleFinding:
    """Minimal finding object for STIX export from markdown."""
    def __init__(self, title, description, tier, source_url, source_type, confidence):
        self.id = str(abs(hash(title)) % (10**12))
        self.title = title
        self.description = description
        self.tier = tier
        self.source_url = source_url
        self.source_type = source_type
        self.confidence = confidence
        self.entities = []
