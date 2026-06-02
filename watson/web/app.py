"""
Watson Web — FastAPI product shell.

Thin layer that:
- Serves the chat UI
- Routes investigation requests to the engine (via agent adapter)
- Publishes completed cases to MCP (free tier)
- Auth (GitHub OAuth) and billing stubs for paid features

Watson is agent-agnostic — the AdapterFactory creates the right adapter
from config (Hermes, OpenClaw, Direct LLM, etc.).
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiohttp
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from ..engine import InvestigationEngine
from ..graph import KnowledgeGraph

# ── App ─────────────────────────────────────────────────────────

app = FastAPI(
    title="Watson OSINT",
    description="The OSINT investigation engine. Bellingcat-inspired. Graph-native.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Templates + static
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

static_dir = BASE_DIR / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# ── Store ───────────────────────────────────────────────────────

# In-memory store (replace with DB for production)
active_investigations: dict[str, dict] = {}
case_store: dict[str, dict] = {}

# Knowledge graph singleton
graph = KnowledgeGraph()

# Agent adapter (lazy-loaded)
_agent = None
_engine = None


def get_engine() -> InvestigationEngine:
    """Get or create the investigation engine with configured adapter."""
    global _agent, _engine
    
    if _engine is not None:
        return _engine
    
    # Determine which adapter to use
    agent_type = os.environ.get("WATSON_AGENT", "hermes")
    
    if agent_type == "hermes":
        from ..agents.hermes import HermesAdapter
        _agent = HermesAdapter(
            api_url=os.environ.get("HERMES_API_URL", "http://localhost:8778"),
        )
    elif agent_type == "direct":
        from ..agents.direct import DirectAdapter
        _agent = DirectAdapter(
            api_key=os.environ.get("WATSON_API_KEY", os.environ.get("DEEPSEEK_API_KEY", "")),
            model=os.environ.get("WATSON_MODEL", "deepseek-chat"),
        )
    else:
        raise ValueError(f"Unknown agent type: {agent_type}")
    
    _engine = InvestigationEngine(agent=_agent, graph=graph)
    return _engine


# ── Models ──────────────────────────────────────────────────────

class InvestigateRequest(BaseModel):
    query: str
    private: bool = False  # premium: don't publish to MCP
    client_id: Optional[str] = None


class ChatMessage(BaseModel):
    message: str
    client_id: Optional[str] = None
    session_id: Optional[str] = None


# ── Routes ──────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Watson chat interface."""
    return templates.TemplateResponse("chat.html", {
        "request": request,
        "title": "Watson OSINT",
    })


@app.get("/health")
async def health():
    """Health check."""
    engine = get_engine()
    try:
        agent_ok = await engine.agent.health_check()
    except Exception:
        agent_ok = False
    
    return {
        "status": "ok",
        "agent": engine.agent.name,
        "agent_healthy": agent_ok,
        "graph": graph.stats(),
    }


@app.post("/api/investigate")
async def investigate(request: InvestigateRequest):
    """Run an investigation. Returns case with findings."""
    engine = get_engine()
    
    investigation_id = uuid.uuid4().hex[:12]
    
    # Track investigation
    active_investigations[investigation_id] = {
        "query": request.query,
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "private": request.private,
    }
    
    # Run investigation
    case = await engine.investigate(request.query)
    
    # Store case
    case_data = {
        "id": case.id,
        "query": request.query,
        "target_type": case.target_type,
        "findings_count": len(case.findings),
        "angles": case.angles,
        "markdown": case.markdown,
        "graph_updates": case.graph_updates,
        "cross_references": len(case.cross_references),
        "created_at": case.created_at,
        "published": not request.private,
    }
    case_store[case.id] = case_data
    
    # Update investigation status
    active_investigations[investigation_id]["status"] = "complete"
    active_investigations[investigation_id]["case_id"] = case.id
    
    return {
        "investigation_id": investigation_id,
        "case": case_data,
    }


@app.post("/api/investigate/stream")
async def investigate_stream(request: InvestigateRequest):
    """SSE streaming investigation — sends events as angles complete."""
    engine = get_engine()
    
    async def event_stream():
        investigation_id = uuid.uuid4().hex[:12]
        
        # Send start event
        yield f"data: {json.dumps({'event': 'start', 'investigation_id': investigation_id, 'query': request.query})}\n\n"
        
        # Run investigation
        case = await engine.investigate(request.query)
        
        # Send finding events
        for finding in case.findings:
            yield f"data: {json.dumps({'event': 'finding', 'title': finding.title, 'confidence': finding.confidence, 'source': finding.source_url or finding.source_type})}\n\n"
        
        # Send graph context
        if case.cross_references:
            yield f"data: {json.dumps({'event': 'cross_refs', 'count': len(case.cross_references), 'refs': case.cross_references[:5]})}\n\n"
        
        # Send complete event
        yield f"data: {json.dumps({'event': 'complete', 'case_id': case.id, 'findings': len(case.findings), 'angles': len(case.angles), 'markdown': case.markdown})}\n\n"
    
    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/case/{case_id}")
async def get_case(case_id: str):
    """Retrieve a completed case."""
    case = case_store.get(case_id)
    if not case:
        # Try loading from disk
        engine = get_engine()
        markdown = engine.load_case(case_id)
        if markdown:
            return {"id": case_id, "markdown": markdown}
        raise HTTPException(404, "Case not found")
    return case


@app.get("/api/cases")
async def list_cases():
    """List all cases."""
    engine = get_engine()
    disk_cases = engine.list_cases()
    
    # Merge with in-memory cases
    result = list(case_store.values())
    for dc in disk_cases:
        if dc["id"] not in case_store:
            result.append(dc)
    
    return {"cases": result, "count": len(result)}


@app.get("/api/graph/context")
async def graph_context(q: str):
    """Check knowledge graph for prior findings on a target."""
    context = graph.context_for_investigation(q)
    return context


@app.get("/api/graph/stats")
async def graph_stats():
    """Knowledge graph statistics."""
    return graph.stats()


# ── Chat endpoint ───────────────────────────────────────────────

@app.post("/api/chat")
async def chat(message: ChatMessage):
    """Chat with Watson — sends investigation queries to the engine."""
    engine = get_engine()
    
    query = message.message.strip()
    if not query:
        return {"response": "What would you like to investigate?"}
    
    # Run as investigation
    case = await engine.investigate(query)
    
    # Generate conversational response
    high_conf = sum(1 for f in case.findings if f.confidence >= 0.7)
    summary = (
        f"## 🔍 Investigation: {query}\n\n"
        f"**Findings:** {len(case.findings)} across {len(case.angles)} angles "
        f"({high_conf} high-confidence)\n\n"
        f"**Case:** {case.id}\n"
        f"**Graph updates:** {case.graph_updates.get('entities', 0)} entities indexed\n\n"
        f"The full briefing has been saved. Want me to show it or dig deeper on any angle?"
    )
    
    return {
        "response": summary,
        "case_id": case.id,
        "markdown": case.markdown,
    }


# ── Auth — GitHub OAuth ───────────────────────────────────────

import secrets as _secrets
from urllib.parse import urlencode

# Session store (in-memory; replace with DB for production)
_user_sessions: dict[str, dict] = {}

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
GITHUB_REDIRECT_URI = os.environ.get(
    "GITHUB_REDIRECT_URI",
    "http://localhost:8000/auth/github/callback",
)


@app.get("/auth/github")
async def github_login(request: Request):
    """Initiate GitHub OAuth flow."""
    if not GITHUB_CLIENT_ID:
        return {"error": "GitHub OAuth not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET."}

    state = _secrets.token_hex(16)
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": GITHUB_REDIRECT_URI,
        "scope": "read:user user:email",
        "state": state,
    }
    auth_url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    return RedirectResponse(auth_url)


@app.get("/auth/github/callback")
async def github_callback(code: str, state: str = ""):
    """Handle GitHub OAuth callback — exchange code for token, fetch user."""
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise HTTPException(500, "GitHub OAuth not configured")

    # Exchange code for access token
    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": GITHUB_REDIRECT_URI,
            },
            headers={"Accept": "application/json"},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            token_data = await resp.json()

        access_token = token_data.get("access_token")
        if not access_token:
            error = token_data.get("error_description", token_data.get("error", "Unknown error"))
            raise HTTPException(400, f"GitHub auth failed: {error}")

        # Fetch user info
        async with session.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            user_data = await resp.json()

    # Create session
    session_token = _secrets.token_hex(32)
    user = {
        "id": user_data.get("id"),
        "login": user_data.get("login"),
        "name": user_data.get("name", user_data.get("login")),
        "email": user_data.get("email", ""),
        "avatar_url": user_data.get("avatar_url", ""),
        "tier": "free",  # default tier
    }
    _user_sessions[session_token] = user

    return {
        "success": True,
        "user": user,
        "session_token": session_token,
    }


@app.get("/auth/me")
async def auth_me(request: Request):
    """Get current user from session token."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = _user_sessions.get(token)
    if not user:
        raise HTTPException(401, "Not authenticated")
    return {"user": user}


@app.get("/auth/logout")
async def auth_logout(request: Request):
    """Logout — remove session."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    _user_sessions.pop(token, None)
    return {"success": True}


# ── Billing placeholder ─────────────────────────────────────────

@app.get("/billing/plans")
async def billing_plans():
    """Placeholder: Premium plans."""
    return {
        "plans": [
            {"name": "Free", "price": 0, "features": ["Public cases", "Community MCP", "Self-hosted"]},
            {"name": "Journalist", "price": 50, "features": ["Private cases", "File upload", "Priority support"]},
            {"name": "Team", "price": 200, "features": ["5 seats", "API access", "Slack integration"]},
            {"name": "Enterprise", "price": "Custom", "features": ["On-prem", "SSO", "SLA"]},
        ]
    }
