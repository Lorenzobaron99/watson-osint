"""mcp_server.py — REST + MCP Protocol API.

Write endpoints require API key auth. Read endpoints are open.
Set MCP_API_KEY env var on the server. Clients pass X-API-Key header.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, field_validator

from .graph import KnowledgeGraph

# ── API Key Auth ──────────────────────────────────────────────────

MCP_API_KEY = os.environ.get("MCP_API_KEY", "")
MCP_DEV_MODE = os.environ.get("WATSON_DEV", "") in ("1", "true", "yes")

if not MCP_API_KEY and not MCP_DEV_MODE:
    print("⚠  WARNING: MCP_API_KEY not set. Write endpoints are BLOCKED (503).")
    print("   Set MCP_API_KEY env var to enable publishing, or WATSON_DEV=1 for dev mode.")

# ── Rate Limiting ───────────────────────────────────────────────

_MAX_ENTITIES_PER_REQUEST = 500
_MAX_ENTITIES_PER_MINUTE = 2000
_rate_window: defaultdict[str, list[float]] = defaultdict(list)

def _check_rate_limit(key: str) -> bool:
    """Return True if within limit, False if exceeded."""
    now = time.time()
    window = [t for t in _rate_window[key] if now - t < 60]
    _rate_window[key] = window
    if len(window) >= _MAX_ENTITIES_PER_MINUTE:
        return False
    return True

def _record_rate(key: str, count: int):
    now = time.time()
    _rate_window[key].extend([now] * count)

async def api_key_middleware(request: Request, call_next):
    """Require API key for write endpoints. Read endpoints are open.

    If MCP_API_KEY is not set and not in dev mode, writes are blocked
    with a clear error message rather than silently allowing everything.
    """
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        key = request.headers.get("X-API-Key", "")
        if not MCP_API_KEY:
            # No key configured — block writes unless dev mode
            if MCP_DEV_MODE:
                return await call_next(request)
            return JSONResponse(
                {"error": "server_unconfigured",
                 "detail": "MCP_API_KEY not set on server. Set it to enable write operations."},
                status_code=503,
            )
        if key != MCP_API_KEY:
            return JSONResponse(
                {"error": "unauthorized",
                 "detail": "Valid X-API-Key required for write operations"},
                status_code=401,
            )
    return await call_next(request)

# ── MCP Protocol Types ─────────────────────────────────────────

class MCPTool(BaseModel):
    name: str
    description: str
    inputSchema: dict = {}


class MCPListToolsResponse(BaseModel):
    tools: list[MCPTool]


class MCPCallToolRequest(BaseModel):
    name: str
    arguments: dict = {}


class MCPCallToolResponse(BaseModel):
    content: list[dict]


# ── App ─────────────────────────────────────────────────────────

mcp = FastAPI(
    title="Watson MCP Server",
    description="Community OSINT investigation knowledge graph",
    version="0.1.0",
)

mcp.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# API key auth — read open, write gated
mcp.middleware("http")(api_key_middleware)

graph = KnowledgeGraph()


# ── MCP Discovery ───────────────────────────────────────────────

@mcp.get("/")
async def root():
    """MCP server info."""
    return {
        "name": "Watson MCP Server",
        "version": "0.1.0",
        "description": "Community OSINT investigation knowledge graph",
        "protocol": "mcp",
        "stats": graph.stats(),
    }


@mcp.get("/.well-known/mcp", response_model=MCPListToolsResponse)
async def list_tools():
    """MCP tool discovery."""
    return MCPListToolsResponse(tools=[
        MCPTool(
            name="watson_search",
            description="Search the Watson community knowledge graph for entities, cases, and relations",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search term"},
                    "limit": {"type": "integer", "default": 20},
                },
                "required": ["query"],
            },
        ),
        MCPTool(
            name="watson_traverse",
            description="Explore connections from an entity in the knowledge graph",
            inputSchema={
                "type": "object",
                "properties": {
                    "entity_value": {"type": "string", "description": "Entity to traverse from"},
                    "entity_type": {"type": "string", "description": "person, domain, company, email, etc."},
                },
                "required": ["entity_value"],
            },
        ),
        MCPTool(
            name="watson_case",
            description="Retrieve a published investigation case",
            inputSchema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "Case ID (e.g., CASE-ABC12345)"},
                },
                "required": ["case_id"],
            },
        ),
        MCPTool(
            name="watson_stats",
            description="Get statistics about the community knowledge graph",
            inputSchema={"type": "object", "properties": {}},
        ),
        MCPTool(
            name="watson_context",
            description="Check if an investigation target has prior findings in the graph",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Investigation target"},
                },
                "required": ["query"],
            },
        ),
    ])


# ── MCP Tool Calls ──────────────────────────────────────────────

@mcp.post("/mcp/call-tool", response_model=MCPCallToolResponse)
async def call_tool(request: MCPCallToolRequest):
    """Handle MCP tool calls."""
    args = request.arguments

    try:
        if request.name == "watson_search":
            entities = graph.search_entities(
                args.get("query", ""),
                limit=args.get("limit", 20),
            )
            return MCPCallToolResponse(content=[{
                "type": "text",
                "text": json.dumps({
                    "query": args.get("query"),
                    "results": [e.to_dict() for e in entities],
                    "count": len(entities),
                }, indent=2),
            }])

        elif request.name == "watson_traverse":
            result = graph.traverse(
                entity_value=args["entity_value"],
                entity_type=args.get("entity_type"),
            )
            return MCPCallToolResponse(content=[{
                "type": "text",
                "text": json.dumps(result, indent=2),
            }])

        elif request.name == "watson_case":
            from pathlib import Path
            cases_dir = Path.home() / "watson-cases"
            case_path = cases_dir / f"{args['case_id']}.md"
            if case_path.exists():
                content = case_path.read_text()
                return MCPCallToolResponse(content=[{
                    "type": "text",
                    "text": content,
                }])
            else:
                return MCPCallToolResponse(content=[{
                    "type": "text",
                    "text": json.dumps({"error": "Case not found", "case_id": args["case_id"]}),
                }])

        elif request.name == "watson_stats":
            stats = graph.stats()
            return MCPCallToolResponse(content=[{
                "type": "text",
                "text": json.dumps(stats, indent=2),
            }])

        elif request.name == "watson_context":
            context = graph.context_for_investigation(args["query"])
            return MCPCallToolResponse(content=[{
                "type": "text",
                "text": json.dumps(context, indent=2),
            }])

        else:
            raise HTTPException(404, f"Unknown tool: {request.name}")

    except Exception as e:
        return MCPCallToolResponse(content=[{
            "type": "text",
            "text": json.dumps({"error": str(e)}),
        }])


# ── REST API (for non-MCP clients) ──────────────────────────────

@mcp.get("/api/search")
async def api_search(q: str = Query(...), limit: int = 20):
    """Search the community graph via REST."""
    entities = graph.search_entities(q, limit=limit)
    return {
        "query": q,
        "results": [e.to_dict() for e in entities],
        "count": len(entities),
    }


@mcp.get("/api/traverse/{entity_value:path}")
async def api_traverse(entity_value: str, entity_type: Optional[str] = None):
    """Traverse graph via REST."""
    result = graph.traverse(entity_value, entity_type=entity_type)
    return result


@mcp.get("/api/stats")
async def api_stats():
    """Graph stats via REST."""
    return graph.stats()


@mcp.get("/api/cases")
async def api_cases():
    """List published cases."""
    from pathlib import Path
    cases_dir = Path.home() / "watson-cases"
    cases = []
    for f in sorted(cases_dir.glob("CASE-*.md"), reverse=True):
        cases.append({
            "id": f.stem,
            "size": f.stat().st_size,
        })
    return {"cases": cases, "count": len(cases)}


@mcp.get("/api/cases/{case_id}")
async def api_case(case_id: str):
    """Get a published case."""
    from pathlib import Path
    case_path = Path.home() / "watson-cases" / f"{case_id}.md"
    if case_path.exists():
        return PlainTextResponse(case_path.read_text(), media_type="text/markdown")
    raise HTTPException(404, "Case not found")


# ── Publishing / Ingest ─────────────────────────────────────────

# Valid entity types that can be ingested
_VALID_ENTITY_TYPES = {
    "person", "organization", "company", "domain", "email",
    "ip", "ipv4", "ipv6", "wallet", "crypto_address", "phone",
    "url", "hash", "md5", "sha256", "cve", "asn", "location",
}

# Max lengths
_MAX_VALUE_LEN = 500
_MAX_SOURCE_LEN = 200

# Garbage patterns — values that are obviously not real entities
_GARBAGE_PATTERNS = [
    re.compile(r"^test\d*$", re.I),
    re.compile(r"^asdf+$", re.I),
    re.compile(r"^foo(bar)?$", re.I),
    re.compile(r"^hello\d*$", re.I),
    re.compile(r"^n/?a$", re.I),
    re.compile(r"^unknown$", re.I),
    re.compile(r"^none$", re.I),
    re.compile(r"^example", re.I),
    re.compile(r"^placeholder", re.I),
    re.compile(r"^sample", re.I),
    re.compile(r"^lorem", re.I),
    re.compile(r"^(.)\1{10,}$"),  # Same char 10+ times
]

# Type-specific validation regexes
_TYPE_VALIDATORS: dict[str, re.Pattern] = {
    "email": re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
    "domain": re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I),
    "ip": re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
    "ipv4": re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
    "ipv6": re.compile(r"^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$", re.I),
    "url": re.compile(r"^https?://", re.I),
    "wallet": re.compile(r"^(0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})$"),
    "crypto_address": re.compile(r"^(0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})$"),
    "md5": re.compile(r"^[a-f0-9]{32}$", re.I),
    "sha256": re.compile(r"^[a-f0-9]{64}$", re.I),
    "cve": re.compile(r"^CVE-\d{4}-\d{4,}$", re.I),
}


def _validate_entity(entity: dict) -> str | None:
    """Validate a single entity dict. Returns error string or None if valid.

    Does NOT trust the caller — every field is checked.
    """
    value = str(entity.get("value", "")).strip()
    type_ = str(entity.get("type", "")).strip().lower()
    tier = str(entity.get("tier", "PROBABLE")).strip().upper()

    # ── Value checks ──────────────────────────────
    if not value:
        return "entity.value is empty"
    if len(value) > _MAX_VALUE_LEN:
        return f"entity.value too long ({len(value)} > {_MAX_VALUE_LEN})"
    if value != entity.get("value", ""):
        return "entity.value has leading/trailing whitespace"

    # ── Garbage detection ─────────────────────────
    for pat in _GARBAGE_PATTERNS:
        if pat.match(value):
            return f"entity.value looks like garbage: '{value}'"

    # ── Type checks ───────────────────────────────
    if not type_:
        return "entity.type is empty"
    if type_ not in _VALID_ENTITY_TYPES:
        return f"entity.type not recognized: '{type_}'. Valid: {sorted(_VALID_ENTITY_TYPES)}"

    # ── Type-specific format validation ─────────────
    validator = _TYPE_VALIDATORS.get(type_)
    if validator and not validator.match(value):
        return f"entity.value '{value}' doesn't match expected format for type '{type_}'"

    # ── Tier checks ────────────────────────────────
    if tier not in ("CONFIRMED", "PROBABLE", "POSSIBLE", "UNVERIFIED"):
        return f"entity.tier not valid: '{tier}'"

    # ── Source length ──────────────────────────────
    source = str(entity.get("source", ""))
    if len(source) > _MAX_SOURCE_LEN:
        return f"entity.source too long ({len(source)} > {_MAX_SOURCE_LEN})"

    return None


class IngestEntity(BaseModel):
    value: str
    type: str
    source: str = ""
    tier: str = "PROBABLE"
    case_id: str = ""

    @field_validator("value")
    @classmethod
    def value_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("value cannot be empty")
        if len(v.strip()) > _MAX_VALUE_LEN:
            raise ValueError(f"value too long ({len(v.strip())} > {_MAX_VALUE_LEN})")
        return v.strip()

    @field_validator("type")
    @classmethod
    def type_valid(cls, v: str) -> str:
        v = v.strip().lower()
        if not v:
            raise ValueError("type cannot be empty")
        if v not in _VALID_ENTITY_TYPES:
            raise ValueError(f"type '{v}' not recognized. Valid: {sorted(_VALID_ENTITY_TYPES)}")
        return v

    @field_validator("tier")
    @classmethod
    def tier_valid(cls, v: str) -> str:
        v = v.strip().upper()
        if v not in ("CONFIRMED", "PROBABLE", "POSSIBLE", "UNVERIFIED"):
            raise ValueError(f"tier '{v}' not valid")
        return v


class IngestPayload(BaseModel):
    case_id: str
    target: str
    target_type: str = ""
    findings_count: int = 0
    confirmed_count: int = 0
    verifiability: str = ""
    date: str = ""
    entities: list[IngestEntity] = []
    markdown: str = ""

    @field_validator("entities")
    @classmethod
    def entities_not_too_many(cls, v: list) -> list:
        if len(v) > _MAX_ENTITIES_PER_REQUEST:
            raise ValueError(f"too many entities ({len(v)} > {_MAX_ENTITIES_PER_REQUEST}) — split into multiple requests")
        return v


# Track which cases have been published — persisted to JSONL
PUBLISHED_PATH = Path.home() / ".watson" / "graph" / "published.jsonl"
PUBLISHED_PATH.parent.mkdir(parents=True, exist_ok=True)

_published_cases: dict[str, dict] = {}

def _load_published():
    """Load published cases from disk."""
    global _published_cases
    if PUBLISHED_PATH.exists():
        try:
            for line in PUBLISHED_PATH.read_text().splitlines():
                if line.strip():
                    d = json.loads(line)
                    _published_cases[d["case_id"]] = d
        except Exception:
            pass

def _save_published():
    """Persist published cases to disk."""
    try:
        lines = [json.dumps(c) + "\n" for c in _published_cases.values()]
        PUBLISHED_PATH.write_text("".join(lines))
    except Exception:
        pass

# Load on startup
_load_published()


@mcp.post("/api/ingest")
async def api_ingest(payload: IngestPayload, request: Request):
    """Ingest a published case into the community knowledge graph.

    Two-layer validation: Pydantic catches schema errors; _validate_entity()
    catches semantic garbage (test data, malformed values, wrong types).
    Rate-limited per API key.
    """
    key = request.headers.get("X-API-Key", "anonymous")

    # ── Rate limit check ─────────────────────────
    if not _check_rate_limit(key):
        raise HTTPException(429, "Rate limit exceeded — max 2000 entities/minute per key")

    # ── Double-layer entity validation (belt + suspenders) ──
    rejected: list[dict] = []
    valid_entities: list[IngestEntity] = []

    for ent in payload.entities:
        # Pydantic already validated the model, but convert back to dict
        # for _validate_entity's semantic checks (garbage patterns, format)
        err = _validate_entity(ent.model_dump())
        if err:
            rejected.append({"value": ent.value, "type": ent.type, "reason": err})
        else:
            valid_entities.append(ent)

    # ── Ingest valid entities ─────────────────────
    ingested = 0
    for ent in valid_entities:
        if ent.tier not in ("CONFIRMED", "PROBABLE"):
            continue
        graph.upsert_entity(
            type_=ent.type,
            value=ent.value,
            case_id=payload.case_id,
            label=ent.value[:200],
        )
        ingested += 1

    # Track rate
    _record_rate(key, ingested)

    # Track published case metadata
    _published_cases[payload.case_id] = {
        "case_id": payload.case_id,
        "target": payload.target,
        "target_type": payload.target_type,
        "findings_count": payload.findings_count,
        "confirmed_count": payload.confirmed_count,
        "verifiability": payload.verifiability,
        "date": payload.date,
        "ingested_entities": ingested,
        "rejected_entities": len(rejected),
    }
    _save_published()

    return {
        "status": "ingested",
        "case_id": payload.case_id,
        "entities_ingested": ingested,
        "entities_rejected": len(rejected),
        "rejected": rejected[:10],  # First 10 only — don't flood response
        "graph_stats": graph.stats(),
    }


@mcp.get("/api/published")
async def api_published():
    """List all published cases in the community graph."""
    return {
        "cases": list(_published_cases.values()),
        "count": len(_published_cases),
    }
