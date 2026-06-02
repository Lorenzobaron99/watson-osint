"""
MCP Server — Community investigation knowledge graph endpoint.

Exposes Watson's knowledge graph via Model Context Protocol.
Free tier cases auto-publish. Premium cases are private.
The community graph creates a network effect — every public
investigation makes everyone's investigations better.
"""

from __future__ import annotations

import json
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from .graph import KnowledgeGraph

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
