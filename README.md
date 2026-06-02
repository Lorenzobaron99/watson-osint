# 🕵️ Watson — OSINT Investigation Engine

**Bellingcat-inspired. Graph-native. Agent-agnostic. LLM-agnostic.**

Watson runs multi-angle parallel OSINT investigations, cross-references findings, and builds a persistent knowledge graph that grows smarter with every case. Think Sherlock, Maigret, and Holehe — but graph-connected.

[Read the architecture →](WATSON_ARCHITECTURE.md)

## Why Watson

General agents answer your question and forget it. Watson investigates, correlates, and remembers.

|  | ChatGPT / Claude | Watson |
|---|---|---|
| State | Stateless | Persistent graph |
| Memory | None across sessions | Every case feeds the graph |
| Cross-case | Impossible | Case #47 surfaces Case #12 |
| Community | N/A | MCP server for collective intel |
| Sources | Sometimes | Every finding has source + confidence |

## Quick Start

```bash
git clone https://github.com/Lorenzobaron99/watson-osint.git
cd watson-osint
pip install -r requirements.txt

# Pick your backend:
#   Hermes (full toolset: web, browser, vision, terminal)
#   export WATSON_AGENT=hermes
#
#   Any OpenAI-compatible API (zero-setup)
#   export WATSON_AGENT=direct
#   export WATSON_API_KEY=sk-...
#   export WATSON_API_BASE=https://api.openai.com/v1   # or any provider
#   export WATSON_MODEL=gpt-4o                          # or claude, gemini, etc.

# Terminal interface
python -m watson.cli

# Web interface
uvicorn watson.web.app:app --port 8000
```

## How It Works

```
investigate "shadowy-company.com"
        │
        ▼
┌──────────────────────────────┐
│ Phase 1: Classify & Plan      │  Target type → investigation angles
│   Domain → WHOIS, DNS, SSL,   │  Checks knowledge graph for
│   Corporate, Historical, News │  connections from past cases
└──────────┬───────────────────┘
           ▼
┌──────────────────────────────┐
│ Phase 2: Parallel Dispatch    │  4-6 angles run simultaneously
│   → crt.sh → 14 subdomains   │  Results stream in real-time
│   → OpenCorporates → LLC     │  via configured adapter
│   → Wayback → 2018 owner     │
│   → DuckDuckGo → 3 articles  │
└──────────┬───────────────────┘
           ▼
┌──────────────────────────────┐
│ Phase 3: Cross-Reference      │  Finds connections across sources
│   "John Doe" in 2 sources →   │  Links to prior cases in graph
│   Sanctions link confirmed    │  Confidence-scored
└──────────┬───────────────────┘
           ▼
┌──────────────────────────────┐
│ Output: Structured Briefing   │  Case saved as CASE-XXXX.md
│   + Knowledge Graph update    │  Entities indexed for future
│   + Follow-up questions       │  cross-case intelligence
└──────────────────────────────┘
```

## Backends

Watson is agent-agnostic and LLM-agnostic. Pick what works:

| Adapter | Setup | Capabilities |
|---|---|---|
| **Hermes** | Local install | Web search, browser, vision, terminal, MCP tools |
| **Direct** | API key only | DuckDuckGo search + any OpenAI-compatible LLM |
| **OpenClaw** | Coming soon | Full toolset |

Set via `WATSON_AGENT` env var.

## OSINT Toolkit Integrations

Watson integrates with the open-source OSINT ecosystem:

- **[Sherlock](https://github.com/sherlock-project/sherlock)** — username enumeration across 300+ platforms
- **[Maigret](https://github.com/soxoj/maigret)** — deep username OSINT
- **[Holehe](https://github.com/megadose/holehe)** — email → registered accounts
- **[GHunt](https://github.com/mxrch/GHunt)** — Google account investigation
- **[Blackbird](https://github.com/p1ngul1n0/blackbird)** — multi-platform username search

Install any of these alongside Watson and they become available as investigation angles. The Bellingcat toolkit registry maps 338 tools to target types.

## MCP Server — Community Knowledge Graph

```bash
uvicorn watson.mcp_server:mcp --port 8001
```

Exposes the investigation graph via Model Context Protocol:

- `watson_search` — search entities, cases, relations
- `watson_traverse` — explore connections from any entity
- `watson_case` — retrieve a published investigation
- `watson_stats` — graph statistics
- `watson_context` — check prior findings before investigating

Every public case writes to this graph. Future investigations auto-surface connections.

## Project Structure

```
watson-osint/
├── watson/
│   ├── agents/          # Pluggable backends
│   │   ├── base.py      # Abstract interface
│   │   ├── hermes.py    # Hermes (CLI subprocess)
│   │   └── direct.py    # OpenAI-compatible + DuckDuckGo
│   ├── engine.py        # Multi-angle investigation engine
│   ├── graph.py         # Persistent knowledge graph
│   ├── mcp_server.py    # Community MCP endpoint
│   ├── cli.py           # Terminal interface
│   └── web/             # FastAPI + chat UI
│       ├── app.py
│       └── templates/
├── requirements.txt
└── LICENSE
```

## Configuration

```bash
# Agent backend
WATSON_AGENT=hermes|direct

# Direct adapter (any OpenAI-compatible API)
WATSON_API_KEY=sk-...
WATSON_API_BASE=https://api.openai.com/v1
WATSON_MODEL=gpt-4o

# GitHub OAuth (optional — for web login)
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...

# MCP community graph
MCP_PORT=8001
```

## License

GNU Affero General Public License v3.0 — if you run Watson as a network service, you must release your modifications.
