# 🕵️ Watson — OSINT Investigation Engine

**Bellingcat-inspired. Graph-native. Agent-agnostic.**

Watson is not a chatbot. It's an investigation engine that runs multi-angle parallel OSINT investigations, cross-references findings, and builds a persistent knowledge graph that grows smarter with every case.

[Read the full architecture →](WATSON_ARCHITECTURE.md)

## Why Watson

General agents answer your question and forget it. Watson investigates, correlates, and remembers.

| | ChatGPT / Claude | Watson |
|---|---|---|
| State | Stateless | Persistent graph |
| Memory | None across sessions | Every case feeds the graph |
| Cross-case | Impossible | Case #47 surfaces Case #12 |
| Community | N/A | MCP server for collective intel |
| Sources | Sometimes | Every finding has source + confidence |

**The moat is the graph.** Every investigation writes entities and relationships to a persistent knowledge graph. Future investigations auto-surface connections from past cases. No general agent has this.

## Quick Start

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/watson-osint.git
cd watson-osint

# Install
pip install -r requirements.txt

# Choose your agent engine:
#   Option A: Hermes (recommended — full toolset)
#     Install Hermes Agent: https://hermes-agent.nousresearch.com
#     Run: hermes api-server --port 8778
#
#   Option B: Direct LLM (quick start — API key only)
#     export WATSON_AGENT=direct
#     export DEEPSEEK_API_KEY=your_key

# Start Watson
python -m watson.cli
# or for web interface:
uvicorn watson.web.app:app --port 8000
```

## Architecture

```
investigate "shadowy-company.com"
        │
        ▼
┌──────────────────────────────┐
│ Phase 1: Semantic Analysis    │  Watson classifies target type,
│   Target: domain              │  identifies investigation angles,
│   Angles: WHOIS, DNS, SSL,    │  checks knowledge graph for
│   Corporate, Historical, News │  prior findings
└──────────┬───────────────────┘
           ▼
┌──────────────────────────────┐
│ Phase 2: Parallel Dispatch    │  4-6 angles run simultaneously
│   → crt.sh → 14 subdomains   │  via configured agent adapter
│   → OpenCorporates → LLC     │  (Hermes, OpenClaw, Direct)
│   → Wayback → 2018 owner     │
│   → News → 3 articles        │
└──────────┬───────────────────┘
           ▼
┌──────────────────────────────┐
│ Phase 3: Cross-Reference      │  Finds connections between
│   "John Doe" in 2 sources     │  sources. Links to prior
│   Sanctions link confirmed    │  cases in the knowledge graph
└──────────┬───────────────────┘
           ▼
┌──────────────────────────────┐
│ Output: Structured Briefing   │  Case saved as CASE-XXXX.md
│   + Knowledge Graph update    │  Free tier: published to MCP
│   + Follow-up questions       │  Premium: private
└──────────────────────────────┘
```

## Agent Agnostic

Watson works with any agent engine:

| Adapter | Setup | Toolset |
|---|---|---|
| **Hermes** | Local install | Web search, browser, vision, terminal, MCP |
| **Direct LLM** | API key only | Web search (LLM-powered), basic reasoning |
| **OpenClaw** | Coming soon | Full toolset |
| **OpenHuman** | Coming soon | Full toolset |

Set via `WATSON_AGENT` env var or choose during CLI onboarding.

## Tiers

| | Free | Journalist ($50/mo) | Team ($200/mo) |
|---|---|---|---|
| Cases | Public | Private | Private |
| MCP publishing | ✅ | ❌ | ❌ |
| File upload | ❌ | ✅ | ✅ |
| Seats | 1 | 1 | 5 |
| API access | ❌ | ❌ | ✅ |

## MCP Server

The community knowledge graph is exposed via Model Context Protocol:

```bash
# Start MCP server
uvicorn watson.mcp_server:mcp --port 8001
```

**Available tools:**
- `watson_search` — search entities, cases, relations
- `watson_traverse` — explore connections from an entity
- `watson_case` — retrieve a published case
- `watson_stats` — graph statistics
- `watson_context` — check prior findings before investigating

## Project Structure

```
watson-osint/
├── watson/
│   ├── agents/          # Pluggable agent adapters
│   │   ├── base.py      # Abstract interface
│   │   ├── hermes.py    # Hermes adapter
│   │   └── direct.py    # Direct LLM adapter
│   ├── engine.py        # Investigation engine
│   ├── graph.py         # Knowledge graph
│   ├── mcp_server.py    # Community MCP endpoint
│   ├── cli.py           # Branded CLI
│   └── web/             # FastAPI shell + chat UI
│       ├── app.py
│       └── templates/
├── requirements.txt
└── LICENSE
```

## Roadmap

1. **Open-source foundation** (now) — self-hosted, public cases, community MCP
2. **Journalist SaaS** — hosted, private cases, file upload
3. **API tier** — usage-based for compliance platforms
4. **Enterprise on-prem** — government, SSO, SLA

## License

MIT
