# Watson Architecture

## Vision

The most powerful OSINT investigator on the web. Not a chatbot that answers questions — an investigation engine that builds a persistent, cross-case knowledge graph no general agent can replicate.

## Why Watson Beats General Agents

| | ChatGPT / Claude / Perplexity | Watson |
|---|---|---|
| **State** | Stateless per query | Persistent investigation graph |
| **Architecture** | Query → Answer | Multi-angle dispatch → Cross-reference → Graph write |
| **Memory** | None across sessions | Every case feeds the graph |
| **Cross-case** | Impossible | Case #47 surfaces findings from Case #12 |
| **Community** | N/A | MCP server exposes collective intelligence |
| **Citations** | Sometimes | Every finding has source, confidence, and timestamp |

**The moat is the graph.** General agents answer your question and forget it. Watson gets smarter every investigation.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     WATSON PRODUCT                        │
│                                                          │
│  ┌──────────┐  ┌────────────┐  ┌─────────────────────┐  │
│  │   CLI    │  │  Web Chat  │  │   MCP Server        │  │
│  │ terminal  │  │ htmx + SSE │  │ community knowledge │  │
│  │ interface │  │ chat UI    │  │ graph endpoint      │  │
│  └────┬─────┘  └─────┬──────┘  └──────────┬──────────┘  │
│       │              │                     │             │
│       └──────────────┼─────────────────────┘             │
│                      │                                   │
│              ┌───────▼────────┐                          │
│              │  Investigation  │                          │
│              │    Engine       │  ← Watson IP             │
│              │  • methodology  │                          │
│              │  • dispatch     │                          │
│              │  • cross-ref    │                          │
│              │  • report       │                          │
│              └───────┬─────────┘                          │
│                      │                                   │
│              ┌───────▼────────┐                          │
│              │  Agent Adapter  │  ← pluggable             │
│              │  • Hermes       │                          │
│              │  • OpenClaw     │                          │
│              │  • OpenHuman    │                          │
│              │  • Direct LLM   │                          │
│              └───────┬─────────┘                          │
│                      │                                   │
│              ┌───────▼────────┐                          │
│              │  Knowledge      │                          │
│              │   Graph         │  ← the moat              │
│              │  nodes: entity  │                          │
│              │  edges: relation │                         │
│              │  case provenance │                         │
│              └─────────────────┘                          │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

## Watson vs. Agent Engines

Watson is **agent agnostic**. The investigation methodology, knowledge graph, case system, and MCP server are Watson's IP. The agent layer underneath is pluggable — today Hermes, tomorrow OpenClaw, or a direct LLM call.

| Layer | Owned by | What it does |
|---|---|---|
| Methodology | **Watson** | Bellingcat-style multi-angle investigation |
| Dispatch | **Watson** | Parallel tool dispatch across source categories |
| Knowledge Graph | **Watson** | Persistent entity-relationship graph with case provenance |
| Case System | **Watson** | Structured .md reports with citations and confidence |
| MCP Server | **Watson** | Community knowledge graph endpoint |
| CLI / UI | **Watson** | Branded terminal and web interface |
| Agent Execution | **Adapter** | Translates Watson commands to agent-specific calls |

## Investigation Flow

```
User: "investigate shadowy-company.com"
  │
  ▼
┌─────────────────────────────────────────────┐
│ PHASE 1: Semantic Analysis (Watson engine)  │
│ • Target type: domain                       │
│ • Entities: shadowy-company.com             │
│ • Angles: WHOIS history, DNS infra,         │
│   corporate ties, news coverage             │
│ • Sources: crt.sh, OpenCorporates,          │
│   Wayback CDX, ICIJ Offshore Leaks          │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│ PHASE 2: Multi-Angle Dispatch (parallel)    │
│                                              │
│ Angle 1: Infrastructure                     │
│   → crt.sh API → 14 subdomains              │
│   → DNS lookup → MX: Google, NS: Cloudflare │
│                                              │
│ Angle 2: Corporate                          │
│   → OpenCorporates → "Shadowy LLC" (Delaware)│
│   → OpenSanctions → director: John Doe      │
│                                              │
│ Angle 3: Historical                         │
│   → Wayback CDX → 2018: different owner     │
│   → WHOIS history → real registrant found   │
│                                              │
│ Angle 4: News / Media                       │
│   → Web search → 3 articles about scandal   │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│ PHASE 3: Cross-Reference                    │
│ • "John Doe" appears in Corporate + News    │
│ • crt.sh domains include leaked-sanctions.  │
│   shadowy-company.com → HIGH confidence     │
│ • 2018 registrant ≠ current owner → flag   │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│ PHASE 4: Report                             │
│ • Structured .md with citations             │
│ • Confidence scores per finding             │
│ • Cross-references highlighted              │
│ • Follow-up questions generated             │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│ PHASE 5: Knowledge Graph Write              │
│ • Entities: shadowy-company.com,            │
│   Shadowy LLC, John Doe, Cloudflare         │
│ • Relations: registered_by, director_of,    │
│   hosted_on, mentioned_in                   │
│ • Provenance: Case #47, sources attached    │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│ PHASE 6: MCP Publish (free tier)            │
│ • md → sha → public graph endpoint          │
│ • Community contributors can query          │
│ • Future Case #89 about John Doe auto-links │
└─────────────────────────────────────────────┘
```

## Knowledge Graph — The Moat

```
┌──────────┐  director_of   ┌──────────────┐
│ John Doe ├───────────────►│ Shadowy LLC   │
└────┬─────┘                └──────┬────────┘
     │                            │
     │ uses_email                 │ registered
     │                            │
     ▼                            ▼
┌──────────────┐         ┌────────────────────┐
│ jd@proton.me │         │ shadowy-company.com│
└──────┬───────┘         └────────┬───────────┘
       │                          │
       │ appears_in               │ hosted_on
       │                          │
       ▼                          ▼
┌──────────────┐         ┌──────────────┐
│ Leaked DB    │         │  Cloudflare   │
│ (Case #12)   │         │  (Case #47)   │
└──────────────┘         └──────────────┘
```

Every edge carries:
- **provenance**: which case found it
- **source**: URL or tool that produced it
- **confidence**: 0.0 – 1.0
- **timestamp**: when it was discovered

When Case #89 investigates John Doe, the graph auto-surfaces:
- "John Doe is director of Shadowy LLC (Case #47, 0.85 confidence)"
- "jd@proton.me appeared in leaked DB (Case #12, 0.90 confidence)"
- "Connected to shadowy-company.com (Case #47)"

This is the capability no general agent has. It's a collective investigation memory that grows with every case.

## MCP Server — Community Intelligence

The MCP (Model Context Protocol) server exposes the public knowledge graph:

- **search** — find entities, cases, relations
- **traverse** — explore connections from an entity (1-hop, 2-hop)
- **case** — retrieve full case by ID
- **stats** — graph statistics (entity count, case count, top entities)

Free tier cases auto-publish. Premium cases are private. The community graph is what makes Watson a network effect product — every public investigation makes everyone's investigations better.

## CLI Onboarding

```
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   ██╗    ██╗ █████╗ ████████╗███████╗ ██████╗ ███╗   ██╗ ║
║   ██║    ██║██╔══██╗╚══██╔══╝██╔════╝██╔═══██╗████╗  ██║ ║
║   ██║ █╗ ██║███████║   ██║   ███████╗██║   ██║██╔██╗ ██║ ║
║   ██║███╗██║██╔══██║   ██║   ╚════██║██║   ██║██║╚██╗██║ ║
║   ╚███╔███╔╝██║  ██║   ██║   ███████║╚██████╔╝██║ ╚████║ ║
║    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝ ║
║                                                          ║
║   The OSINT investigation engine. Bellingcat-inspired.    ║
║   Graph-native. Community-powered.                        ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝

Welcome to Watson. Let's set up your investigation environment.

→ Choose your agent engine:
  [1] Hermes (local, full toolset)
  [2] OpenClaw
  [3] OpenHuman
  [4] Direct LLM (API key required)

→ Your choice: _

→ Watson will save cases to: ~/watson-cases/
  Change? [y/N]: _

→ Community MCP: publish public cases? [Y/n]: _

✓ Watson is ready. Type /investigate <target> to begin.
  Or just describe what you want to investigate.
```

## Agent Adapter Interface

```python
class AgentAdapter(ABC):
    """Pluggable agent backend for Watson."""
    
    name: str           # "hermes", "openclaw", "direct"
    
    async def search(self, query: str, sources: list[str] = None) -> list[SearchResult]: ...
    async def browse(self, url: str, extract: str = None) -> BrowseResult: ...
    async def vision(self, image: bytes | str, question: str) -> VisionResult: ...
    async def terminal(self, command: str) -> TerminalResult: ...
    async def investigate(self, query: str, angles: list[str]) -> InvestigationResult: ...
```

Watson's engine calls these abstract methods. Each adapter implements them for its specific agent. Watson's methodology, dispatch logic, graph, and reporting are completely independent of the agent layer.

## Project Structure

```
watson-osint/
├── WATSON_ARCHITECTURE.md      ← this file
├── README.md                   ← GitHub landing
│
├── watson/                     ← Watson product code
│   ├── __init__.py
│   ├── cli.py                  ← terminal interface
│   ├── engine.py               ← investigation engine
│   ├── graph.py                ← knowledge graph engine
│   ├── reporter.py             ← .md case generation
│   ├── mcp_server.py           ← MCP community endpoint
│   │
│   ├── agents/                 ← pluggable agent adapters
│   │   ├── __init__.py
│   │   ├── base.py             ← AgentAdapter ABC
│   │   ├── hermes.py           ← Hermes adapter
│   │   ├── openclaw.py         ← OpenClaw adapter
│   │   └── direct.py           ← Direct LLM adapter
│   │
│   ├── data/                   ← reference data
│   │   └── bellingcat_toolkit.csv
│   │
│   └── web/                    ← FastAPI product shell
│       ├── app.py
│       ├── auth.py
│       ├── templates/
│       │   └── chat.html
│       └── static/
│           └── watson.css
│
├── cases/                      ← published case .md files
├── requirements.txt
├── LICENSE
└── .env.example
```

## Agent Engine Comparison

| Feature | Hermes | OpenClaw | OpenHuman | Direct LLM |
|---|---|---|---|---|
| Web search | ✅ native | ✅ | ? | ❌ (need API) |
| Browser | ✅ Playwright | ✅ | ? | ❌ |
| Vision | ✅ | ✅ | ? | ✅ if GPT-4V |
| Terminal | ✅ | ✅ | ? | ❌ |
| MCP tools | ✅ native | ✅ | ? | ❌ |
| Skills | ✅ | ? | ? | ❌ |
| Setup | Local install | Local install | ? | API key only |
| Best for | Full power | Good alt | ? | Quick start |

**Default recommendation**: Hermes for full toolset, Direct LLM for zero-setup quick start.
