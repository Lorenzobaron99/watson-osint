# 🕵️ Watson — OSINT Investigation Engine

**Multi-source. Graph-native. Model-agnostic. Agent-agnostic.**

Watson runs 7-phase OSINT investigations across 16 APIs, cross-references findings, and builds a persistent knowledge graph that grows smarter with every case. Inspired by investigative methodology, built for practitioners who want tools, not hype.

[Architecture →](WATSON_ARCHITECTURE.md) · [Self-hosting MCP →](SELF_HOSTING.md) · [Landing page →](https://lorenzobaron99.github.io/watson)

---

## Why Watson

General agents answer your question and forget it. Watson investigates, correlates, and remembers.

|  | ChatGPT / Claude | Watson |
|---|---|---|
| State | Stateless | Persistent graph |
| Memory | None across sessions | Every case feeds the graph |
| Cross-case | Impossible | Case #47 surfaces connections from Case #12 |
| Community | N/A | MCP server — collective intelligence |
| Sources | Sometimes | Every finding has source URL + confidence tier |

---

## Quick Start

```bash
git clone https://github.com/Lorenzobaron99/watson-osint.git
cd watson-osint
pip install -r requirements.txt

# Terminal — onboarding wizard
python -m watson.cli onboard

# Web UI
PYTHONPATH=.:src uvicorn watson.web.app:app --port 8777
```

Zero-cost mode works immediately — no API keys required. Watson uses DuckDuckGo and 10+ free APIs out of the box.

---

## Architecture

### 7-Phase Investigation Pipeline

```
investigate "target"
        │
        ▼
┌──────────────────────────────────────────────┐
│ Phase 1: Classify                            │
│   Target type → investigation strategy       │
│   Person, company, domain, email, IP, wallet │
│   Checks knowledge graph for prior findings  │
└──────────────────┬───────────────────────────┘
                   ▼
┌──────────────────────────────────────────────┐
│ Phase 2: Surface                             │
│   crt.sh, Wayback, URLscan, DDG, Wikipedia   │
│   Domain WHOIS, DNS, SSL certificates        │
│   Social media presence, news mentions       │
└──────────────────┬───────────────────────────┘
                   ▼
┌──────────────────────────────────────────────┐
│ Phase 3: Pivot                               │
│   Identifier chaining: email→accounts        │
│   Username→profiles across 300+ platforms    │
│   Breach data (HIBP), password exposure      │
└──────────────────┬───────────────────────────┘
                   ▼
┌──────────────────────────────────────────────┐
│ Phase 4: Deep                                │
│   OpenSanctions, OpenCorporates, Wikidata    │
│   ICIJ Offshore Leaks, OCCRP Aleph           │
│   SEC EDGAR filings, corporate registries    │
│   VirusTotal domain reputation               │
└──────────────────┬───────────────────────────┘
                   ▼
┌──────────────────────────────────────────────┐
│ Phase 5: Dark (escalated)                    │
│   Dark web indicators, ransomware checks     │
│   Triggered by criminal/financial keywords   │
│   Skipped for most investigations            │
└──────────────────┬───────────────────────────┘
                   ▼
┌──────────────────────────────────────────────┐
│ Phase 6: Analyze                             │
│   Cross-reference across all phases          │
│   Entity resolution — deduplicate identities │
│   Source tiering: PRIMARY → UNVERIFIED       │
│   LLM synthesis → structured brief           │
└──────────────────┬───────────────────────────┘
                   ▼
┌──────────────────────────────────────────────┐
│ Phase 7: Report                              │
│   CASE-XXXX.md saved to ~/watson-cases/      │
│   Entities indexed in knowledge graph        │
│   Verifiability score, evidence gaps flagged │
│   Opt-in: publish to community graph (MCP)   │
└──────────────────────────────────────────────┘
```

### Investigation Modes

| Mode | Duration | Phases | Use Case |
|---|---|---|---|
| `background_check` | 30–60s | Classify + Surface | Quick identity/domain check |
| `due_diligence` | 2–5 min | + Pivot + Deep | Business verification, adverse media |
| `deep_investigation` | 5–15 min | All 7 phases | Full dossier, criminal/legal, dark web |
| `twin_connection` | 3–8 min | Dedicated pipeline | Find connections between two targets |

---

## Model & Agent Agnostic

Watson doesn't lock you into any AI stack.

### Models (any OpenAI-compatible API)

```bash
export WATSON_API_KEY=sk-...           # Any provider
export WATSON_API_BASE=https://...     # OpenAI, Anthropic, DeepSeek, Groq, etc.
export WATSON_MODEL=claude-sonnet-4    # or gpt-4o, deepseek-v3, gemini, command-r
```

### Agents (pluggable runtime backends)

| Agent | Setup | Capabilities |
|---|---|---|
| **Direct** | API key only | DuckDuckGo search + any LLM. Zero dependencies. |
| **Hermes** | Local install | Full toolset: web search, browser, vision, terminal, MCP tools |
| **OpenClaw** | Local install | Full toolset via OpenClaw CLI |
| **Custom** | Implement adapter | Add any agent runtime — the interface is 4 methods |

Set via `WATSON_AGENT` env var or during `watson onboard`. Adapters implement a simple protocol — adding a new agent backend is ~80 lines of code.

---

## API Integrations

### Free (no keys required)

crt.sh, URLscan.io, Wayback Machine, DuckDuckGo, Wikipedia, Wikidata, ICIJ Offshore Leaks, OCCRP Aleph, BuiltWith, Instant Username Search, OpenSky Network, FlightAware, WhatsApp social graph

### Paid (optional, individually configurable)

| Service | Use | Approx. Cost |
|---|---|---|
| **OpenSanctions** | Sanctions, PEP, entities | $0–50/mo |
| **OpenCorporates** | Company registries | ~$50/mo |
| **VirusTotal** | Domain/IP reputation | $0–50/mo |
| **HIBP** | Breach/credential data | $4/mo |

All paid APIs are optional. Watson is fully functional on the free tier.

---

## Community Knowledge Graph (MCP)

Watson ships with an MCP server that turns your investigations into a queryable intelligence graph.

```
watson_search     → Search entities across all published cases
watson_traverse   → Explore connections from any entity
watson_context    → Check prior findings before investigating
watson_case       → Retrieve full investigation reports
watson_stats      → Graph statistics
```

### Running locally

```bash
# Auto-started when you run `watson web`
# Or manually:
uvicorn watson.mcp_server:mcp --port 8700
```

The graph persists in `~/watson-graph/`. Per-case consent: nothing is shared without explicit opt-in per investigation.

### Connecting a community instance

```bash
export WATSON_MCP_URL=https://watson-graph.example.com
export MCP_API_KEY=your-key
```

[Self-hosting guide →](SELF_HOSTING.md)

---

## Project Structure

```
watson-osint/
├── watson/                    # Web app + tools
│   ├── web/app.py             # FastAPI application (:8777)
│   ├── agents/                # Pluggable agent adapters
│   │   ├── base.py            # Abstract interface
│   │   ├── direct.py          # OpenAI-compatible + DuckDuckGo
│   │   └── hermes.py          # Hermes agent adapter
│   ├── graph.py               # Knowledge graph engine
│   ├── mcp_server.py          # MCP community graph (:8700)
│   ├── cli.py                 # Terminal interface
│   ├── toolkit.py              # 16 direct API integrations
│   └── memory.py              # Investigation persistence
├── src/watson/                # Core engine
│   ├── orchestration/
│   │   ├── engine.py          # 7-phase investigation engine
│   │   ├── synthesis.py       # LLM report generation
│   │   ├── resolution.py      # Entity resolution
│   │   └── target_profile.py  # Target classification
│   ├── tools/                 # Specialized tools
│   │   ├── blockchain.py, corporate.py, people.py
│   │   ├── social_media.py, websites.py, wikidata.py
│   │   └── darkweb.py, satellite.py, geolocation.py
│   └── core/models.py         # Data models
├── frontend/                  # React UI (Vite + Tailwind)
│   └── src/components/        # WatsonChat, Sidebar, CaseBoard, etc.
├── tests/                     # 117 tests
├── deploy.sh                  # One-command production deploy
├── SELF_HOSTING.md            # MCP self-hosting guide
├── WATSON_ARCHITECTURE.md     # Full architecture deep-dive
├── LICENSE                    # AGPLv3
└── requirements.txt
```

---

## License

**GNU Affero General Public License v3.0** — free forever for any use. If you deploy a modified Watson as a network service, you must release your changes. Premium features and commercial licensing available from the copyright holder.

[Full license →](LICENSE)
