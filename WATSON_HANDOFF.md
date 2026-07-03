# Watson OSINT — Handoff Context for Claude

## What Watson Is

An LLM-driven OSINT investigation agent. User types a query →
Watson investigates using real APIs → streams findings to a web UI.

Running at `http://localhost:8777`, server managed by `bash run_server.sh`.

Working directory: `/Users/lorenzobaron/Desktop/watson-osint`
Python: `.venv/bin/python` (venv at project root)
API keys: `~/.hermes/.env` (DEEPSEEK_API_KEY)

## Architecture v3 (Just Built — Reasoning Loop)

**The old decompose→fan-out pattern is dead.** It produced hallucinations
("Lorenzo99 CEO" from an email) and 0 confirmed findings.

**New pipeline:**
```
User query → IntentClassifier (LLM) → Reasoning Loop → Report
```

### Key Files

| File | Role |
|------|------|
| `src/watson/orchestration/intent.py` | **NEW** — LLM intent classifier. Fast-path for email/domain/crypto, LLM for everything else. Returns `{intent, entities, focus, ambiguous, clarifying_question}` |
| `src/watson/orchestration/engine.py` | **REWRITTEN** — Reasoning loop engine. Plan → execute → observe → repeat (max 8 iterations). Tool registry with 12 tools. Tools failing = visible findings. |
| `src/watson/orchestration/decomposer.py` | **DEPRECATED** — Old decompose prompt. Not used by new engine. Keep for backward compat. |
| `src/watson/agents/orchestrator.py` | **MODIFIED** — Added comma-context stripping to `normalize_query()` |
| `src/watson/agents/protocol.py` | Agent dataclasses (Finding, AgentRole, SourceClass, etc.) |
| `src/watson/agents/social.py` | SocialAgent — HIBP, username enumeration, social profile search |
| `src/watson/agents/corporate.py` | CorporateAgent — OpenCorporates, OpenSanctions, ICIJ |
| `src/watson/agents/dark.py` | DarkAgent — Psbdmp pastebin, HIBP domain breach, Tor |
| `src/watson/agents/recon.py` | ReconAgent — DNS (dig), WHOIS, crt.sh |
| `src/watson/agents/media.py` | MediaAgent — Image analysis (not used for web search) |
| `src/watson/topic_investigator.py` | Topic research (DuckDuckGo + browser reading). Used by old path. |
| `src/watson/browser_scraper.py` | Playwright browser for reading article URLs |
| `watson/web/app.py` | FastAPI server. Entry: `POST /api/agent/investigate` calls `engine.investigate()`. SSE streaming via `/api/agent/stream/<client_id>` |
| `watson/web/templates/investigation-map.html` | Main UI (Sidney Ledger theme). Also served at `/chat` |
| `tests/test_integration.py` | **REWRITTEN** — Engine tests now mock `_call_reasoning_llm` |

### Frontend Expectations (SSE Events)

The web UI handles these SSE events:
- `progress` — agent status messages
- `hypothesis` — LLM planning a step `{tool, target, rationale, iteration}`
- `finding` — a new Finding object
- `tool_result` — tool execution result
- `cross_reference` — patterns found across findings
- `investigation_complete` — investigation done
- `clarifying_question` — when intent is ambiguous
- `error` — agent errors

The new engine emits: `progress`, `hypothesis`, `finding`, `tool_result`, `cross_reference`, `investigation_complete`, `clarifying_question`.

## Code Review Findings (20 Issues)

Done just now. Here's the prioritized list:

### 🔴 Critical (Fix First)

1. **engine.py ~line 244 — Broken import** `from src.watson.ethics import get_ledger` → should be `from ..ethics import get_ledger` (relative import). This is a guaranteed production crash when the ledger feed runs.

2. **engine.py/intent.py/decomposer.py — Thread-unsafe singletons** — `get_engine()`, `get_classifier()`, `get_decomposer()` use `global _x; if _x is None: _x = X()` without locks. Compare with `persistence/store.py:237` which uses `threading.Lock()` correctly.

3. **engine.py ~line 694 — Inconsistent API key loading** — Three different key-loading implementations exist. Engine's `_call_reasoning_llm` only checks `DEEPSEEK_API_KEY` in `.env`, not `OPENAI_API_KEY`. If user sets only `OPENAI_API_KEY`, classifier works but reasoning loop silently fails.

### 🟠 High

4. **engine.py ~line 593 — SSRF risk in `_read_url`** — URL from LLM response is used directly in Playwright browser. No scheme validation. Could access `http://169.254.169.254/`, `file:///etc/passwd`, `http://localhost:6379/`.

5. **engine.py — Unvalidated URLs in markdown** — `source_url` from findings embedded directly in generated `.md` files. Could contain `javascript:` or `file:` URIs.

6. **engine.py ~line 718 — Hardcoded model** — `"model": "deepseek-chat"` in `_call_reasoning_llm`. Classifier and decomposer accept model param; engine doesn't.

7. **engine.py ~line 774 — Type mismatch in resume()** — `resume()` extends `all_findings` with raw dicts from JSON, not Finding objects.

### 🟡 Medium

8. **max_tokens=400** may truncate JSON from reasoning prompt (prompt can be 2000+ tokens with findings list)
9. **Tool validation gap** — `search_web` not always in `_tools_for_target()` but always available in prompt
10. **Comma-stripping** edge case with empty strings in split
11. **asyncio.to_thread on sync methods** — no assertion that methods are sync

### 🔵 Low

12-20. Copy-paste code (`_parse_json` x3, key-loading x3), dead deprecated methods, DDGS instantiated per call (no caching), local `import os` in method body.

## What Works (Verified End-to-End)

- `"baron.lorenzo99@gmail.com"` → 3 findings (username enumeration works, HIBP needs API key)
- `"Matteo Salvini, criminal records, convictions"` → 5 findings (web search + 4 real articles read)
- `"lorenzo baron"` → 3 findings (web searches with different angles)
- Intent classifier correctly identifies focus ("criminal records") vs generic person lookup
- All 80 tests pass

## What Still Needs Work

- **HIBP v3 requires API key** — `_hibp_fetch` returns None. Set `HIBP_API_KEY` in env.
- **No court records API** — For "criminal records" queries, we only have web search + OpenSanctions
- **Tool failure visibility** is implemented but untested with real failures (only email case tested)
- **The old decomposer.py** is still imported by some paths. Check if any callers remain.
- **The web app** at `watson/web/app.py` has TWO investigate endpoints:
  - `/api/investigate` → OLD Dispatcher (Bellingcat firehose, 96 tools)
  - `/api/agent/investigate` → NEW reasoning loop
  Frontend `doInvestigate()` calls the NEW one. Verify.

## Commands

```bash
# Start server
cd /Users/lorenzobaron/Desktop/watson-osint && bash run_server.sh

# Run tests
cd /Users/lorenzobaron/Desktop/watson-osint && .venv/bin/python -m pytest tests/ -q

# Test intent classifier
cd /Users/lorenzobaron/Desktop/watson-osint && .venv/bin/python -c "
import sys, asyncio
sys.path.insert(0, 'src')
from watson.orchestration.engine import get_engine
async def t():
    inv = await get_engine().investigate('test query')
    print(f'{inv.total_findings} findings')
asyncio.run(t())
"
```

## User's Goal

Make Watson the "most powerful intelligence agent ever created."
Current request: fix the 20 review issues, make it production-ready.
User is applying to AI labs (OpenAI, Anthropic, Mistral) for PMM roles.
Code quality matters — this is portfolio work.
