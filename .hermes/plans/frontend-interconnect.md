# Watson Frontend — Full Backend Interconnection Plan

**Date:** 2026-06-29
**Status:** Awaiting review

## Goal

Wire every page of the React frontend to Watson's live backend. Currently only WatsonChat
(the investigation tab) works — the rest are static Sherlock Holmes mockups with hardcoded
data.

## Architecture

```
React Frontend (Vite + TypeScript + Tailwind v4)
  │
  ├─ WatsonChat ──────────────► POST /api/agent/investigate → SSE stream  ✅ DONE
  ├─ Archives ───────────────► GET /api/cases                         ◻ TO DO
  ├─ Case Board ─────────────► GET /api/cases/:id (findings feed)     ◻ TO DO
  ├─ Evidence Map ───────────► Knowledge Graph visualization           ◻ TO DO
  ├─ OSINT Decoder ──────────► POST /api/agent/investigate (quick)    ◻ TO DO
  ├─ Personnel Dossiers ─────► GET /api/entities (from graph)         ◻ TO DO
  └─ API Vault ─────────────► SettingsModal (model-agnostic)          ◻ TO DO
```

## Task Breakdown

### Task 1: Archives page — list past cases

**File:** `src/components/Archives.tsx` (new)
**API:** `GET /api/cases` (adds new endpoint to `watson/web/app.py`)
**Effort:** Small (~60 lines)

- List all saved cases from `~/watson-cases/` with timestamps, target, findings count
- Click a case → load it inline (read the `.md` file)
- Search/filter by target name
- Status badges: verifiability %, findings count

### Task 2: Case Board page — live findings feed

**File:** `src/components/CaseBoard.tsx` (rewrite)
**API:** Same as WatsonChat — listens to SSE events
**Effort:** Medium (~120 lines)

- Mirrors WatsonChat's findings feed but as evidence cards
- Each finding → Clue card with title, description, source URL, confidence
- Red twine connections between related findings
- Auto-updates during live investigation
- Persists clues to localStorage

### Task 3: Evidence Map — knowledge graph visualization

**File:** `src/components/EvidenceMap.tsx` (rewrite)
**API:** `watson/mcp_server.py` (already exists, needs to be started)
**Effort:** Medium-Large (~180 lines)

- Canvas-based node-edge graph with D3/force-layout or Canvas API
- Nodes: entities (person, domain, company, crypto) + findings
- Edges: relationships (registered_to, mentions, subsidiary_of)
- Drag, zoom, click-to-expand
- Color-coded by entity type

### Task 4: OSINT Decoder — quick single-tool looks

**File:** `src/components/OSINTToolkit.tsx` (rewrite)
**API:** New endpoint `POST /api/agent/quick` or `POST /api/tools/lookup`
**Effort:** Small (~80 lines)

- Single-tool quick lookup: WHOIS, DNS, reverse IP, SSL cert, Wayback snapshot
- Returns raw data in a code block
- No full 7-phase pipeline — just the tool output

### Task 5: Personnel Dossiers — entity search

**File:** `src/components/Personnel.tsx` (rewrite)
**API:** `GET /api/search?q=...` or MCP `watson_search`
**Effort:** Small (~50 lines)

- Search entities across all past investigations
- Show entity profile: type, sources, related entities
- Link to original cases

### Task 6: API Vault — model-agnostic settings

**File:** `src/components/SettingsModal.tsx` (already rewritten)
**Effort:** ✅ Done

### Task 7: MCP Server — start alongside main app

**File:** `watson/mcp_server.py` (already exists)
**Effort:** Tiny (~5 lines)

- Start MCP server on port 8776 when `watson start` runs
- Wire into main app lifecycle
- Register as Hermes MCP server in config

### Task 8: Backend additions

**File:** `watson/web/app.py`
**Effort:** Small (~30 lines)

- `GET /api/cases` — list all cases with metadata
- `GET /api/cases/:id` — get a specific case markdown
- Parse `.md` cases to extract target, date, findings count, verifiability

## Implementation Order

1. **Archives** (easiest, biggest UX win) — Task 1 + Task 8 backend
2. **MCP Server** (unlocks Evidence Map data) — Task 7
3. **Evidence Map** (visual wow factor) — Task 3
4. **Case Board** (live findings mirror) — Task 2
5. **OSINT Decoder** (quick tool access) — Task 4
6. **Personnel** (entity search) — Task 5

Total estimated lines: ~500 lines of React + ~50 lines of Python.

## Files to create/modify

```
src/components/Archives.tsx          NEW  (~60 lines)
src/components/CaseBoard.tsx         REWRITE (~120 lines) 
src/components/EvidenceMap.tsx       REWRITE (~180 lines)
src/components/OSINTToolkit.tsx      REWRITE (~80 lines)
src/components/Personnel.tsx         REWRITE (~50 lines)
watson/web/app.py                   ADD endpoints (~30 lines)
watson/cli.py                       ADD MCP startup (~5 lines)
```

## Non-goals (explicitly out of scope)

- Multi-user auth (Watson is single-user local-first)
- Real-time collaboration
- Persistence beyond localStorage + filesystem
- Dark web scraping beyond existing tools
- Mobile responsive (desktop-first for investigation work)
