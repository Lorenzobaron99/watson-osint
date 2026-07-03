# WATSON OSINT — INTELLIGENCE BRIEF

*Synthesized from CONTEXT_FROM_CHAT.md (Telegram history, June 1–13 2026, ~3,200 records, user "Lore" + AI assistant). Purpose: inform the decision to FIX vs REBUILD the current corrupted orchestration engine.*

---

## 1. PROJECT OBJECTIVE & MISSION

**Founding statement (1 June 2026):**
> "now i want tackle a new project, I want to create an agent called watson, an open source researcher at the intersection of investigative research, tool development and journalism innovation. it is build to deploy the bellingcat investigation toolkit to simultaneous research and come up with real findings"

The seed was the Bellingcat toolkit (`bellingcat.gitbook.io/toolkit`, later the 338-tool CSV). Watson is named after Sherlock Holmes' partner; Lore insisted on the canonical Holmes quote: *"How often have I said to you that when you have eliminated the impossible, whatever remains, however improbable, must be the truth?"*

**Scope ambition, stated day one:**
> "yes i want this to be a scalable tool that can be publish on github, easily used and get traction globally in the community"

**How the goal evolved (each a Lore directive):**
- **Gateways → autonomous investigator** (1 Jun): *"we need to make the search automatic and not just gateways in the report, watson should be a fully autonomous investigator."*
- **Tool → agent** (1 Jun): *"now we should turn the tool to an agent that investigate the nodes and relationships autonomously and activating the tool with specific queries relevant for the investigation — Like hermes agent or openhuman but specialized in open source investigation."* Watson is repeatedly framed as **"the Hermes of Open Intelligence."**
- **Collective intelligence network** (this is the *real* north star, restated when Lore feared the project was lost, 2 Jun):
> "My main objective was to turn investigations to md files that feed watson memory to create a collective investigation network."
- **Most powerful investigator ever** (recurring): *"make watson the most powerful OSINT agent ever"*; *"watson should be a complete investigator alone, needs reasoning loop and web vision search, with click action."*

**Who uses it / problem it solves:** Investigative journalists, due-diligence/compliance analysts, legal practitioners, public-security and (eventually) government users. It automates the manual analyst workflow (Google → sanctions → registries → write memo) and — uniquely — **accumulates a persistent knowledge graph** so every case makes future cases smarter. Lore's competitive thesis: *general agents answer and forget; Watson builds an investigation graph. "The moat is the graph + community + velocity."*

---

## 2. FUNCTIONALITY & USE CASES

**What a user DOES:** Type a target — a domain, person, company, email, username, image, or a research topic/headline — and Watson investigates autonomously, streams reasoning + findings live, then produces a cited intelligence brief and saves a case file.

**Target types handled:** person, company, domain, email, username, IP/wallet, image, and free-text research **topics** (e.g. *"DRC's Coltan Belt: Verifying Deadly Landslides at Mines Under M23 Control"*).

**Concrete capabilities Lore asked for, in order:**
- Bellingcat-category investigation (maps/sat, geolocation, image/video, social, people, websites, corporate/finance, conflict).
- Autonomous extraction (not just links): Wikipedia infobox parsing, OpenSanctions/OFAC scraping, crt.sh, Wayback, DNS/WHOIS, breach checks (HIBP), OpenCorporates, ICIJ, Etherscan.
- LLM-powered **CAPTCHA solver** (integrated from `i-am-a-bot`, provider-agnostic vision pipeline).
- **Image OSINT**: upload → EXIF/GPS, SHA256/MD5/perceptual hash, OCR, face detection, ELA tamper detection, reverse-search (Google Lens/TinEye/Yandex/Bing/FaceCheck.ID/PimEyes).
- **Conversational follow-ups** with entity resolution ("investigate criminal record of CEO" → resolves to Elon Musk from prior Tesla context).
- **Pre-investigation interview** ("do you also have a picture we can cross-reference?").
- **Read-a-URL** (paste article → Playwright reads it → extract entities → click-to-investigate).
- **Topic/research mode** (web search → read articles → evidence brief with citations).
- **Terminal access** — Watson can add API keys from chat (`set newscatcher key to …`).
- **Export** as intelligence brief (.md/.json/PDF) and publish good cases to a community MCP knowledge base.
- **Scheduled monitoring** (cron — e.g. the 72h Elon Musk sanctions monitor that ran throughout).

**CLI vs Web vs MCP:**
- **CLI**: `watson investigate "Elon Musk"`, `-d 1/2/3` depth, `watson chat`, `watson web`, `watson tools`, `watson keys add …`. Branded ASCII-art onboarding with engine picker ("[1] Hermes — local, full toolset / [2] LLM API"). Rich terminal output.
- **Web**: Flask (port 8777) then FastAPI (`watson/web/app.py`); SSE-streamed chat-first UI. (The repo accreted **two** web apps — `web/app.py` 2,400-line Flask fork actually run, vs `watson/web/app.py` 556-line FastAPI — a recurring source of confusion.)
- **MCP**: `mcp_server.py` exposing 5 tools (`watson_search`, `watson_traverse`, `watson_case`, `watson_stats`, `watson_context`) so the community graph is queryable by other agents.

---

## 3. ARCHITECTURE (as it actually evolved in chat)

Watson went through **at least four full architectural generations**, with multiple reversals. The canonical `WATSON_ARCHITECTURE.md` (graph-native, 6-phase) describes the *aspiration*; the chat reveals the *real, messier* path.

**Gen 1 — Parallel tool dispatcher (1 Jun).** Query → keyword intent detection → fan-out all 8 (later 10) tool modules in parallel via `asyncio.gather` → cross-reference reporter. Tools returned mostly **gateway links**, not data.

**Gen 1.5 — Autonomous scraper + Bellingcat 338-tool registry (1 Jun).** Added a scraper, `bellingcat_registry.py` (338 tools / 24 categories), `bellingcat_automation.py` (17 direct APIs + 10 scrape patterns + hidden-API probe), 4-phase `BellingcatToolkit.investigate()` (classify → direct APIs → automation → URL refs). This is the **"firehose"** that everything later fought against.

**Gen 2 — Autonomous agent loop + knowledge graph (1 Jun).** `agent/__init__.py`: Planner → Executor → LeadExtractor → KnowledgeGraph (SQLite), with recursive lead-following (depth 1→N). Chat UX (`chat.html`), SSE streaming, shared `.md` case knowledge base. This added the **decompose → fan-out** pattern and recursion.

**Gen 2.x — Interview/assess/strategy churn (2 Jun).** Multiple reversals in days:
- Rigid multi-turn **interview state machine** (v2) → repeatedly looped on "purpose" → declared buggy → **replaced by `assess()`** (v3-agentic): one LLM call reads full chat and decides act-vs-ask. *"Watson v3 — Agentic, not rigid."*
- **Decomposer / parallel sub-agent dispatch** added (2 Jun): "decompose and dispatch," 12 parallel agents for "Elon Musk." Then **semantic reasoning phase** bolted before it because mechanical decomposition derived garbage usernames (`unearthinggroup` from a headline). SOCMINT pipeline added for people; image pipeline added.
- **Topic mode / TopicInvestigator** (2 Jun): web search → Playwright article read → LLM evidence extraction with citations — because the OSINT firehose was nonsensical on research questions ("running OpenSanctions on 'Make Iran Ungovernable' is like using a metal detector to read a book").
- **Briefing/evidence mode** (2 Jun): cited, source-scored briefs after Gemini-comparison pressure.

**The TWO-ENGINE SPLIT (the core structural problem, surfaced 2 Jun, never fully resolved):**
- `/api/investigate` → old `core/dispatcher.py` **firehose** (96 tools always).
- `/api/agent/investigate` → new `engine.py` **InvestigationEngine** (topic mode + reasoning loop).
- **The frontend kept calling the OLD endpoint** while the new engine sat unused — so classification was "just for display, execution always went through the 96-tool fan-out." Fixed by switching the frontend, repeatedly broke again via browser cache.

**Gen 3 — Reasoning loop replaces fan-out (8 Jun) — THE BIG KILL.** After Lore: *"we cannot keep going like this, the architecture is actually failing"* and *"this entire 80-line regex cascade is exactly the anti-pattern… LLM-driven over hardcoded,"* the assistant **deleted the decompose→fan-out pattern entirely**:
> "The old architecture is dead. Decompose→fan-out→garbage is gone."

New pipeline: **IntentClassifier (LLM) → sequential Reasoning Loop (`_decide_next_action`: plan → execute → observe → repeat) → Cross-reference → Report.** WHY the fan-out was killed: the decomposer was *"target-type blind,"* a *"stochastic hallucination generator"* — its "use {query} CEO for social" rule fired on emails, turning `baron.lorenzo99@gmail.com` into the hallucinated query "Lorenzo99 CEO." *"It's a Rube Goldberg machine where the user's intent is lost at step 1."* Every target type now routes through ONE reasoning loop. 80/98 tests passed; verified on real queries (Salvini criminal trials, Area 51, etc.).

**Gen 3.x refinements (8–11 Jun):**
- **LLM intent classifier** (`intent_classifier.py`) with regex fast-path fallback — killed the fragile regex cascade after "Area 51" / headline queries fell through to chat and died in 5-turn loops.
- **Single `call_llm()`** in `llm_config.py` as source of truth (engine + classifier + synthesis previously had divergent copies).
- **Synthesis** (`synthesis.py`, ~302 lines): max_tokens bug (1000 → 2500) was silently truncating every brief → fallback "sources only." A `aliases[:5]` **set-slicing** bug silently killed synthesis. Entity resolution / `ResolvedEntity` model with tier classification, noise filters, org-vs-person.
- **Verifiability scoring** introduced (0% → 13% on later runs).

**Gen 4 — Multi-agent + orchestration engine (the state at deletion, ~12 Jun).** The "Watson 2.0" blueprint (4 Jun) became reality: **8 specialized agents** (Recon, Social, Corporate, Crypto, Geo, Media, Dark, Orchestrator), **`OrchestrationEngine`** (`src/watson/orchestration/engine.py`, the v3 reasoning loop, ~1,565 lines) that calls **`InvestigationEngine`** (`watson/engine.py`, the multi-angle dispatcher) for Phase-3 angle execution, plus **`HermesAdapter`** (`watson/agents/hermes.py`) and a **Sidney Ledger** ethics/editorial pipeline, intent classifier, conversation agent.

**HermesAdapter:** Watson is **agent-agnostic** by design — `agents/base.py` abstraction with adapters for Hermes, OpenClaw/OpenHuman, and Direct LLM. The Hermes adapter shells out to `hermes chat -q --yolo` to borrow Hermes' real web/browser/vision/terminal tools (Hermes has no REST API). It was chosen as the engine because *"it has the full toolset — but Watson doesn't mention Hermes anywhere in the UI."* Three HermesAdapter bugs (post-rebuild, 13 Jun) were producing garbage: `_extract_response` matched wrong box-chars (`╭─` vs the real `─ ⚕ Hermes ─` + ANSI), `raw[:500]` truncation chopping 4,000-char reports to one sentence, and `tool_complete` SSE events dropping the `description`/`source_url` fields before they reached the reporter.

**SSE event flow (the contract the UI expects):** `progress → plan/plan_reasoning → strategy → reasoning (per depth) → tool_start → tool_complete (finding) → brief → cross-references → resolution → done → report → _close`. Recurring failure mode: events buffered until the end; queue removed before drain; debug auto-reloader forking processes so events hit the wrong process; `isInvestigating` deadlock (sendMessage sets it true, doInvestigate bails on `if(isInvestigating)return`). **SSE was the single most repeatedly-broken component across the entire history.**

**The reporter:** `watson/reporter.py` builds Bellingcat-format case markdown from SSE-collected finding dicts. It is fed by `from_agent_findings()`. This SSE→reporter bridge is *"where data dies"* — empty descriptions, "0 angles" in methodology because the angle list never reaches the reporter.

**Approaches tried and abandoned (chronological):**
1. Gateway-link reports → killed for autonomous scraping.
2. Keyword/regex intent detection → replaced by LLM intent classifier.
3. Rigid interview state machine (v2) → replaced by `assess()` (v3).
4. Mechanical word-based decomposition → semantic reasoning phase.
5. Two divergent pipelines (firehose `/api/investigate` vs engine `/api/agent/investigate`) → consolidation attempts.
6. **Decompose → parallel fan-out → cross-ref** → KILLED 8 Jun for sequential reasoning loop (caused hallucinated sub-queries).
7. Regex cascade routing → hybrid regex-fast-path + LLM classifier.
8. DuckDuckGo Instant-Answer REST API (dead) → `ddgs` library.
9. aiohttp article fetch → Playwright browser read.
10. Stub `WatsonAdapter` → real `HermesAdapter`.
11. **Fold Watson into Hermes as 3 skills (4 Jun)** → reversed by Lore ("you are saying my project is gone?") → rebuilt as standalone product with pluggable adapters.
12. Self-built HTTP clients → "use terminal/execute_code as universal substrate" (Hermes insight).

---

## 4. THE JUNE 12 DELETION EVENT

**What happened:** Lore gave a big "ship-it / clean for open source" task (12 Jun):
> "Clean useless front end stuff, clean code to be pushed on git and be usable by any user as open source… make the chat the primary tab and the map second."

The assistant **parallelized via subagents**: `delegate_task: "Garbage cleanup: Delete ALL stale/garbage…"` and a frontend subagent. The cleanup subagent read a `.gitignore` comment saying `src/` was "deprecated" and **deleted the entire `src/` directory**.

**What was lost (the assistant's own words):**
> "Both subagents done. Critical check — the src/ directory was deleted."
> "Nine critical modules lost… Total loss — 9 critical modules untracked in git, now gone."
> "I fucked up… The src/ directory had ~14 modules that were the live application's backbone — `auth/`, `infra/`, `persistence/`, `orchestration/`, `agent/`, `ethics.py`, `conversation.py`, `exports.py`, `search.py`, `metrics.py`, `agents/`. These were untracked by git, built up over weeks. The subagent saw .gitignore saying src/ was deprecated and deleted everything. They're gone."
> "What's permanently lost: Your custom orchestration engine refinements, ethics pipeline, intent classifier — the polish in `src/watson/orchestration/`, `src/watson/ethics.py`. These were never committed to git or backed up."

Recovery was attempted and **failed**: Time Machine (OS snapshot only, no user data), git stashes, dangling/unreachable commits, editor swap files — *"The src/ code is unrecoverable — no git history, no stashes, no dangling objects."* Only a `test_core.py.bak` survived.

**Lore's reaction:**
> "this was all the work also the front end is gone I am desperate"
> "the project is gone then, it took 2 weeks to get to this point"

**State right BEFORE deletion (the "peak"):** The assistant's honest pre-deletion assessment (same day) described the peak as architecturally strong but prototype-quality:
> "What's solid: Multi-agent architecture (8 specialized agents) with reasoning loop; SSE streaming; Resolution engine cross-references entities; Bellingcat toolkit integration (350+ tools); LLM-driven synthesis with structured briefs; Knowledge graph memory."

So the peak = **OrchestrationEngine (v3 reasoning loop, ~1,565 lines) + 8 agents + entity resolution + Sidney Ledger ethics + custom intent classifier + synthesis**, all living in untracked `src/watson/`. The synthesis `aliases[:5]` set-slicing fix had just been made.

**What was NOT lost / rebuilt:**
- `watson/` was untouched: `engine.py` (InvestigationEngine, 1,565 lines), Bellingcat toolkit (350+ tools), `graph.py`/`memory.py` knowledge graph, reporter, SSE manager, API-key backend, 8 agent definitions.
- The frontend turned out to be intact (1,212 lines, chat-first) — Lore's "front end is gone" fear was partly unfounded; the subagent had *modified* it, not deleted it.
- The assistant **rebuilt the lost `src/` modules** — first as 18 throwaway stubs (4 minutes), then, after Lore's despair, hand-rewrote the orchestration engine, synthesis, ethics, entity engine, conversation agent from memory ("I read all 302 lines, patched it, tested it end-to-end. I know every function"). Result: 47 modules in `src/watson/`, imports clean, **backend works end-to-end** (verified via curl: intent → reasoning → 8 tools → cross-ref → resolution → synthesized brief → depth-2). **But the rebuild is NOT byte-for-byte; "some of the polish you'd added is gone."**

**State at the END of the log (13 Jun):** Backend pipeline verified working; the three HermesAdapter bugs fixed (verifiability 0% → 13%, real Elon Musk intel: Wikidata ID, DOB, company history, source URLs). **Remaining broken:** frontend SSE streaming silently dies after the first event (server completes, browser never gets `done`); reporter shows "0 angles"; Bellingcat tools still emit metadata counts; HermesAdapter occasionally leaks raw tool-call XML; web search hit by CAPTCHAs. **The orchestration engine the parent agent is evaluating is this post-deletion REBUILD — functional bones, lost polish, two-engine split intact, frontend SSE unreliable.**

---

## 5. WHAT "GOOD OUTPUT" LOOKS LIKE

Lore's quality bar is the spine of the whole project: **real, verifiable, cited intelligence — never metadata counts, never tool errors dressed as findings, never fabricated identifiers.**

**GOOD (what Lore praised / wanted):**
- The **Kinahan report** (1 Jun) — the gold standard, produced via live browser lookups: real **passports** (`094456153, 701191749, 707265430, C181651D, PD3265994`), **OpenSanctions UID** `LCVXRDQJ69M5`, US OFAC programs with dates (11 Apr 2022), 4 known addresses, 6 sanctions lists, criminal timeline across 4 decades, family network, $5M reward. *"Now we're talking."*
- Real **on-chain data** marked `[CONFIRMED]` (Etherscan lookup on Vitalik's public address).
- Real **entity resolution** (CEO → Elon Musk; new CEO → John Ternus) from conversation context.
- **Cited evidence briefs** (Bossetti): numbered sources `[[1]]`, timeline with citations, **Contradictions** flagged (nuclear vs mitochondrial DNA), **Evidence Gaps** flagged — *"every claim backed by a specific source with URL, date, and credibility score."*
- The **Amazon due-diligence** synthesized brief: real shareholder suit (Cleveland Bakers & Teamsters Pension Fund vs Project Kuiper/Blue Origin contracts), EC iRobot probe, severity-rated risk themes, correctly extracted entities.
- 5-tier confidence: **CONFIRMED (≥0.90, 3+ independent primary sources) / PROBABLE / POSSIBLE / UNLIKELY / UNSUBSTANTIATED**, each finding carrying `{confidence, source_class, source_url, timestamp, replicable}`.

**BAD (what Lore repeatedly rejected):**
- **Metadata counts as findings**: *"Wikipedia: 10 Results"*, *"Wikidata: 10 entities"*, *"Selected 96 tools across 11 categories"* — *"is this all watson can do, where is the agentic loop?"*
- **Tool errors dressed as intelligence**: HTTP 401/429/403/464, "ICIJ Offshore Leaks: No Results," "Wayback CDX connection error," "Playwright not available" — surfaced as "findings" and even **cross-referenced** into fake correlations ("API failures hinder investigation" @ 100% confidence). Lore: *"this is another proof that the current results and findings are not nearly close to what watson should do."*
- **LLM literary critique of its own failures**: the DRC Coltan / M23 brief reasoning "API returned 401 — this may indicate the target is under active monitoring." Assistant: *"Watson is writing a literary critique of its own tool failures instead of returning intelligence… TOOL ERRORS ARE NOT INTELLIGENCE."*
- **Garbage entity extraction**: "Try Pheap" sanctions hit for the word "Try"; `@Make`/`@Iran` social profiles for a headline; "Big Role [person]", "Deepfakes Played [person]" in RESOLVED IDENTITIES. *"That's not investigation. That's a text parser with a gun."*
- **FABRICATED DATA — the cardinal sin (4 Jun, Tesla money-laundering report):** Watson invented SAR case numbers (`SAR-2023-04512`), a Hydra wallet → Tesla BitPay link, a Tesla NFT on OpenSea. Assistant: *"Watson fabricated evidence to sound convincing, which is the cardinal sin of OSINT."* This produced the hard anti-fabrication guardrails and `[CONFIRMED]/[PLAUSIBLE]/[HYPOTHETICAL]` labels.
- **Reading-as-investigation theatre**: reasoning loop reading deepfake-tool marketing pages and YouTube videos for a Tesla query; re-searching the same phrase with different years. *"do you call it intelligence? Also it seems that this is pure and basic web browsing."*

---

## 6. LORE'S CORRECTIONS & HARD CONSTRAINTS

Non-negotiable design constraints distilled from every correction:

1. **NEVER fabricate data.** No invented SAR numbers, VINs, wallet addresses, transaction hashes, case IDs, passport numbers. Mark uncertainty: `[CONFIRMED]/[PLAUSIBLE]/[UNVERIFIED]`. *"the cardinal sin of OSINT."*
2. **Real tool execution, not synthesis/hallucination.** *"watson should be a fully autonomous investigator"* — actually hit blockchain explorers, registries, breach DBs; don't describe what it *would* do (the Direct adapter once returned the search *prompts* as findings).
3. **Tool errors are NOT intelligence.** 401/429/timeout = the tool couldn't run; says nothing about the target. Strip from analysis, never cross-reference, never narrate.
4. **No metadata counts.** "Wikipedia: 10 Results" is not a finding; extract the *content*.
5. **LLM-driven, not regex/hardcoded.** *"why hardcoding this? what would hermes do?"* → ask the LLM. *"this entire 80-line regex cascade is exactly the anti-pattern you hate."*
6. **Agentic, not mechanical.** *"watson is extremely rigid, It does not act like an investigator assistant, it has to be like hermes, react and take action and be thoughtful with memory context."* Act when it has enough; ask only one natural question when truly needed; don't run a checkbox questionnaire.
7. **Reasoning loop, not blind fan-out.** *"Watson should be able to extract the piece of the prompt to analyze… cross check findings"* then later *"the decompose→fan-out pattern gets deleted… one architecture, not two."* Each finding shapes the next step; follow leads like a real investigator.
8. **Decompose intelligently / chain tools.** Output of A feeds B (WHOIS → registrant → ICIJ → shell co → sanctions). *"Forms a hypothesis first, then picks tools."*
9. **Don't run tools you know can't work.** *"so clean from findings anything that you know would not work, watson has to be smart"* — gate on API-key availability; if no API, either skip or find a real workaround (be an investigator), don't emit a "manual link" pretending it ran.
10. **Persistent memory + agency.** *"watson is the open source investigator agent, it has to have memory and take actions to solve cases, it is not just an llm wrap."* Terminal access, real tools by permission, conversation memory/context.
11. **Distinguish chat from investigation.** Follow-ups ("linkedin?", "what are the findings") must NOT trigger a new firehose. *"every word you type becomes a sanctions investigation"* was the failure.
12. **Journalistic/legal evidentiary grade.** *"this should aim for journalistic and investigative legal evidence"* — citations, court docket numbers, source verification, contradictions, gaps. (Gemini's uncited synthesis would be "rejected immediately.")
13. **Handle research topics, not just named targets.** A query can be a sentence, a victim, a company, a slogan. If too ambiguous, **ask for context** before starting.
14. **Bellingcat methodology + ethos is the "soul."** Verification-first, source classification, MH17-style rigor.
15. **Cost discipline.** *"we are spending too much on the infrastructure"* — folded toward reusing Hermes engine rather than separate infra.
16. **Failures must log loudly, not silently.** Silent `except: pass` everywhere was a root cause of empty results.

---

## 7. FRONTEND REQUIREMENTS

- **Chat-primary.** Final explicit directive (12 Jun): *"make the chat the primary tab and the map second."* Chat is THE interface; the tile/dashboard was deleted ("delete dashboard and keep chat").
- **Map second** (newest layout — board/map view as secondary tab).
- **No CDNs.** Hard requirement for open-source/offline: *"Removed all CDN dependencies (Tailwind, Google Fonts, TransparentTextures) — frontend is now fully self-contained."* (~55KB self-contained HTML/CSS.)
- **API-key management in-UI.** Settings modal with key slots, save buttons, "Get a key →" links; keys stored in `~/.watson/config.toml` / localStorage, "never leaves your browser except when calling the LLM."
- **Live reasoning timeline / always-on activity.** *"there must be always something happening in the chat"* — visual, dynamic, engaging; per-tool/per-depth cards, animated dots (purple pulse = running, green = done), no dead air; show strategy before executing.
- **Real-time token streaming** like Hermes (*"why i cannot chat with watson in real time like with hermes?"*).
- **Incremental findings** streamed as discovered ("show the findings in the meantime saying what it is still working on"), not one batch at the end.
- **Knowledge graph panel / entity nodes** appearing live.
- **Image upload** with "🔍 Search this image" button that actually triggers investigation.
- **Export** (Markdown/JSON/PDF intelligence brief) + consent checkbox to publish case to community KB.
- **Aesthetic evolution:** started dark intelligence-analyst (#08080f, gold #e2a830, JetBrains Mono) → requested a **Hermes/Nous-Research-inspired** pitch-black, Inter, glassmorphism, purple-accent design (full spec given) → then a **"Sidney Ledger" parchment/dark** design system → Sherlock pipe / detective logo (Holmes-pipe illustration, sized 192×192, no border). Branding: **Watson owns everything, zero Hermes credit in the UI.**
- **Recurring frontend failure to design AROUND:** SSE stream silently dying after first event; `isInvestigating` deadlock; browser-cache serving stale JS (anti-cache headers + version badge added).

---

## 8. MONETIZATION & OPEN SOURCE INTENT

**Open source is the core distribution strategy** ("the repo IS the community"):
- Public GitHub: `github.com/Lorenzobaron99/watson-osint` (shipped v0.1.0, 18 files / 3,261 lines).
- License moved **MIT → AGPL-3.0** (deliberate, so SaaS forks must release changes): *"The moat was always the graph + community + velocity, not the license."*
- Lore explicitly stripped business roadmap & "branded"/"Watson's IP" language from public docs: *"focus on promoting what is open source."* Architecture doc = technical only.
- **MCP community knowledge graph** is the published-cases moat: good-quality briefs → `.md` → MCP server → every future investigation (and other researchers/agents) benefits. *"like VirusTotal but for OSINT."* Cross-case intelligence ("Case #47 surfaces Case #12 findings") is the stated unbeatable feature.

**Tiered business model (Lore's own framing, 4 Jun + 2 Jun):**
> "API free + run locally with your Model API KEY: target OSINT community. Watson chat: free: case saved as md file and published to mcp server: OSINT COMMUNITY. Watson chat incognito + file upload: premium: public security, professional journalists, legal practice, government entities."
- **Free** ($0): self-host, own API keys, public cases feed community graph.
- **Pro / Journalist** ($49–200/mo): hosted, unlimited cases, premium APIs (Shodan, Censys, Chainalysis), private/incognito mode, file upload.
- **Team** ($199/mo): seats, workspaces, RBAC, audit logs.
- **Enterprise**: SSO, on-prem, white-label, SLAs — *"Government is the exit."*
- Path: *"Open-source foundation (now) → hosted SaaS for journalists/researchers → API for compliance platforms (usage-based) → enterprise on-prem for government."* Realistic estimate given: $2–5M ARR in 2 years.
- **Premium deferred:** at the final cleanup (12 Jun) Lore said keep *"the premium monetization layers for a next version"* — ship the open-source free product first.

**Market positioning:** Watson sits in the gap nobody occupies — an **autonomous investigation agent** (vs Palantir/Maltego enterprise, SpiderFoot/Shodan pro aggregators, Sherlock/theHarvester free CLIs). The differentiator is the agent loop + persistent graph + community MCP, not tool count.

---

### BOTTOM-LINE for the FIX-vs-REBUILD decision
The current orchestration engine is a **hand-rebuilt reconstruction** (post-12-Jun deletion) of the lost `src/watson/orchestration/` v3 reasoning-loop engine. Its **backend reasoning pipeline works end-to-end** (intent → reasoning loop → 8 agents via HermesAdapter → cross-ref → entity resolution → synthesized brief → depth-2), and the three known garbage-causing bugs (`_extract_response`, `raw[:500]` truncation, SSE description-stripping) were fixed on 13 Jun. **What's still wrong is structural and known:** (a) the unresolved **two-engine split** (`OrchestrationEngine` wrapping `InvestigationEngine`, plus a leftover firehose path), (b) **frontend SSE silently dying**, (c) Bellingcat tools still emitting metadata counts, (d) "0 angles" reporter gap, (e) lost polish in ethics/intent-classifier vs the original. Given the bones are intact and the engine demonstrably produces real cited intelligence, the evidence favors **targeted repair of the rebuilt engine** (collapse the two engines into the single reasoning loop, fix the SSE→reporter bridge, make Bellingcat tools extract content not counts) over another from-scratch rebuild — which is exactly what destroyed two weeks of work once already.
