"""Watson OSINT Investigation Engine — v4 Sequential Pipeline.

Professional OSINT architecture based on Bazzell (Identifier Pivoting),
Bertram (Surface→Deep→Dark progression), and generalist OSINT lifecycle.

7-phase sequential pipeline:
  0. OPSEC — sandbox, evidence log, API key loading
  1. CLASSIFY — intent classification (LLM)
  2. SURFACE — search engine dorking, WHOIS, DNS, crt.sh, Wayback, metadata
  3. PIVOT — identifier chaining (email→breach→accounts, username→profiles)
  4. DEEP — sanctions, corporate registry, court records, financial leaks
  5. DARK — Tor circuit, ransomware checks, pastebin (escalated only)
  6. ANALYZE — cross-reference, source tiering, entity resolution, synthesis
  7. REPORT — markdown generation, graph persistence, monitoring setup

Key principle: each investigation phase is a SINGLE Hermes subprocess call
where Opus 4.8 does sequential tool-use (search→read→extract→search again).
This is what produced real intelligence on June 12 — the model is the
reasoning engine, not the parallel angle dispatcher.

Source tiering (from Bazzell):
  PRIMARY   (0.90-0.95): Court records, gov registries, OFAC sanctions
  SECONDARY (0.60-0.75): News articles, corporate registries, breach data
  TERTIARY  (0.30-0.40): Wikipedia, social media self-reported
  UNVERIFIED (0.10-0.20): Anonymous sources, forum posts, single mentions
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Optional

logger = logging.getLogger("watson.orchestration")

# ── Constants ──────────────────────────────────────────────────

CASES_DIR = Path("~/watson-cases").expanduser().resolve()

SOURCE_TIERS = {
    "court_record":       {"tier": "PRIMARY",    "confidence": 0.95},
    "gov_registry":       {"tier": "PRIMARY",    "confidence": 0.90},
    "ofac_sanctions":     {"tier": "PRIMARY",    "confidence": 0.90},
    "un_sanctions":       {"tier": "PRIMARY",    "confidence": 0.90},
    "eu_sanctions":       {"tier": "PRIMARY",    "confidence": 0.90},
    "doj_indictment":     {"tier": "PRIMARY",    "confidence": 0.95},
    "interpol_notice":    {"tier": "PRIMARY",    "confidence": 0.90},
    "sec_filing":         {"tier": "PRIMARY",    "confidence": 0.85},
    "breach_data":        {"tier": "SECONDARY",  "confidence": 0.70},
    "corp_registry":      {"tier": "SECONDARY",  "confidence": 0.75},
    "news_article":       {"tier": "SECONDARY",  "confidence": 0.60},
    "academic_paper":     {"tier": "SECONDARY",  "confidence": 0.65},
    "crt_sh":             {"tier": "TERTIARY",   "confidence": 0.50},
    "whois":              {"tier": "TERTIARY",   "confidence": 0.40},
    "dns_record":         {"tier": "TERTIARY",   "confidence": 0.45},
    "wikipedia":          {"tier": "TERTIARY",   "confidence": 0.40},
    "wikidata":           {"tier": "TERTIARY",   "confidence": 0.45},
    "social_media":       {"tier": "TERTIARY",   "confidence": 0.30},
    "forum_post":         {"tier": "UNVERIFIED", "confidence": 0.20},
    "anonymous_source":   {"tier": "UNVERIFIED", "confidence": 0.10},
    "pastebin":           {"tier": "UNVERIFIED", "confidence": 0.15},
    "dark_web":           {"tier": "UNVERIFIED", "confidence": 0.20},
    "web_search":         {"tier": "SECONDARY", "confidence": 0.55},
}

# Dark web escalation triggers
DARK_WEB_TRIGGERS = [
    "ransomware", "dark web", ".onion", "tor", "cybercrime",
    "hacker", "malware", "data breach victim", "ransom",
    "sanctions evasion", "money laundering", "cryptocurrency laundering",
]

# Person deep investigation triggers — when these appear in findings, override person skips
# and run the full deep pipeline (courts, sanctions, media, dark web, gap filling).
PERSON_DEEP_TRIGGERS = [
    "murder", "homicide", "killed", "convicted", "sentenced", "prison",
    "arrested", "crime", "criminal", "court", "trial", "guilty", "fugitive",
    "wanted", "interpol", "terroris", "fraud", "embezzlement", "corruption",
    "indictment", "prosecutor", "lawsuit", "defendant", "plaintiff",
    "sanctions", "ofac", "trafficking", "cartel", "mafia", "money laundering",
]

# Locale-aware search — when profile has location data, add language-specific queries
# for criminal/news deep dives. Maps country codes to news domains and translated keywords.
LOCALE_SEARCH = {
    "IT": {
        "news_domains": "site:corriere.it OR site:repubblica.it OR site:ansa.it OR site:ilfattoquotidiano.it OR site:lastampa.it",
        "criminal_keywords": ["omicidio", "condanna", "ergastolo", "arrestato", "processo", "carcere", "tribunale", "indagato", "delitto"],
        "person_keywords": ["giornalista", "analista", "imprenditore", "fondatore"],
    },
    "FR": {
        "news_domains": "site:lemonde.fr OR site:lefigaro.fr OR site:liberation.fr OR site:mediapart.fr",
        "criminal_keywords": ["meurtre", "condamné", "prison", "arrêté", "procès", "tribunal", "coupable"],
        "person_keywords": ["journaliste", "analyste", "entrepreneur", "fondateur"],
    },
    "DE": {
        "news_domains": "site:spiegel.de OR site:zeit.de OR site:sueddeutsche.de OR site:faz.net",
        "criminal_keywords": ["Mord", "verurteilt", "Gefängnis", "festgenommen", "Prozess", "Gericht", "schuldig"],
        "person_keywords": ["Journalist", "Analyst", "Gründer", "Unternehmer"],
    },
    "ES": {
        "news_domains": "site:elpais.com OR site:elmundo.es OR site:abc.es OR site:lavanguardia.com",
        "criminal_keywords": ["asesinato", "condenado", "prisión", "detenido", "juicio", "tribunal", "culpable"],
        "person_keywords": ["periodista", "analista", "emprendedor", "fundador"],
    },
    "UA": {
        "news_domains": "site:pravda.com.ua OR site:kyivindependent.com OR site:unian.ua",
        "criminal_keywords": ["вбивство", "засуджений", "в'язниця", "арештований", "суд", "злочин"],
        "person_keywords": ["журналіст", "аналітик", "підприємець", "засновник"],
    },
    "RU": {
        "news_domains": "site:kommersant.ru OR site:vedomosti.ru OR site:novayagazeta.ru OR site:meduza.io",
        "criminal_keywords": ["убийство", "осужден", "тюрьма", "арестован", "суд", "преступление"],
        "person_keywords": ["журналист", "аналитик", "предприниматель", "основатель"],
    },
    "UK": {
        "news_domains": "site:bbc.co.uk OR site:theguardian.com OR site:telegraph.co.uk OR site:independent.co.uk",
        "criminal_keywords": ["murder", "convicted", "sentenced", "prison", "arrested", "trial", "guilty"],
        "person_keywords": ["journalist", "analyst", "entrepreneur", "founder"],
    },
    "US": {
        "news_domains": "site:nytimes.com OR site:washingtonpost.com OR site:wsj.com OR site:apnews.com",
        "criminal_keywords": ["murder", "convicted", "sentenced", "prison", "arrested", "trial", "guilty"],
        "person_keywords": ["journalist", "analyst", "founder", "executive"],
    },
    "JP": {
        "news_domains": "site:nhk.or.jp OR site:asahi.com OR site:mainichi.jp OR site:yomiuri.co.jp",
        "criminal_keywords": ["殺人", "有罪", "刑務所", "逮捕", "裁判", "判決", "起訴"],
        "person_keywords": ["記者", "アナリスト", "起業家", "創業者"],
    },
    "CN": {
        "news_domains": "site:scmp.com OR site:caixin.com OR site:thepaper.cn OR site:bbc.com/zhongwen",
        "criminal_keywords": ["谋杀", "定罪", "监禁", "逮捕", "审判", "判决", "起诉"],
        "person_keywords": ["记者", "分析师", "企业家", "创始人"],
    },
    "KR": {
        "news_domains": "site:chosun.com OR site:joongang.co.kr OR site:hani.co.kr OR site:koreaherald.com",
        "criminal_keywords": ["살인", "유죄", "감옥", "체포", "재판", "선고", "기소"],
        "person_keywords": ["기자", "분석가", "기업가", "창업자"],
    },
    "BR": {
        "news_domains": "site:folha.uol.com.br OR site:oglobo.globo.com OR site:estadao.com.br",
        "criminal_keywords": ["assassinato", "condenado", "prisão", "preso", "julgamento", "tribunal", "culpado"],
        "person_keywords": ["jornalista", "analista", "empreendedor", "fundador"],
    },
    "NL": {
        "news_domains": "site:nos.nl OR site:volkskrant.nl OR site:nrc.nl OR site:telegraaf.nl",
        "criminal_keywords": ["moord", "veroordeeld", "gevangenis", "arrestatie", "rechtszaak", "rechtbank"],
        "person_keywords": ["journalist", "analist", "ondernemer", "oprichter"],
    },
    "PL": {
        "news_domains": "site:onet.pl OR site:wyborcza.pl OR site:rp.pl OR site:tvn24.pl",
        "criminal_keywords": ["morderstwo", "skazany", "więzienie", "aresztowany", "proces", "sąd"],
        "person_keywords": ["dziennikarz", "analityk", "przedsiębiorca", "założyciel"],
    },
    "TR": {
        "news_domains": "site:hurriyet.com.tr OR site:sabah.com.tr OR site:milliyet.com.tr OR site:cumhuriyet.com.tr",
        "criminal_keywords": ["cinayet", "mahkum", "hapis", "tutuklandı", "dava", "mahkeme", "suçlu"],
        "person_keywords": ["gazeteci", "analist", "girişimci", "kurucu"],
    },
    "SE": {
        "news_domains": "site:svd.se OR site:dn.se OR site:expressen.se OR site:aftonbladet.se",
        "criminal_keywords": ["mord", "dömd", "fängelse", "gripen", "rättegång", "domstol"],
        "person_keywords": ["journalist", "analytiker", "entreprenör", "grundare"],
    },
    "IN": {
        "news_domains": "site:timesofindia.indiatimes.com OR site:thehindu.com OR site:hindustantimes.com OR site:indianexpress.com",
        "criminal_keywords": ["murder", "convicted", "sentenced", "prison", "arrested", "trial", "guilty"],
        "person_keywords": ["journalist", "analyst", "entrepreneur", "founder"],
    },
    "IL": {
        "news_domains": "site:haaretz.com OR site:jpost.com OR site:timesofisrael.com OR site:ynetnews.com",
        "criminal_keywords": ["רצח", "הורשע", "כלא", "נעצר", "משפט", "בית משפט"],
        "person_keywords": ["עיתונאי", "אנליסט", "יזם", "מייסד"],
    },
}

def _get_locale(profile, query: str = "") -> dict | None:
    """Extract locale config from profile locations, TLDs, and email domains.
    
    Detection order: profile.locations → email domain TLD → query TLD → None.
    Covers 20 locales including CJK, Cyrillic, Hebrew, Arabic.
    """
    # 1. Profile locations (from GLiNER/Wikidata)
    if profile and getattr(profile, "locations", None):
        for loc in profile.locations:
            loc_upper = loc.upper() if len(loc) == 2 else ""
            if loc_upper in LOCALE_SEARCH:
                return LOCALE_SEARCH[loc_upper]
    # 2. Email domain TLD detection
    import re as _re
    email_match = _re.search(r'@[\w.-]+\.([a-z]{2,3})$', query)
    if email_match:
        tld = email_match.group(1).upper()
        # Map common ccTLDs to locale codes
        tld_map = {
            "IT": "IT", "FR": "FR", "DE": "DE", "ES": "ES", "UA": "UA",
            "RU": "RU", "UK": "UK", "JP": "JP", "CN": "CN", "KR": "KR",
            "BR": "BR", "NL": "NL", "PL": "PL", "TR": "TR", "SE": "SE",
            "IN": "IN", "IL": "IL", "AU": "AU", "CH": "DE", "AT": "DE",
            "BE": "NL", "PT": "BR", "MX": "ES", "AR": "ES",
        }
        if tld in tld_map:
            return LOCALE_SEARCH.get(tld_map[tld])
    # 3. Query TLD detection (for domain targets like molfar.com → .com → US)
    # Only apply if it's a ccTLD, not a generic TLD
    domain_match = _re.search(r'\b[\w-]+\.([a-z]{2,3})\b', query)
    if domain_match:
        tld = domain_match.group(1).upper()
        if tld in LOCALE_SEARCH:
            return LOCALE_SEARCH[tld]
    # 4. Fuzzy location name matching
    if profile and getattr(profile, "locations", None):
        for loc in profile.locations:
            loc_lower = loc.lower()
            for name, code in {
                "italy": "IT", "italia": "IT", "france": "FR", "deutschland": "DE",
                "germany": "DE", "spain": "ES", "españa": "ES", "ukraine": "UA",
                "україна": "UA", "russia": "RU", "россия": "RU", "united kingdom": "UK",
                "uk": "UK", "united states": "US", "usa": "US", "japan": "JP",
                "日本": "JP", "china": "CN", "中国": "CN", "korea": "KR", "한국": "KR",
                "brasil": "BR", "brazil": "BR", "nederland": "NL", "netherlands": "NL",
                "polska": "PL", "poland": "PL", "türkiye": "TR", "turkey": "TR",
                "sverige": "SE", "sweden": "SE", "india": "IN", "भारत": "IN",
                "israel": "IL", "ישראל": "IL", "australia": "AU",
            }.items():
                if name in loc_lower:
                    return LOCALE_SEARCH.get(code)
    return None

# ── Data models ────────────────────────────────────────────────


@dataclass
class Finding:
    """Intelligence finding with source tracking and confidence."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    title: str = ""
    description: str = ""
    source_type: str = "web_search"
    source_url: str = ""
    source_tier: str = "SECONDARY"
    confidence: float = 0.5
    entities: list[dict] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    phase: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def tier(self) -> str:
        if self.confidence >= 0.85:
            return "CONFIRMED"
        if self.confidence >= 0.70:
            return "PROBABLE"
        if self.confidence >= 0.40:
            return "POSSIBLE"
        if self.confidence >= 0.10:
            return "UNLIKELY"
        return "UNSUBSTANTIATED"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "source_type": self.source_type,
            "source_url": self.source_url,
            "source_tier": self.source_tier,
            "confidence": self.confidence,
            "tier": self.tier,
            "entities": self.entities,
            "phase": self.phase,
        }


@dataclass
class InvestigationReport:
    """Complete investigation report."""
    case_id: str = field(default_factory=lambda: f"CASE-{uuid.uuid4().hex[:8].upper()}")
    query: str = ""
    target_type: str = ""
    target_profile: Any = None  # TargetProfile from target_profile.py
    findings: list[Finding] = field(default_factory=list)
    entities: list[dict] = field(default_factory=list)
    cross_references: list[dict] = field(default_factory=list)
    brief: dict = field(default_factory=dict)
    markdown: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    phases_completed: list[str] = field(default_factory=list)
    verifiability_score: float = 0.0
    graph_context: dict = field(default_factory=dict)  # Known entities from community graph pre-check
    stix_bundle: dict | None = None  # STIX 2.1 bundle from serialization phase
    stix_path: str | None = None  # Path to saved STIX JSON file


# ── SSE Emitter ────────────────────────────────────────────────


class SSEEmitter:
    """Thread-safe SSE event emission."""

    def __init__(self, on_event: Callable | None, client_id: str = ""):
        self._on_event = on_event
        self.client_id = client_id
        self.executed_tools: set[tuple[str, str]] = set()

    def emit(self, event_type: str, data: dict):
        if self._on_event:
            try:
                self._on_event(event_type, data)
            except Exception:
                pass

    def progress(self, phase: str, message: str):
        self.emit("progress", {
            "step": f"phase_{phase}",
            "status": "running",
            "message": message,
        })

    def finding(self, finding: Finding):
        self.emit("finding", finding.to_dict())

    def phase_start(self, phase: str, label: str):
        self.emit("phase_start", {"phase": phase, "label": label})

    def phase_done(self, phase: str, count: int):
        self.emit("phase_done", {"phase": phase, "finding_count": count})

    def track_tool(self, tool: str, target: str):
        self.executed_tools.add((tool, target[:100]))

    def graph_entities(self, context: dict):
        """Send community graph pre-check results to the frontend."""
        known = context.get("known_entities", [])
        self.emit("graph_context", {
            "known_count": len(known),
            "entities": [
                {"value": e.get("value", ""), "type": e.get("type", "unknown"), 
                 "case_ids": e.get("case_ids", []), "label": e.get("label", "")}
                for e in known
            ],
            "prior_relations": context.get("prior_relations", []),
            "relevant_cases": context.get("relevant_cases", []),
        })


# ═══════════════════════════════════════════════════════════════
# PHASE PROMPTS
# ═══════════════════════════════════════════════════════════════


def _surface_prompt(query: str, profile) -> str:
    """Phase 2 prompt: surface web collection with source dorking."""
    ttype = profile.target_type
    enrich = ""
    if profile.associated_orgs:
        enrich += f"\nASSOCIATED ORGANIZATIONS: {', '.join(profile.associated_orgs)}"
    if profile.associated_domains:
        enrich += f"\nASSOCIATED DOMAINS: {', '.join(profile.associated_domains)}"
    if profile.social_handles:
        enrich += f"\nSOCIAL HANDLES: {', '.join(profile.social_handles)}"
    if profile.locations:
        enrich += f"\nLOCATIONS: {', '.join(profile.locations)}"
    if profile.suggested_sources:
        enrich += f"\nSUGGESTED SOURCES: {', '.join(profile.suggested_sources)}"
    if profile.wikidata_qid:
        enrich += f"\nWIKIDATA: {profile.wikidata_label or profile.wikidata_qid} — {profile.wikidata_description or ''}"

    return f"""You are a professional OSINT investigator conducting Phase 2 (Surface Collection) of an investigation.

TARGET: {query}
TYPE: {ttype}{enrich}

OBJECTIVES:
1. Run targeted search engine queries with appropriate operators
2. Check certificate transparency (crt.sh) for subdomains (if domain target)
3. Check WHOIS records (if domain target)
4. Check DNS records (MX, NS, A) (if domain/company target)
5. Check Wayback Machine for historical versions (if web target)
6. Search for government/public records on the target
7. Extract metadata and source URLs from everything you find

SEARCH STRATEGY:
- Use precise search operators: site:gov, site:justice.gov, filetype:pdf
- For people: "NAME" sanctions OR indictment OR wanted OR court
- For companies: "COMPANY" OFAC OR sanctions OR investigation OR lawsuit
- For domains: site:crt.sh OR "certificate transparency" OR whois
- For emails: "EMAIL" breach OR leak OR pastebin

For each finding, PROVIDE:
- The actual content/data you discovered (not just search result counts)
- The source URL
- A confidence assessment
- Any new identifiers you can pivot from

OUTPUT FORMAT: For each finding, write:
FINDING: [title]
SOURCE: [url]
DATA: [the actual information found — names, dates, amounts, identifiers]
CONFIDENCE: [HIGH/MEDIUM/LOW]
PIVOT: [any new identifiers to chain from this]"""


def _pivot_prompt(query: str, profile, surface_context: str) -> str:
    """Phase 3 prompt: identifier pivoting and chaining."""
    ttype = profile.target_type
    enrich = ""
    if profile.associated_orgs:
        enrich += f"\nASSOCIATED ORGS: {', '.join(profile.associated_orgs)}"
    if profile.associated_domains:
        enrich += f"\nASSOCIATED DOMAINS: {', '.join(profile.associated_domains)}"
    if profile.social_handles:
        enrich += f"\nSOCIAL HANDLES: {', '.join(profile.social_handles)}"
    if profile.source_ids:
        enrich += f"\nSOURCE IDs: {json.dumps(profile.source_ids)}"

    return f"""You are a professional OSINT investigator conducting Phase 3 (Identifier Pivoting) of an investigation.

TARGET: {query}
TYPE: {ttype}{enrich}

PREVIOUS PHASE CONTEXT:
{surface_context}

OBJECTIVES:
Now that we have surface intelligence, pivot every identifier we've found:

1. EMAILS → check breach databases (HIBP) → leaked passwords/services
2. EMAILS → check registered accounts (check as many services as you can)
3. USERNAMES → cross-platform discovery (check GitHub, Twitter, Reddit, LinkedIn, etc.)
4. DOMAINS → check historical WHOIS → registrant email → pivot back to step 1
5. PHONE NUMBERS → carrier lookup → social graph connections
6. CRYPTO WALLETS → Etherscan → linked wallets → exchange KYC trails
7. COMPANY NAMES → subsidiary/corporate network → parent/sibling companies
8. PERSON NAMES → known associates, business partners, family members

KEY PRINCIPLE (Bazzell): Every data point chains to the next. Each finding
is a new starting point. Follow the chain recursively.

For each finding, PROVIDE:
- The actual data discovered
- The source/API used
- Confidence level
- The NEXT pivot this enables

OUTPUT FORMAT: For each finding:
FINDING: [title]
SOURCE: [url or API name]
DATA: [actual information]
CONFIDENCE: [HIGH/MEDIUM/LOW]
CHAIN: [potential next pivot from this data]"""


def _deep_prompt(query: str, profile, pivot_context: str) -> str:
    """Phase 4 prompt: deep investigation — sanctions, corporate, court, media."""
    ttype = profile.target_type
    enrich = ""
    if profile.associated_orgs:
        enrich += f"\nASSOCIATED ORGS (check OpenCorporates, sanctions for each): {', '.join(profile.associated_orgs)}"
    if profile.wikidata_qid:
        enrich += f"\nWIKIDATA: {profile.wikidata_label or profile.wikidata_qid}"
    if profile.locations:
        enrich += f"\nJURISDICTIONS TO CHECK: {', '.join(profile.locations)}"
    if profile.suggested_sources:
        enrich += f"\nSUGGESTED SOURCES: {', '.join(profile.suggested_sources)}"
    if profile.source_ids:
        enrich += f"\nKNOWN SOURCE IDS: {json.dumps(profile.source_ids)}"

    return f"""You are a professional OSINT investigator conducting Phase 4 (Deep Investigation).

TARGET: {query}
TYPE: {ttype}{enrich}

PREVIOUS FINDINGS (surface + pivot results):
{pivot_context}

OBJECTIVES — go deep now:

SANCTIONS & WATCHLISTS:
- Check OFAC SDN, EU sanctions, UN sanctions lists
- Check OpenSanctions for the target and any associated entities
- Check Interpol notices

CORPORATE:
- OpenCorporates: search for the entity and any directors/officers
- Companies House (if UK), SEC filings (if US public company)
- Check for shell company indicators, nominee directors
- ICIJ Offshore Leaks: search for connections

COURT & LEGAL:
- Search for court records, criminal cases, civil litigation
- PACER (US federal courts), local court databases
- Regulatory enforcement actions, fines, settlements

FINANCIAL:
- Follow the money trail — any financial crime connections
- Crypto/crypto laundering indicators if applicable

MEDIA DEEP-DIVE:
- Read full articles from credible news sources
- Check multiple outlets for corroboration
- Look for investigative journalism, not just press releases

For each finding, provide:
- The actual data (names, dates, amounts, case numbers, identifiers)
- The source URL or database name
- Whether this is PRIMARY (gov/court), SECONDARY (news/corp), or TERTIARY (wiki/social)
- Confidence assessment

OUTPUT FORMAT: For each finding:
FINDING: [title]
SOURCE: [url or registry name]
TIER: [PRIMARY|SECONDARY|TERTIARY]
DATA: [actual detailed information]
CONFIDENCE: [HIGH/MEDIUM/LOW]"""


def _dark_prompt(query: str, deep_context: str) -> str:
    """Phase 5 prompt: dark web investigation."""
    return f"""You are a professional OSINT investigator conducting Phase 5 (Dark Web Investigation).

TARGET: {query}

PREVIOUS FINDINGS (all phases):
{deep_context}

WARNING: This is an escalated phase. Only proceed if warranted by the findings above.
If no dark web indicators exist (ransomware, sanctions evasion, cybercrime, data breach victim),
state that clearly and skip.

OBJECTIVES:
1. Check RansomWatch and Ransomware.live for the target
2. Check Psbdmp/pastebin for target mentions
3. Check known data breach repositories (if relevant)
4. Search for .onion references to the target
5. Check dark web forum mentions (via clearnet mirrors)
6. Document any dark web infrastructure connected to the target

For each finding, provide:
- The actual data/mention found
- The source (even if it's a .onion URL — document it)
- Confidence assessment (dark web intel is inherently lower confidence)
- Any new identifiers

OUTPUT FORMAT:
FINDING: [title]
SOURCE: [source reference]
DATA: [actual information]
CONFIDENCE: [LOW/MEDIUM]
NOTE: [any caveats about the source reliability]"""


# ═══════════════════════════════════════════════════════════════
# MAIN ENGINE
# ═══════════════════════════════════════════════════════════════


class OrchestrationEngine:
    """7-phase professional OSINT investigation engine.

    Each investigation phase is a single Hermes subprocess call where
    Opus 4.8 performs sequential tool-use. The model is the reasoning
    engine — we give it the right prompt and tools per phase.

    INTERACTIVE STEERING: During investigation, the user can send
    interrupt messages via the /interrupt endpoint. The engine checks
    for interrupts between phases and can:
      - Inject context ("focus on the Russian sanctions angle")
      - Stop gracefully ("stop")
      - Skip a phase ("skip dark web")

    Interrupt queues are keyed by client_id and cleaned up on completion.
    """

    # Shared interrupt queues — indexed by client_id
    _interrupt_queues: dict[str, asyncio.Queue] = {}

    @classmethod
    def register_interrupt_queue(cls, client_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        cls._interrupt_queues[client_id] = q
        return q

    @classmethod
    def send_interrupt(cls, client_id: str, message: dict) -> bool:
        q = cls._interrupt_queues.get(client_id)
        if q:
            try:
                q.put_nowait(message)
                return True
            except asyncio.QueueFull:
                pass
        return False

    @classmethod
    def remove_interrupt_queue(cls, client_id: str) -> None:
        cls._interrupt_queues.pop(client_id, None)

    def __init__(self, depth: int = 2):
        self.depth = max(1, min(depth, 5))
        self._hermes_bin = "hermes"
        self._load_env()
        self._user_context = ""  # Accumulated user steering context
        self._should_stop = False
        self._skip_phases: set[str] = set()  # Phases to skip
        self._person_escalated = False  # True when criminal indicators trigger full deep
        self._focus_corrected = False  # True when target validation corrected the query

    def _check_person_escalation(self, findings: list[Finding]) -> bool:
        """Check if person target findings contain criminal/legal indicators.
        
        When true, overrides person pipeline skips — runs full deep investigation
        including dark web, gap filling, and full court/sanctions/media search.
        """
        if not findings:
            return False
        
        combined = " ".join(
            f"{getattr(f, 'title', '')} {getattr(f, 'description', '')}".lower()
            for f in findings[:30]
        )
        for trigger in PERSON_DEEP_TRIGGERS:
            if trigger in combined:
                logger.info("person_escalation_triggered: '%s' found in findings", trigger)
                return True
        return False

    # ── Main entry point ──────────────────────────────────────

    async def _check_interrupts(self, sse: SSEEmitter) -> dict | None:
        """Check for user interrupt messages. Non-blocking — returns None if empty.
        
        Returns the interrupt dict or None. Sets self._should_stop / self._skip_phases.
        """
        q = self._interrupt_queues.get(sse.client_id) if hasattr(sse, 'client_id') and sse.client_id else None
        if not q:
            return None
        
        messages = []
        while not q.empty():
            try:
                msg = q.get_nowait()
                messages.append(msg)
            except asyncio.QueueEmpty:
                break
        
        if not messages:
            return None
        
        for msg in messages:
            action = msg.get("action", "")
            text = msg.get("text", "").strip()
            
            if action == "stop" or text.lower() in ("stop", "enough", "done"):
                self._should_stop = True
                sse.progress("interrupt", "⏹ User requested stop — finishing current phase…")
            elif action == "skip_phase" or text.lower().startswith("skip "):
                phase = text.lower().replace("skip ", "").strip()
                self._skip_phases.add(phase)
                sse.progress("interrupt", f"⏭ Skipping phase: {phase}")
            elif text:
                # Context injection
                self._user_context += f"\n[USER STEERING]: {text}"
                sse.progress("interrupt", f"📝 Steering received: {text[:100]}")
        
        return messages[0] if messages else None

    def _finalize_early(self, report: InvestigationReport, sse: SSEEmitter, reason: str) -> dict:
        """Generate partial results when user stops investigation early."""
        brief = {"executive_summary": f"Investigation stopped early: {reason}"}
        report.brief = brief
        markdown = self._phase_report(report)
        report.markdown = markdown

        sse.emit("investigation_complete", {
            "case_id": report.case_id,
            "target_type": report.target_type,
            "total_findings": len(report.findings),
            "confirmed": sum(1 for f in report.findings if f.tier == "CONFIRMED"),
            "probable": sum(1 for f in report.findings if f.tier == "PROBABLE"),
            "unverified": sum(1 for f in report.findings if f.tier == "UNVERIFIED"),
            "early_stop": True,
            "stop_reason": reason,
        })

        return {
            "case_id": report.case_id,
            "target_type": report.target_type,
            "findings_count": len(report.findings),
            "confirmed_count": sum(1 for f in report.findings if f.tier == "CONFIRMED"),
            "verifiability_score": report.verifiability_score,
            "markdown": markdown,
            "early_stop": True,
        }

    @staticmethod
    def _load_env():
        """Load Hermes .env file for API keys needed by synthesis/classification."""
        import os as _os
        import sys as _sys
        # Add project root to path so watson.graph, watson.memory are importable
        _project_root = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))))
        if _project_root not in _sys.path:
            _sys.path.insert(0, _project_root)
        env_path = _os.path.expanduser("~/.hermes/.env")
        if _os.path.exists(env_path):
            for line in open(env_path):
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    if k.strip() not in _os.environ:
                        _os.environ[k.strip()] = v.strip()

    async def investigate(
        self,
        query: str,
        focus: str = "",
        on_event: Optional[Callable[[str, Any], None]] = None,
        client_id: str = "",
        depth: int | None = None,
        save_mode: str = "approval",
        mode: str = "deep_investigation",
    ) -> dict:
        """Run a full 7-phase investigation.

        mode:
          - "background_check" (30-60s): classify + surface only. Identity, sanctions, PEP, social.
          - "due_diligence" (2-5 min): + pivot + deep. Business/employment, adverse media, financial.
          - "deep_investigation" (5-15 min): All 7 phases + gap filling + locale search. Full dossier.

        save_mode:
          - "approval" (default): Don't auto-save. Frontend must call /save endpoint.
          - "auto": Save to disk immediately (legacy behavior).
        """
        d = depth if depth is not None else self.depth
        sse = SSEEmitter(on_event, client_id)
        report = InvestigationReport(query=query)

        # ── Phase 0: OPSEC setup ──
        CASES_DIR.mkdir(parents=True, exist_ok=True)

        # ── Phase 0.5: Entity extraction for long/ambiguous queries ──
        # Classification is designed for atomic targets (names, emails, IPs, domains).
        # Long sentences choke the classifier. Descriptive queries like "CEO of Binance"
        # need entity resolution before classification.
        LONG_QUERY_THRESHOLD = 35
        DESCRIPTIVE_PATTERNS = [
            r'\b(?:ceo|cto|cfo|coo|founder|president|director|chairman|owner)\s+of\s+',
            r'\b(?:head|chief|vp|svp|manager|lead)\s+of\s+',
        ]
        is_descriptive = any(re.search(p, query, re.IGNORECASE) for p in DESCRIPTIVE_PATTERNS)

        if (len(query) > LONG_QUERY_THRESHOLD or is_descriptive) and mode != "twin_connection":
            is_atomic = bool(
                re.search(r'^[\w.+-]+@[\w-]+\.[a-z]{2,}$', query.strip())
                or re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', query.strip())
                or re.search(r'^[\w-]+\.[a-z]{2,}$', query.strip())
                or re.search(r'^0x[a-fA-F0-9]{40}$', query.strip())
            )
            if not is_atomic:
                sse.progress("init", "Descriptive query detected — extracting entities for classification…" if is_descriptive
                             else "Long query detected — extracting entities for classification…")
                entities = self._extract_entities(query)
                # For descriptive queries, try to resolve the company/organization name too
                if is_descriptive:
                    org_name = re.sub(
                        r'(?i)\b(?:ceo|cto|cfo|coo|founder|president|director|chairman|owner|head|chief|vp|svp|manager|lead)\s+of\s+',
                        '', query
                    ).strip()
                    if org_name and org_name not in entities.get("people", []):
                        # Force-add the org name for classification
                        entities.setdefault("orgs", []).insert(0, org_name)

                best = (
                    (entities.get("people") or [None])[0]
                    or (entities.get("orgs") or [None])[0]
                    or (entities.get("domains") or [None])[0]
                    or (entities.get("emails") or [None])[0]
                    or (entities.get("ips") or [None])[0]
                )
                if best:
                    sse.progress("init",
                        f"→ Extracted target: '{best}' from query. "
                        f"Full text preserved as investigation context.")
                    query_for_classify = best
                    if not focus:
                        focus = query
                else:
                    sse.progress("init",
                        "→ No atomic entity found — passing full query to classifier.")
                    query_for_classify = query
            else:
                query_for_classify = query
        else:
            query_for_classify = query

        # ── Phase 1: Classify ──
        profile = await self._phase_classify(query_for_classify, sse)
        report.target_type = profile.target_type
        report.target_profile = profile

        # ── Mode gating (after classify — can use target_type) ──
        valid_modes = ("background_check", "due_diligence", "deep_investigation", "twin_connection")
        if mode not in valid_modes:
            mode = "deep_investigation"
        self._investigation_mode = mode

        # ── Twin Connection: dedicated pipeline ──
        if mode == "twin_connection":
            return await self._twin_pipeline(query, focus, sse, report)

        # Per-type per-mode phase decisions
        t = profile.target_type
        run_pivot = (
            mode in ("due_diligence", "deep_investigation")
            or (mode == "background_check" and t in ("person", "email"))
        )
        run_deep = mode in ("due_diligence", "deep_investigation")
        run_dark = mode == "deep_investigation"
        run_gaps = mode == "deep_investigation"

        sse.progress("init", f"Watson v4 [{mode.replace('_', ' ').title()}] — investigating: {query}")

        await self._check_interrupts(sse)
        if self._should_stop:
            return self._finalize_early(report, sse, "stopped_after_classify")

        focus = profile.primary_name or focus

        # ── Graph pre-check: surface existing community intelligence ──
        graph_context: dict = {"known_entities": [], "prior_relations": [], "relevant_cases": []}
        try:
            from watson.graph import KnowledgeGraph
            g = KnowledgeGraph()
            graph_context = g.context_for_investigation(query, max_entities=10)
            known_count = len(graph_context.get("known_entities", []))
            case_count = len(graph_context.get("relevant_cases", []))
            if known_count > 0:
                sse.progress("graph", 
                    f"📊 Community graph: {known_count} known entities across {case_count} prior cases")
                sse.graph_entities(graph_context)
            else:
                sse.progress("graph", "📊 Community graph: no prior findings — fresh investigation")
        except Exception as e:
            logger.debug("graph_pre_check_failed: %s", e)
        report.graph_context = graph_context

        # Phase 2: Surface collection
        sse.progress("surface", f"Surface collection — targeting: {query}")
        surface_findings = await self._phase_surface(query, profile, sse)
        report.findings.extend(surface_findings)
        report.findings = self._filter_quality(report.findings, query=report.query)
        report.phases_completed.append("surface")

        # ── Target validation: did we investigate the RIGHT person? ──
        if not self._focus_corrected and mode != "twin_connection":
            corrected = await self._validate_target_focus(
                query, profile.primary_name, surface_findings, sse)
            if corrected:
                self._focus_corrected = True
                # Keep the pre-correction findings as context, don't discard
                prior_count = len(surface_findings)
                # Re-run surface with corrected target
                sse.progress("surface", 
                    f"→ Re-running surface collection with corrected target: {corrected}")
                corrected_findings = await self._phase_surface(corrected, profile, sse)
                # Merge: corrected findings first, then original (as supplementary)
                surface_findings = corrected_findings + surface_findings
                report.findings = corrected_findings + report.findings
                sse.progress("surface",
                    f"→ Corrected: {len(corrected_findings)} new findings for '{corrected}' "
                    f"(+ {prior_count} prior findings retained as context)")
                # Update profile so downstream phases use the corrected name
                profile.primary_name = corrected

        # Check for person escalation — criminal/legal indicators trigger full deep investigation
        if profile.target_type == "person" and self._check_person_escalation(surface_findings):
            self._person_escalated = True
            sse.progress("surface", "⚠️ Criminal/legal indicators detected — escalating to full deep investigation")

        await self._check_interrupts(sse)
        if self._should_stop:
            return self._finalize_early(report, sse, "stopped_after_surface")

        # ── Graph Enrichment: Maltego-style entity discovery ──
        # For ALL target types (including person), run the entity graph + transform
        # engine to discover infrastructure (subdomains, IPs, geolocation,
        # emails) that the surface phase may have missed. Person targets
        # benefit from domain→email→person→org chain when surface findings
        # contain URLs/domains associated with the target.
        # Publisher/noise filter prevents news sites from polluting the graph.
        graph_enrich_findings = await self._run_graph_enrichment(
            surface_findings, query, profile, sse,
            target_types=["domain", "company", "organization", "person", "email"],
        )
        if graph_enrich_findings:
            report.findings.extend(graph_enrich_findings)
            sse.progress(
                "surface",
                f"→ Graph enrichment: {len(graph_enrich_findings)} new discoveries",
            )

        # Phase 3: Identifier pivoting
        # Email targets: skip generic pivot — identity search runs in Phase 2 (surface).
        if not run_pivot:
            sse.progress("pivot", f"⏭ Skipping pivot ({mode} mode)")
        elif profile.target_type == "email":
            sse.progress("pivot", "⏭ Skipping pivot (email — identity search in Phase 4)")
        elif "pivot" not in self._skip_phases:
            pivot_context = self._findings_context(surface_findings)
            pivot_findings = await self._phase_pivot(query, profile, pivot_context, sse)
            report.findings.extend(pivot_findings)
            report.findings = self._filter_quality(report.findings, query=report.query)
            report.phases_completed.append("pivot")
        else:
            sse.progress("pivot", "⏭ Skipping pivot (user requested)")

        await self._check_interrupts(sse)
        if self._should_stop:
            return self._finalize_early(report, sse, "stopped_after_pivot")

        # Phase 4: Deep investigation
        if not run_deep:
            sse.progress("deep", f"⏭ Skipping deep investigation ({mode} mode)")
        elif "deep" not in self._skip_phases:
            all_context = self._findings_context(report.findings)
            deep_findings = await self._phase_deep(query, profile, all_context, sse)
            report.findings.extend(deep_findings)
            report.findings = self._filter_quality(report.findings, query=report.query)
            report.phases_completed.append("deep")

            # ── OpenSanctions auto-pivot: discovered names → structured sanctions ──
            # Person investigations often discover full names during DDG search that
            # weren't in the original query (e.g. "Volodymyr Viktorovych" → discovers
            # "Volodymyr Viktorovych Tymoshchuk"). Re-run OpenSanctions with each
            # discovered name to get structured sanctions data (schema, datasets, topics).
            if profile.target_type == "person":
                os_pivot_findings = await self._auto_pivot_opensanctions(
                    report.findings, query, profile.primary_name, sse
                )
                if os_pivot_findings:
                    report.findings.extend(os_pivot_findings)
                    report.findings = self._filter_quality(report.findings, query=report.query)
                    sse.progress(
                        "deep",
                        f"→ OpenSanctions auto-pivot: {len(os_pivot_findings)} findings from discovered names",
                    )
        else:
            sse.progress("deep", "⏭ Skipping deep investigation (user requested)")

        await self._check_interrupts(sse)
        if self._should_stop:
            return self._finalize_early(report, sse, "stopped_after_deep")

        # ── Post-Deep Graph Enrichment: extract entities from ALL findings ──
        # For person targets in deep modes, the deep phase may have discovered
        # associated organizations, domains, or emails (foundations, shell companies,
        # properties). Run the graph engine on accumulated findings to discover
        # infrastructure and reverse-pivot to additional people/orgs.
        post_deep_graph = await self._run_graph_enrichment(
            report.findings, query, profile, sse,
            target_types=None,  # ALL target types eligible post-deep
        )
        if post_deep_graph:
            report.findings.extend(post_deep_graph)
            sse.progress(
                "deep",
                f"→ Post-deep graph enrichment: {len(post_deep_graph)} new discoveries from accumulated findings",
            )

        # Phase 5: Dark web (deep_investigation only)
        # NOTE: person_skip_dark defined for the elif chain below
        person_skip_dark = profile.target_type == "person" and not self._person_escalated
        if not run_dark:
            sse.progress("dark", f"⏭ Skipping dark web ({mode} mode)")
        elif profile.target_type in ("email", "company", "organization", "wallet") or person_skip_dark:
            sse.progress("dark", "Skipping dark web — irrelevant for this target type")
        elif "dark" in self._skip_phases:
            sse.progress("dark", "⏭ Skipping dark web (user requested)")
        elif self._should_escalate_to_dark(report.findings, query):
            sse.progress("dark", "⚠️ Escalating: dark web indicators detected")
            dark_findings = await self._phase_dark(query, profile, all_context, sse)
            report.findings.extend(dark_findings)
            report.findings = self._filter_quality(report.findings, query=report.query)
            report.phases_completed.append("dark")
        else:
            sse.progress("dark", "No dark web indicators — skipping escalation")

        await self._check_interrupts(sse)
        if self._should_stop:
            return self._finalize_early(report, sse, "stopped_after_dark")

        # Phase 5.5: Cross-platform identity correlation (person/email only)
        # Chains email→LinkedIn→phone→address by cross-referencing signals
        # across findings. Produces confidence-scored identity clusters.
        correlation = None
        if profile.target_type in ("person", "email") and report.findings:
            sse.progress("correlate", "Cross-platform identity correlation…")
            correlation = self._correlate_identity(report.findings, query, sse)

        # Phase 6: Analyze — cross-reference + entity resolution + synthesis
        if "analyze" not in self._skip_phases:
            sse.progress("analyze", "Cross-referencing, resolving entities, synthesizing…")
            brief = await self._phase_analyze(query, focus, report.findings, sse, report.target_type, report.graph_context, correlation)
            report.brief = brief or {}
        else:
            sse.progress("analyze", "⏭ Skipping analysis (user requested)")

        # Phase 6.5: Fill evidence gaps — deep_investigation only
        if not run_gaps:
            sse.progress("gaps", f"⏭ Skipping gap filling ({mode} mode)")
        else:
            # Deep Investigation: fill gaps for ALL target types — comprehensive coverage.
            # Due Diligence: skip gap filling entirely (doesn't reach this code path).
            if report.brief and report.brief.get("evidence_gaps"):
                gaps = report.brief["evidence_gaps"]
                sse.progress("gaps", f"Filling {len(gaps)} evidence gaps with targeted search…")
                gap_findings = await self._phase_fill_gaps(query, focus, gaps[:3], sse)
                if gap_findings:
                    report.findings.extend(gap_findings)
                    report.findings = self._filter_quality(report.findings, query=report.query)
                    sse.progress("gaps", f"→ {len(gap_findings)} new findings from gap filling")
                    # Re-synthesize with new findings
                    try:
                        brief2 = await self._phase_analyze(query, focus, report.findings, sse, report.target_type)
                        if brief2:
                            report.brief = brief2
                    except Exception:
                        pass

        await self._check_interrupts(sse)
        if self._should_stop:
            return self._finalize_early(report, sse, "stopped_after_analyze")

        # Phase 6.6: LLM Verification — second-pass false-positive filter
        # Runs after gap filling (which may have added new findings) and before
        # the final report. Each finding is re-examined; hallucinated or
        # unverifiable findings are dropped or downgraded.
        if "verify" not in self._skip_phases:
            sse.progress("verify", "Verifying findings — second-pass LLM audit…")
            try:
                from watson.verification import create_verifier
                verifier = create_verifier()
                if verifier:
                    verifications = await verifier.verify(report.findings, query)
                    if not verifications:
                        verifications = []
                    dropped = 0
                    kept = []
                    # Build lookup map safely
                    vmap: dict = {}
                    for v in verifications:
                        fid = v.get("finding_id", "")
                        if fid:
                            vmap[fid] = v
                    for finding in report.findings:
                        try:
                            finding_id = getattr(finding, "id", str(id(finding))[:12])
                            v = vmap.get(finding_id)
                            if v:
                                finding, was_dropped = verifier.apply(finding, v)
                                if was_dropped:
                                    dropped += 1
                                    continue
                        except Exception as ve:
                            logger.warning("verify_apply_failed: finding=%s error=%s", getattr(finding, "id", "?"), ve)
                        kept.append(finding)
                    report.findings = kept
                    if dropped:
                        sse.progress("verify", f"→ Dropped {dropped} unverifiable findings, {len(kept)} passed")
                    else:
                        sse.progress("verify", f"→ {len(kept)} findings verified — all passed")
                else:
                    sse.progress("verify", "⏭ Verification skipped (LLM unavailable)")
            except Exception as e:
                logger.warning("verification_phase_failed: %s", e)
                sse.progress("verify", f"⚠ Verification skipped ({e})")
        else:
            sse.progress("verify", "⏭ Skipping verification (user requested)")

        # Phase 6.7: STIX 2.1 Serialization — enterprise structured output
        if "stix" not in self._skip_phases:
            sse.progress("stix", "Producing STIX 2.1 bundle…")
            try:
                from watson.serializers.stix import export_stix
                stix_bundle, stix_path = export_stix(
                    query=query,
                    case_id=report.case_id,
                    target_type=report.target_type,
                    findings=report.findings,
                    entities=report.entities if hasattr(report, 'entities') else None,
                    brief=report.brief,
                )
                report.stix_bundle = stix_bundle
                report.stix_path = str(stix_path) if stix_path else None
                obj_count = len(stix_bundle.get("objects", []))
                sse.emit("stix_bundle", {
                    "case_id": report.case_id,
                    "objects": obj_count,
                    "spec_version": "2.1",
                })
                sse.progress("stix", f"→ STIX 2.1 bundle: {obj_count} objects")
            except Exception as e:
                logger.warning("stix_serialization_failed: %s", e)
                sse.progress("stix", f"⚠ STIX skipped ({e})")
        else:
            sse.progress("stix", "⏭ Skipping STIX (user requested)")

        # Phase 7: Report
        sse.progress("report", "Generating intelligence report…")
        # ── Global quality filter: strip tool-generated garbage ──
        report.findings = self._filter_quality(report.findings, query=report.query)
        markdown = self._phase_report(report)
        report.markdown = markdown

        # Notify frontend IMMEDIATELY — graph operations (O(N²) relations
        # + MCP publish) can take 30+ seconds and block the SSE stream,
        # making the frontend appear "stuck" at "generating report".
        sse.emit("investigation_complete", {
            "case_id": report.case_id,
            "mode": mode,
            "target_type": report.target_type,
            "total_findings": len(report.findings),
            "confirmed": sum(1 for f in report.findings if f.tier == "CONFIRMED"),
            "probable": sum(1 for f in report.findings if f.tier == "PROBABLE"),
            "verifiability": f"{report.verifiability_score:.0%}",
            "brief": brief,
            "markdown": markdown,
            "phases": report.phases_completed,
            "stix_available": report.stix_bundle is not None,
            "stix_objects": len(report.stix_bundle.get("objects", [])) if report.stix_bundle else 0,
        })

        # Save to disk / knowledge graph — offload to background thread
        # so the engine returns immediately after notifying the frontend.
        # _update_graph does O(N²) relation writes + MCP HTTP publish that
        # can block for minutes on large investigations.
        if save_mode == "auto":
            import threading
            threading.Thread(
                target=self._save_and_update_graph,
                args=(report,),
                daemon=True,
            ).start()
        else:
            # Store in pending for later approval
            if not hasattr(self, '_pending_reports'):
                self._pending_reports = {}
            self._pending_reports[report.case_id] = report

        return {
            "case_id": report.case_id,
            "mode": mode,
            "query": query,
            "target_type": report.target_type,
            "findings": report.findings,
            "findings_count": len(report.findings),
            "confirmed_count": sum(1 for f in report.findings if f.tier == "CONFIRMED"),
            "brief": brief,
            "markdown": markdown,
            "verifiability_score": report.verifiability_score,
            "cross_references": report.cross_references,
            "entities": report.entities,
            "phases_completed": report.phases_completed,
            "created_at": report.created_at,
        }

    # ── Twin Connection Pipeline ──────────────────────────────

    async def _twin_pipeline(self, query: str, focus: str, sse: SSEEmitter, report) -> dict:
        """Dedicated pipeline for connecting two findings.

        Phases:
          1. Parse — extract Finding A / Finding B entities from the query text
          2. Cross-match — find overlapping/shared entities
          3. Investigate — run focused OSINT on each overlap
          4. Synthesize — produce connection report
        """
        sse.phase_start("twin", "Twin Connection — cross-referencing two findings…")
        sse.progress("twin", "Parsing entities from both findings…")

        # ── Phase 1: Parse entities from both findings ──
        entities_a, entities_b = self._parse_twin_entities(query)

        sse.progress("twin",
            f"Finding A: {len(entities_a)} entities — "
            f"{entities_a.get('people', [])} {entities_a.get('domains', [])} {entities_a.get('urls', [])}")
        sse.progress("twin",
            f"Finding B: {len(entities_b)} entities — "
            f"{entities_b.get('people', [])} {entities_b.get('domains', [])} {entities_b.get('urls', [])}")

        # ── Phase 2: Cross-match ──
        sse.progress("twin", "Cross-matching entities between findings…")
        overlaps = self._cross_match_entities(entities_a, entities_b)

        if not overlaps:
            sse.progress("twin", "⚠️ No shared entities found. Running broader semantic search…")
            # Fallback: run a surface investigation on the key person/term from each
            all_people = entities_a.get("people", []) + entities_b.get("people", [])
            if all_people:
                focus_target = all_people[0]
                sse.progress("twin", f"→ Investigating shared context: {focus_target}")
                profile = SimpleNamespace(target_type="person", primary_name=focus_target)
                surface = await self._phase_surface(focus_target, profile, sse)
                report.findings.extend(surface)
                report.phases_completed.append("twin_surface_fallback")
        else:
            sse.progress("twin",
                f"✓ Found {len(overlaps)} shared entities: "
                f"{', '.join(o['value'][:40] for o in overlaps[:5])}")

            # ── Phase 3: Investigate each overlap ──
            sse.phase_start("twin_investigate", "Investigating shared connections…")
            for i, overlap in enumerate(overlaps[:4]):  # max 4 overlaps to keep it fast
                entity_type = overlap["type"]
                entity_value = overlap["value"]
                sse.progress("twin_investigate",
                    f"[{i+1}/{min(len(overlaps), 4)}] Investigating: {entity_value} ({entity_type})")

                findings = await self._investigate_overlap(entity_type, entity_value, query)
                for f in findings:
                    report.findings.append(f)
                    sse.finding(f)
                    sse.track_tool("twin_connection", entity_value)

        # ── Phase 4: Synthesize connection ──
        sse.phase_start("twin_synthesis", "Synthesizing connection report…")
        connection_brief = await self._synthesize_twin(query, report.findings, overlaps, entities_a, entities_b)
        report.brief = connection_brief or {}

        sse.progress("twin_synthesis", "Connection analysis complete")
        if connection_brief and connection_brief.get("connection_summary"):
            sse.progress("twin_synthesis", connection_brief["connection_summary"][:300])

        report.phases_completed.append("twin")
        markdown = self._phase_report(report)
        report.markdown = markdown

        sse.emit("investigation_complete", {
            "case_id": report.case_id,
            "mode": "twin_connection",
            "target_type": "twin_connection",
            "total_findings": len(report.findings),
            "confirmed": sum(1 for f in report.findings if f.tier == "CONFIRMED"),
            "probable": sum(1 for f in report.findings if f.tier == "PROBABLE"),
            "verifiability": f"{report.verifiability_score:.0%}",
            "brief": connection_brief,
            "markdown": markdown,
            "phases": report.phases_completed,
        })

        return {
            "case_id": report.case_id,
            "mode": "twin_connection",
            "query": query,
            "target_type": "twin_connection",
            "findings": report.findings,
            "findings_count": len(report.findings),
            "confirmed_count": sum(1 for f in report.findings if f.tier == "CONFIRMED"),
            "brief": connection_brief,
            "markdown": markdown,
            "verifiability_score": report.verifiability_score,
            "cross_references": [],
            "entities": [],
            "phases_completed": report.phases_completed,
            "created_at": report.created_at,
        }

    # ── Entity Extraction (shared by twin + pre-classification) ──

    @staticmethod
    def _extract_entities(text: str) -> dict[str, list[str]]:
        """Extract people, domains, IPs, emails, URLs, orgs from any text block.

        Used by:
          - _parse_twin_entities (twin connection pipeline)
          - investigate() pre-classification guard (long query entity extraction)
        """
        import re as _re

        result: dict[str, list[str]] = {
            "people": [], "domains": [], "ips": [],
            "emails": [], "urls": [], "orgs": [],
        }
        # URLs
        result["urls"] = _re.findall(r'https?://[^\s\)\]\|,;]+', text)
        # Emails
        result["emails"] = _re.findall(r'[\w.+-]+@[\w-]+\.[a-z]{2,}', text, _re.IGNORECASE)
        # IPs
        result["ips"] = _re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)
        # Domains
        domain_matches = _re.findall(
            r'(?:DOMAIN:|domain:)\s*([^\s\|,\]]+)', text, _re.IGNORECASE
        )
        if not domain_matches:
            domain_matches = _re.findall(
                r'(?:https?://)?(?:www\.)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-z]{2,}(?:\.[a-z]{2,})?)',
                text
            )
        result["domains"] = list(set(d for d in domain_matches
                                     if d not in ("com", "org", "net", "io", "gov", "edu", "lang", "en")))
        # People
        people_raw = _re.findall(r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b', text)
        skip_words = {
            "United States", "European Union", "New York", "San Francisco",
            "Custom Coordinate", "Organized Crime", "Security Council",
            "Wayback Machine", "Surface Collection", "Deep Investigation",
            "Dark Web", "Gravatar Profile", "Bellingcat Complete",
            "Treasury Has", "Investigate the", "Report specific", "Identify overlaps",
            "What links", "for twin.com", "Reverse DNS",
        }
        label_words = {
            "TITLE", "SOURCE", "DATA", "TIER", "EXHIBIT", "TYPE",
            "QUOTE", "DESCRIPTION", "CONFIDENCE", "FINDING", "TIER SECONDARY",
            "TIER UNLIKELY", "TIER PROBABLE", "SOURCE URL", "SOURCE TYPE",
            "CONFIDENCE TIER", "DOMAIN", "DOMAIN x.com", "DOMAIN opensanctions.org",
        }
        result["people"] = list(set(
            p for p in people_raw
            if p not in skip_words
            and p not in label_words
            and not p.startswith(("http", "www", "TITLE", "SOURCE", "DATA", "TIER", "FINDING"))
            and not any(p.startswith(lw) for lw in label_words)
        ))[:10]
        cleaned = []
        for p in result["people"]:
            if " | " in p:
                p = p.split(" | ")[0].strip()
            cleaned.append(p)
        result["people"] = cleaned
        # Orgs
        org_matches = _re.findall(r'\b([A-Z][A-Z&]{2,}(?:\s+[A-Z][A-Z&]{2,})*)\b', text)
        known_orgs = {"OCCRP", "OFAC", "FBI", "CIA", "NSA", "UN", "EU", "DOJ", "FINCEN"}
        result["orgs"] = list(set(
            o for o in org_matches
            if o in known_orgs or (len(o) > 5 and o not in label_words)
        ))[:5]
        return result

    @staticmethod
    def _parse_twin_entities(query: str) -> tuple[dict, dict]:
        """Split a twin-connection query into Finding A / Finding B and extract entities from each."""
        # Split by finding markers
        parts_a: list[str] = []
        parts_b: list[str] = []
        current = None
        for line in query.split("\n"):
            stripped = line.strip()
            if "[FINDING A]" in stripped:
                current = "a"
                after = stripped.split("[FINDING A]", 1)[-1].strip()
                if after:
                    parts_a.append(after)
                continue
            elif "[FINDING B]" in stripped:
                current = "b"
                after = stripped.split("[FINDING B]", 1)[-1].strip()
                if after:
                    parts_b.append(after)
                continue
            if current == "a":
                parts_a.append(line)
            elif current == "b":
                parts_b.append(line)

        text_a = "\n".join(parts_a)
        text_b = "\n".join(parts_b)

        # Fallback splits for malformed queries
        if not text_a.strip() or not text_b.strip():
            split_marker = "Identify overlaps in entities"
            if split_marker in query:
                pre, _ = query.split(split_marker, 1)
                lines = pre.strip().split("\n")
                mid = len(lines) // 2
                text_a = "\n".join(lines[:mid])
                text_b = "\n".join(lines[mid:])
            else:
                lines = query.split("\n")
                mid = len(lines) // 2
                text_a = "\n".join(lines[:mid])
                text_b = "\n".join(lines[mid:])

        return OrchestrationEngine._extract_entities(text_a), OrchestrationEngine._extract_entities(text_b)

    @staticmethod
    def _cross_match_entities(entities_a: dict, entities_b: dict) -> list[dict]:
        """Find shared entities between two finding entity sets.

        For people: uses fuzzy matching — "Karina Rotenberg Sanctions" matches "Karina Rotenberg".
        For domains/IPs/emails/orgs: exact match after lowercasing.
        """
        overlaps: list[dict] = []

        for key in ("people", "domains", "ips", "emails", "orgs"):
            items_a = entities_a.get(key, [])
            items_b = entities_b.get(key, [])

            if key == "people":
                # Fuzzy match: name A contains name B or vice versa
                for pa in items_a:
                    pa_lower = pa.lower().strip()
                    for pb in items_b:
                        pb_lower = pb.lower().strip()
                        if pa_lower == pb_lower:
                            overlaps.append({"type": "person", "value": pa, "confidence": 0.95})
                        elif pa_lower in pb_lower or pb_lower in pa_lower:
                            # "Karina Rotenberg Sanctions" contains "Karina Rotenberg"
                            shorter = pa if len(pa) < len(pb) else pb
                            overlaps.append({"type": "person", "value": shorter, "confidence": 0.75})
            else:
                set_a = {e.lower().strip() for e in items_a}
                set_b = {e.lower().strip() for e in items_b}
                shared = set_a & set_b
                for val in shared:
                    orig_a = next((e for e in items_a if e.lower().strip() == val), val)
                    overlaps.append({"type": key.rstrip("s"), "value": orig_a, "confidence": 0.9})

        # Also check URL domain overlaps
        from urllib.parse import urlparse
        domains_a = set()
        domains_b = set()
        for url in entities_a.get("urls", []):
            try:
                domains_a.add(urlparse(url).netloc.lower())
            except Exception:
                pass
        for url in entities_b.get("urls", []):
            try:
                domains_b.add(urlparse(url).netloc.lower())
            except Exception:
                pass
        shared_domains = domains_a & domains_b
        for d in shared_domains:
            if d and d not in {o["value"].lower() for o in overlaps}:
                overlaps.append({"type": "domain", "value": d, "confidence": 0.85,
                                 "note": "shared source domain"})

        # Deduplicate by value
        seen = set()
        unique = []
        for o in overlaps:
            key = o["value"].lower()
            if key not in seen:
                seen.add(key)
                unique.append(o)

        return unique

    async def _investigate_overlap(
        self, entity_type: str, entity_value: str, original_query: str
    ) -> list:
        """Run focused OSINT on a shared entity to find connection evidence."""
        findings: list = []

        # OpenSanctions for people/orgs
        if entity_type in ("people", "person", "org"):
            try:
                import httpx
                async with httpx.AsyncClient(timeout=15) as client:
                    resp = await client.get(
                        "https://api.opensanctions.org/search/default",
                        params={"q": entity_value, "limit": 3},
                        headers={"User-Agent": "WatsonOSINT/1.0", "Accept": "application/json"},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        results = data.get("results", [])
                        if results:
                            for r in results[:2]:
                                findings.append(Finding(
                                    title=f"🔗 OpenSanctions: {r.get('caption', entity_value)}",
                                    description=(
                                        f"OpenSanctions match for '{entity_value}' — "
                                        f"{r.get('schema', 'entity')}: "
                                        f"{r.get('properties', {}).get('notes', r.get('caption', ''))[:300]}"
                                    ),
                                    source_type="opensanctions",
                                    source_url=f"https://www.opensanctions.org/entities/{r.get('id', '')}",
                                    confidence=0.85 if r.get("match") else 0.7,
                                    phase="twin_investigate",
                                ))
            except Exception as e:
                logger.warning("twin_opensanctions_failed: %s", e)

        # DDG search for connection evidence
        try:
            from ddgs import DDGS

            query_map = {
                "people": f'"{entity_value}" connection investigation linked',
                "person": f'"{entity_value}" connection investigation linked',
                "domain": f'"{entity_value}" whois investigation',
                "ip": f'"{entity_value}" investigation',
                "email": f'"{entity_value}" investigation',
                "org": f'"{entity_value}" investigation news',
            }
            search_query = query_map.get(entity_type, f'"{entity_value}" investigation')

            def _search():
                try:
                    with DDGS() as ddgs:
                        return list(ddgs.text(search_query, max_results=3))
                except Exception:
                    return []

            raw_results = await asyncio.to_thread(_search)
            for r in raw_results:
                title = r.get("title", "")[:200]
                body = r.get("body", "")[:400]
                href = r.get("href", "")
                if href:
                    findings.append(Finding(
                        title=f"🔍 {title}",
                        description=body,
                        source_type="web_search",
                        source_url=href,
                        confidence=0.55,
                        phase="twin_investigate",
                    ))
        except Exception as e:
            logger.warning("twin_ddg_failed: %s", e)

        return findings

    async def _synthesize_twin(
        self, query: str, findings: list, overlaps: list[dict],
        entities_a: dict, entities_b: dict
    ) -> dict | None:
        """Produce a connection summary from the twin investigation."""
        if not overlaps and not findings:
            return {
                "connection_summary": (
                    "No direct entity overlap found between the two findings. "
                    "The connection may be thematic or contextual rather than entity-based."
                ),
                "shared_entities": [],
                "connection_strength": "WEAK",
            }

        shared = [{"type": o["type"], "value": o["value"]} for o in overlaps]
        strength = "STRONG" if len(overlaps) >= 3 else ("MODERATE" if overlaps else "WEAK")

        people_shared = [o for o in overlaps if o["type"] in ("person", "people")]
        domain_shared = [o for o in overlaps if o["type"] == "domain"]
        url_shared = [o for o in overlaps if o["type"] == "url"]

        parts = []
        if people_shared:
            parts.append(f"Shared person(s): {', '.join(p['value'] for p in people_shared)}")
        if domain_shared:
            parts.append(f"Shared domain(s): {', '.join(d['value'] for d in domain_shared)}")
        if url_shared:
            parts.append(f"Same source URL: {', '.join(u['value'] for u in url_shared)}")

        summary = (
            f"{' | '.join(parts)}. "
            f"Connection strength: {strength}. "
            f"{len(findings)} supporting findings collected."
        ) if parts else (
            f"Entities identified but no direct overlap. "
            f"{len(findings)} contextual findings collected. "
            f"Connection strength: {strength}."
        )

        return {
            "connection_summary": summary,
            "shared_entities": shared,
            "connection_strength": strength,
            "total_overlaps": len(overlaps),
            "investigation_findings": len(findings),
        }

    # ── Phase 1: Classify ─────────────────────────────────────

    async def _phase_classify(self, query: str, sse: SSEEmitter):
        """Fast layered target profiling: regex → GLiNER → Wikidata → LLM fallback."""
        from .target_profile import profile_target
        from .llm_config import call_llm

        sse.phase_start("classify", "Profiling target…")

        # Phase 1a: Regex (instant)
        sse.progress("classify", f"Checking deterministic patterns…")
        profile = await profile_target(query, call_llm=call_llm)

        # Phase 1b: GLiNER (local CPU NER)
        # (profile_target handles this internally via _gliner_classify)

        # Phase 1c: Wikidata enrichment
        # (profile_target handles this internally via _wikidata_enrich)

        classify_msgs = {
            "regex":   "🎯 Regex match — deterministic classification",
            "gliner":  "🧠 GLiNER NER — local CPU entity recognition",
            "gliner+wikidata": "🧠 + 📚 Wikidata enrichment",
            "regex+wikidata":  "🎯 + 📚 Wikidata enrichment",
            "llm":     "🤖 LLM fallback — ambiguous target",
            "empty":   "⚠️  Empty query",
            "none":    "⚠️  Could not classify — treating as topic",
        }
        classify_msg = classify_msgs.get(profile.classified_by, f"Classified via {profile.classified_by}")
        sse.progress("classify", classify_msg)

        # Rich SSE target event for frontend
        sse.emit("target_profile", {
            "target_type": profile.target_type,
            "primary_name": profile.primary_name,
            "confidence": profile.confidence,
            "associated_orgs": profile.associated_orgs,
            "associated_domains": profile.associated_domains,
            "social_handles": profile.social_handles,
            "known_aliases": profile.known_aliases,
            "locations": profile.locations,
            "wikidata_qid": profile.wikidata_qid,
            "wikidata_label": profile.wikidata_label,
            "wikidata_description": profile.wikidata_description,
            "suggested_sources": profile.suggested_sources,
            "investigation_angles": profile.investigation_angles,
            "classified_by": profile.classified_by,
        })

        sse.phase_done("classify", 0)
        sse.progress(
            "classify",
            f"Target: {profile.target_type.upper()} — {profile.primary_name} "
            f"(confidence: {profile.confidence:.0%})"
        )
        return profile

    # ── Target Validation —─────────────────────────────────────
    # After surface collection, verify we investigated the RIGHT target.
    # Prevents the class of bugs where regex extraction grabs the wrong name
    # (e.g., "Massimo Bossetti Italian" → falls back to "Yara Gambirasio").
    # LLM checks: do the findings match the original query intent?

    async def _validate_target_focus(
        self, original_query: str, primary_name: str,
        surface_findings: list[Finding], sse: SSEEmitter,
    ) -> str | None:
        """Validate that surface findings address the intended target.
        
        Returns corrected query string if the target was wrong, None if correct.
        Max 10s timeout, 200 tokens — cheap checkpoint.
        """
        # Build a minimal findings summary
        titles = []
        for f in surface_findings[:12]:  # top 12 is enough
            source = ""
            if f.source_url:
                try:
                    from urllib.parse import urlparse
                    source = urlparse(f.source_url).netloc.replace("www.", "")
                except Exception:
                    pass
            titles.append(f"- {f.title[:120]} ({source})" if source else f"- {f.title[:120]}")
        
        summaries = "\n".join(titles) if titles else "(no findings)"

        prompt = f"""ORIGINAL QUERY: {original_query}
WATSON SEARCHED FOR: {primary_name}

SURFACE FINDINGS SUMMARY:
{summaries}

QUESTION: Do these findings investigate "{original_query}" (the intended target), 
or did Watson investigate a different person/entity by mistake?
Reply with ONE line:
- "CORRECT" if the findings address the right target
- "WRONG: <corrected search term>" if we investigated the wrong entity

Examples:
- Query="Massimo Bossetti Italian murderer Yara Gambirasio case", searched "Yara Gambirasio" → WRONG: Massimo Bossetti
- Query="Elon Musk Twitter CEO", searched "Elon Musk" → CORRECT
- Query="CEO of Binance", searched "Changpeng Zhao" → CORRECT"""

        try:
            from .llm_config import call_llm as _call_llm
            response = await asyncio.wait_for(
                _call_llm(prompt, timeout=10, max_tokens=200),
                timeout=12,
            )
            if not response:
                return None
            
            response = response.strip()
            if response.upper().startswith("CORRECT"):
                return None
            if response.upper().startswith("WRONG:"):
                corrected = response.split(":", 1)[1].strip()
                if corrected and corrected != primary_name:
                    sse.progress("surface",
                        f"🔄 Target correction: '{primary_name}' → '{corrected}' "
                        f"(findings were about the wrong entity)")
                    return corrected
        except (asyncio.TimeoutError, Exception) as e:
            logger.debug("target_validation_failed: %s", e)
        
        return None

    # ── Phase 2: Surface Collection ───────────────────────────

    async def _phase_surface(self, query: str, profile, sse: SSEEmitter) -> list[Finding]:
        """Surface web collection — REAL tools: crt.sh, DNS, Wayback + LLM analysis."""
        sse.phase_start("surface", "Surface Collection — crt.sh, DNS, Wayback, web search…")
        sse.progress("surface", f"Running real OSINT tools on: {query}")

        # ── Run real API tools in parallel ──
        tool_findings: list[Finding] = []

        # Domain targets: run websites tool (crt.sh, DNS, Wayback)
        # EMAIL targets: skip domain tools — run email-specific surface checks in PARALLEL
        if profile.target_type == "email":
            sse.progress("surface", "→ Email check: Gravatar + HIBP + domain analysis (parallel)…")
            email_addr = profile.primary_name if "@" in profile.primary_name else query
            if "@" in email_addr:
                domain = email_addr.split("@")[-1]

                async def _run_people_tool():
                    try:
                        from ..tools.people import PeopleTool
                        people = PeopleTool()
                        return await people.investigate(email_addr)
                    except Exception as e:
                        logger.warning("email_people_tool_failed: %s", e)
                        return []

                async def _run_gravatar():
                    results = []
                    import hashlib
                    email_hash = hashlib.md5(email_addr.strip().lower().encode()).hexdigest()
                    gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404&s=200"
                    try:
                        import httpx
                        async with httpx.AsyncClient(timeout=8) as raw:
                            resp = await raw.get(gravatar_url, headers={"User-Agent": "WatsonOSINT/0.3"})
                            if resp.status_code == 200:
                                results.append(Finding(
                                    title=f"🖼 Gravatar profile picture found for {email_addr}",
                                    description=f"A public avatar is linked to this email.\n[Gravatar profile](https://www.gravatar.com/{email_hash})",
                                    source_type="gravatar",
                                    source_url=f"https://www.gravatar.com/{email_hash}",
                                    confidence=0.85,
                                    phase="surface",
                                ))
                            else:
                                results.append(Finding(
                                    title=f"📭 No Gravatar profile for {email_addr}",
                                    description="No public avatar/profile picture is linked to this email on Gravatar.",
                                    source_type="gravatar",
                                    confidence=0.6,
                                    phase="surface",
                                ))
                    except Exception:
                        pass
                    return results

                async def _run_domain_tools():
                    """Investigate the email's domain — only for custom domains, not providers."""
                    _KNOWN_PROVIDERS = {
                        "gmail.com", "googlemail.com", "yahoo.com", "ymail.com",
                        "outlook.com", "hotmail.com", "live.com", "msn.com",
                        "protonmail.com", "proton.me", "pm.me",
                        "icloud.com", "me.com", "mac.com",
                        "aol.com", "mail.com", "gmx.com", "gmx.de",
                        "zoho.com", "fastmail.com", "tutanota.com",
                        "yandex.com", "yandex.ru", "qq.com", "163.com",
                    }
                    if domain.lower() in _KNOWN_PROVIDERS:
                        return []  # DNS/crt.sh on Google's servers tells you nothing
                    try:
                        from ..tools.websites import WebsitesTool
                        web_tool = WebsitesTool()
                        return await web_tool.investigate(domain)
                    except Exception as e:
                        logger.warning("email_domain_tools_failed: %s", e)
                        return []

                async def _run_identity_search():
                    """DDG identity search — runs in ALL modes including Background Check.
                    Extracts name from email username for better search queries."""
                    results = []
                    try:
                        from ddgs import DDGS
                        username = email_addr.split("@")[0]
                        # Extract potential name: "baron.lorenzo99" → "Lorenzo Baron"
                        import re as _re
                        name_parts = _re.sub(r'[\d._-]+', ' ', username).strip().split()
                        name_queries = [username, email_addr]
                        if len(name_parts) >= 2:
                            # Try both orders: "Lorenzo Baron" and "Baron Lorenzo"
                            forward = " ".join(name_parts)
                            reverse = " ".join(reversed(name_parts))
                            name_queries.extend([
                                f'"{forward}" linkedin',
                                f'"{forward}" github',
                                f'"{reverse}" linkedin',
                                f'"{reverse}" github',
                            ])
                        else:
                            name_queries.extend([
                                f'{username} linkedin',
                                f'{username} github',
                            ])
                        def _search(q):
                            try:
                                with DDGS() as ddgs:
                                    return list(ddgs.text(q, max_results=3))
                            except Exception:
                                return []
                        all_raw = await asyncio.gather(*[
                            asyncio.to_thread(_search, q) for q in name_queries[:6]
                        ])
                        seen = set()
                        for raw_list in all_raw:
                            for r in raw_list:
                                href = r.get("href", "")
                                if href and href not in seen:
                                    seen.add(href)
                                    results.append(Finding(
                                        title=f"🔍 {r.get('title', '')[:140]}",
                                        description=r.get("body", "")[:250],
                                        source_type="identity_search",
                                        source_url=href,
                                        confidence=0.6,
                                        phase="surface",
                                    ))
                    except Exception as e:
                        logger.warning("email_identity_surface_failed: %s", e)
                    return results

                # Run all four in parallel
                people_results, gravatar_results, domain_results, identity_results = await asyncio.gather(
                    _run_people_tool(), _run_gravatar(), _run_domain_tools(), _run_identity_search(),
                )
                for rf in people_results:
                    f = self._tool_finding_to_engine(rf, phase="surface")
                    if f:
                        tool_findings.append(f)
                        sse.finding(f)
                        sse.track_tool("people", email_addr)
                for f in gravatar_results:
                    tool_findings.append(f)
                    sse.finding(f)
                    sse.track_tool("gravatar", email_addr)
                for rf in domain_results:
                    f = self._tool_finding_to_engine(rf, phase="surface")
                    if f:
                        tool_findings.append(f)
                        sse.finding(f)
                        sse.track_tool("websites", domain)
                for f in identity_results:
                    tool_findings.append(f)
                    sse.finding(f)
                    sse.track_tool("identity_search", email_addr)
                if identity_results:
                    sse.progress("surface", f"→ Found {len(identity_results)} identity references")
                else:
                    sse.progress("surface", "→ No public identity traces found")

        elif profile.target_type in ("domain", "company", "organization"):
            # DOMAIN/COMPANY: run websites tool (crt.sh, DNS, Wayback)
            # PERSON: skip — associated_domains for person targets are noise
            # (linkedin.com, wikipedia.org from profile enrichment — not investigation targets)
            sse.progress("surface", "→ crt.sh + DNS + Wayback Machine…")
            try:
                from ..tools.websites import WebsitesTool
                web_tool = WebsitesTool()
                domain_query = query
                if profile.associated_domains:
                    domain_query = profile.associated_domains[0]
                raw_findings = await web_tool.investigate(domain_query)
                for rf in raw_findings:
                    f = self._tool_finding_to_engine(rf, phase="surface")
                    if f:
                        tool_findings.append(f)
                        sse.finding(f)
                        sse.track_tool("websites", domain_query)
            except Exception as e:
                logger.warning("websites_tool_failed: %s", e)

        # Person/company targets: scrape Wikipedia
        if profile.target_type in ("person", "company", "organization"):
            sse.progress("surface", "→ Wikipedia extraction…")
            try:
                from ..tools.scraper import ScraperTool
                scraper = ScraperTool()
                raw_findings = await scraper.investigate(profile.primary_name)
                for rf in raw_findings:
                    f = self._tool_finding_to_engine(rf, phase="surface")
                    if f:
                        tool_findings.append(f)
                        sse.finding(f)
                        sse.track_tool("scraper", profile.primary_name)

                        # Detect location/municipality disambiguation
                        # Wikipedia pages for comunes/regions contain keywords like
                        # "comune", "municipality", "province", "region" in the description.
                        desc = (f.description or "").lower()
                        wiki_title = (f.title or "").lower()
                        location_keywords = [
                            "comune", "municipality", "province of", "region of",
                            "frazione", "town in", "city in", "village in",
                            "metropolitan city", "italian region", "capital of",
                        ]
                        if profile.target_type == "person" and any(
                            kw in desc or kw in wiki_title for kw in location_keywords
                        ):
                            sse.progress("surface",
                                f"⚠️ Wikipedia says '{profile.primary_name}' is a location. "
                                f"Searching for a real person with this name…")
                            # Add the location to the profile so later phases can use it
                            if not profile.locations:
                                profile.locations = []
                            profile.locations.append(profile.primary_name)
                            profile._location_disambiguation = True

                            # FORCE a targeted person search excluding the non-person Wikipedia hit
                            # Universal fix: when Wikipedia returns a location/org/thing instead of a person,
                            # search with -site:wikipedia.org + person keywords. Works for:
                            # - Marco Rossi (comune) → "Marco Rossi" analyst defense
                            # - Austin Texas (city) → "Austin Texas" linkedin
                            # - Paris Hilton (city) → "Paris Hilton" celebrity (though common enough to find anyway)
                            try:
                                from ddgs import DDGS
                                person_name = profile.primary_name
                                person_queries = [
                                    f'"{person_name}" -site:wikipedia.org linkedin OR author OR analyst OR journalist OR engineer',
                                    f'"{person_name}" -site:wikipedia.org professional OR founder OR director',
                                ]
                                def _person_search(q):
                                    try:
                                        with DDGS() as ddgs:
                                            return list(ddgs.text(q, max_results=5))
                                    except Exception:
                                        return []
                                all_raw = await asyncio.gather(*[
                                    asyncio.to_thread(_person_search, q) for q in person_queries
                                ])
                                seen = set()
                                for raw_list in all_raw:
                                    for r in raw_list:
                                        href = r.get("href", "")
                                        title = r.get("title", "")[:150]
                                        body = r.get("body", "")[:300]
                                        if href and href not in seen and "wikipedia.org" not in href:
                                            seen.add(href)
                                            tool_findings.append(Finding(
                                                title=f"👤 Person search: {title}",
                                                description=body,
                                                source_type="web_search",
                                                source_url=href,
                                                confidence=0.7,
                                                phase="surface",
                                            ))
                                            sse.finding(tool_findings[-1])
                                            sse.track_tool("person_disambiguation_search", person_name)
                                if seen:
                                    sse.progress("surface",
                                        f"→ Found {len(seen)} potential person matches for '{person_name}' "
                                        f"(excluding Wikipedia)")
                                else:
                                    sse.progress("surface",
                                        f"→ No person matches found for '{person_name}' "
                                        f"outside of Wikipedia — may genuinely not be a person")
                            except Exception as e:
                                logger.warning("person_disambiguation_search_failed: %s", e)
            except Exception as e:
                logger.warning("scraper_tool_failed: %s", e)

        # Person targets: identity search (PeopleTool) + social discovery
        # Run people-search FIRST — Google dorks, Wikidata, professional profiles.
        # Then social discovery fills gaps with LinkedIn/Twitter/Instagram DDG.
        if profile.target_type == "person":
            # ── Identity search (PeopleTool): Google dorks, Wikidata, GitHub, Twitter ──
            sse.progress("surface", "→ Identity search: Google dorks, Wikidata, professional profiles…")
            try:
                from ..tools.people import PeopleTool
                people = PeopleTool()
                person_name = profile.primary_name or query
                identity_findings = await people.investigate(person_name)
                for rf in identity_findings:
                    f = self._tool_finding_to_engine(rf, phase="surface")
                    if f:
                        tool_findings.append(f)
                        sse.finding(f)
                        sse.track_tool("people", person_name)
                if identity_findings:
                    sse.progress("surface",
                        f"→ Found {len(identity_findings)} identity references for '{person_name}'")
            except Exception as e:
                logger.warning("people_tool_failed: %s", e)

            # ── Social profile discovery (DDG): LinkedIn, Twitter, Instagram ──
            sse.progress("surface", "→ Social profile discovery…")
            try:
                from ddgs import DDGS
                person_name = profile.primary_name or query
                # ── Common-name guard: skip generic LinkedIn/Instagram for short names ──
                # "Charles Taylor" → 3200+ LinkedIn profiles, all wrong person.
                # Only trigger for names with common Western first/given names.
                COMMON_FIRST_NAMES = {
                    "john", "jane", "michael", "maria", "james", "sarah", "david", "lisa",
                    "robert", "emma", "william", "anna", "thomas", "olivia", "daniel",
                    "matthew", "andrew", "ryan", "joshua", "christopher", "nicholas",
                    "anthony", "benjamin", "samuel", "jacob", "joseph", "charles", "mark",
                    "paul", "steven", "richard", "george", "peter", "simon", "edward",
                    "frank", "henry", "stephen", "philip", "patrick", "alexander",
                }
                name_parts = person_name.split()
                is_common_name = (
                    len(name_parts) == 2
                    and name_parts[0].lower() in COMMON_FIRST_NAMES
                    and len(name_parts[1]) < 12
                )
                if is_common_name:
                    sse.progress("surface", f"  ⚠ Common name detected — skipping social queries for '{person_name}' to avoid noise")
                    # For common names (2 short words), generic LinkedIn/Instagram searches
                    # return thousands of wrong people. Skip and rely on Wikipedia + identity tools.
                    social_queries = [
                        f'"{person_name}" wikipedia',
                    ]
                else:
                    social_queries = [
                        f'"{person_name}" linkedin',
                        f'"{person_name}" twitter OR x.com',
                        f'"{person_name}" instagram',
                    ]
                def _social_search(q):
                    try:
                        with DDGS() as ddgs:
                            return list(ddgs.text(q, max_results=2))
                    except Exception:
                        return []
                all_social = await asyncio.gather(*[
                    asyncio.to_thread(_social_search, q) for q in social_queries
                ])
                seen_urls = set()
                social_found = 0
                # Domains that are business directories, not social profiles
                _BUSINESS_DIRS = {
                    "aziende.virgilio.it", "trova-aperto.it", "paginegialle.it",
                    "tuttocitta.it", "impresaitalia.info", "companyhouse.it",
                    "yelp.", "tripadvisor.", "maps.google.",
                }
                for raw_list in all_social:
                    for r in raw_list:
                        href = r.get("href", "")
                        if href and href not in seen_urls:
                            # Skip business directory results — these are noise for person search
                            if any(d in href for d in _BUSINESS_DIRS):
                                continue
                            body = (r.get("body", "") or "").lower()
                            if any(kw in body for kw in ("via ", "telefono", "orari ", "impresa ", "imprese ", "p.iva")):
                                continue
                            seen_urls.add(href)
                            platform = ""
                            title_lower = (r.get("title", "")).lower()
                            url_lower = href.lower()
                            if "linkedin.com" in url_lower: platform = "LinkedIn"
                            elif "twitter.com" in url_lower or "x.com" in url_lower: platform = "X/Twitter"
                            elif "instagram.com" in url_lower: platform = "Instagram"
                            else: platform = "social"
                            tool_findings.append(Finding(
                                title=f"🌐 [{platform}] {r.get('title', '')[:140]}",
                                description=r.get("body", "")[:250],
                                source_type="social_discovery",
                                source_url=href,
                                confidence=0.55,
                                phase="surface",
                            ))
                            sse.finding(tool_findings[-1])
                            social_found += 1
                if social_found:
                    sse.progress("surface", f"→ Found {social_found} social profile references")
                else:
                    sse.progress("surface", "→ No public social profiles found")
                    sse.track_tool("social_discovery", person_name)
            except Exception as e:
                logger.warning("social_discovery_failed: %s", e)

        # Location targets: geocode places from classifier profile
        # SKIP for person targets — geocoding "Italy" to find nearby factories
        # for a person investigation is noise. Geolocation is for OSINT on
        # specific places (crime scenes, company HQs, asset locations).
        if profile.locations and profile.target_type != "person":
            sse.progress("surface", f"→ Geolocating: {', '.join(profile.locations[:3])}…")
            try:
                from ..tools.geolocation import GeolocationTool
                geo_tool = GeolocationTool()
                for loc in profile.locations[:3]:  # Top 3 locations
                    geo_findings = await geo_tool.investigate(loc)
                    for rf in geo_findings:
                        f = self._tool_finding_to_engine(rf, phase="surface")
                        if f:
                            tool_findings.append(f)
                            sse.finding(f)
                            sse.track_tool("geolocation", loc)
            except Exception as e:
                logger.warning("geolocation_tool_failed: %s", e)

        # ── LLM analysis with DuckDuckGo ──
        # Skip for email, company/org, wallet, AND person targets: targeted search handles them.
        # The generic surface prompt produces redundant results.
        if profile.target_type not in ("email", "company", "organization", "wallet", "person"):
            sse.progress("surface", "→ Web search + LLM analysis…")
            prompt = _surface_prompt(query, profile)
            raw = await self._investigation_call(prompt, phase="surface", sse=sse)
            llm_findings = self._parse_findings(raw, phase="surface")
        else:
            sse.progress("surface", "→ Skipping generic search (targeted search in later phases)")
            llm_findings = []

        all_findings = tool_findings + llm_findings
        sse.phase_done("surface", len(all_findings))
        return all_findings

    # ── Graph Enrichment: Maltego-style entity discovery ──────────

    async def _run_graph_enrichment(
        self,
        surface_findings: list[Finding],
        query: str,
        profile,
        sse: SSEEmitter,
        target_types: list[str] | None = None,  # None = use default (domain/org only)
    ) -> list[Finding]:
        """Run entity graph + transform engine on findings.

        For domain/organization targets, this discovers infrastructure
        (subdomains, IPs, geolocation, emails) through recursive transforms
        and enriches findings with OSINT Framework tool links.

        When called post-deep (target_types=None), runs for ALL target types
        to extract any domains/orgs/emails discovered in earlier phases.

        Returns new Finding objects to add to the investigation.
        """
        # Determine eligible target types
        if target_types is None:
            # Post-deep mode: run for all target types
            eligible = True
        else:
            eligible = profile.target_type in target_types

        if not eligible:
            return []

        try:
            from ..graph import EntityGraph, TransformEngine
            from ..graph.osint_framework import get_framework
        except ImportError as e:
            logger.warning("graph_enrichment_import_failed: %s", e)
            return []

        sse.progress("surface", "→ Building entity graph from surface findings…")

        # 1. Create graph and ingest surface findings
        graph = EntityGraph()
        ingested = graph.ingest_findings(surface_findings, source_transform="surface_ingest")

        if ingested == 0:
            sse.progress("surface", "→ No entities extracted from surface findings — skipping graph enrichment")
            return []

        sse.progress(
            "surface",
            f"→ Extracted {ingested} entities from {len(surface_findings)} findings",
        )

        # 2. Add the primary target as a seed entity
        from ..graph.entities import EntityType
        if profile.target_type in ("domain", "company", "organization"):
            target_domain = query
            if profile.associated_domains:
                target_domain = profile.associated_domains[0]
            graph.add_or_get(
                EntityType.DOMAIN,
                target_domain,
                source="primary_target",
                confidence=1.0,
            )
        elif profile.target_type == "person":
            # For person targets, add the person as the central seed node.
            # The transforms will chain from any domains/emails discovered
            # in surface findings, and the person seed anchors the graph.
            graph.add_or_get(
                EntityType.PERSON,
                query,
                source="primary_target",
                confidence=1.0,
            )
        elif profile.target_type == "email":
            # For email targets, add the email as the central seed node.
            # Transforms will chain email→person→org from surface findings,
            # building a personal identity graph around the email address.
            graph.add_or_get(
                EntityType.EMAIL,
                query,
                source="primary_target",
                confidence=1.0,
            )

        # 3. Run transforms — depth varies by target type.
        # Domain/company targets benefit from full chain (domain→IP→geo).
        # Email/person targets should stop at identity level to avoid
        # chasing DNS/IP of unrelated domains from search snippets.
        # EXCEPTION: if criminal indicators triggered person escalation,
        # allow full transforms — cybercriminals own infrastructure.
        if profile.target_type in ("email", "person") and not getattr(self, "_person_escalated", False):
            max_depth = 1  # email→person or person→org only — no infrastructure drill-down
            # Skip domain→IP transforms. A Twitter bio mentioning a domain
            # should not trigger DNS resolution for ordinary people.
            from ..graph.entities import EntityType
            entity_types = [EntityType.PERSON, EntityType.EMAIL, EntityType.ORGANIZATION]
        else:
            max_depth = 3  # domain→email→person→org = 3 hops
            entity_types = None  # Run ALL transforms for full pivot chain
        sse.progress("surface", f"→ Running transforms (depth={max_depth})…")
        engine = TransformEngine(graph)

        try:
            new_count = await engine.run(
                max_depth=max_depth,
                entity_types=entity_types,
            )
        except Exception as e:
            logger.warning("graph_transform_failed: %s", e)
            new_count = 0

        sse.progress(
            "surface",
            f"→ Transforms discovered {new_count} new entities "
            f"(graph: {graph.entity_count} entities, {graph.relationship_count} relationships)",
        )

        # ── Stream graph to frontend for Maltego-style visualization ──
        try:
            # Send entities
            entity_data = []
            for e in graph.iter_entities():
                entity_data.append({
                    "id": e.id,
                    "type": e.entity_type.value if hasattr(e.entity_type, 'value') else str(e.entity_type),
                    "value": e.value,
                    "label": getattr(e, "display_name", e.value),
                    "source": e.source,
                    "confidence": getattr(e, "confidence", 1.0),
                })
            sse.emit("graph_entities", {
                "entities": entity_data,
                "total": len(entity_data),
            })

            # Send relationships
            rel_data = []
            for r in graph.iter_relationships():
                rel_data.append({
                    "source_id": r.source_id,
                    "target_id": r.target_id,
                    "type": r.rel_type,
                    "confidence": r.confidence,
                })
            sse.emit("graph_relations", {
                "relations": rel_data,
                "total": len(rel_data),
            })
        except Exception as e:
            logger.warning("graph_sse_stream_failed: %s", e)

        # 4. Reverse-pivot: feed discovered people into Watson's existing tools
        extra_findings: list[Finding] = []
        discovered_people = graph.entities_of_type(EntityType.PERSON)
        discovered_orgs = graph.entities_of_type(EntityType.ORGANIZATION)
        discovered_emails = graph.entities_of_type(EntityType.EMAIL)

        if discovered_people or discovered_orgs:
            sse.progress(
                "surface",
                f"→ Reverse pivot: investigating {len(discovered_people)} people, "
                f"{len(discovered_orgs)} organizations…",
            )

        # Feed each discovered PERSON into the existing people investigation pipeline
        for person in discovered_people[:5]:  # Limit to 5 to avoid explosion
            try:
                from ..tools.people import PeopleTool
                people_tool = PeopleTool()
                # Run HIBP + social + breach check on the person's name
                raw = await people_tool.investigate(person.display_name)
                for rf in raw:
                    f = self._tool_finding_to_engine(rf, phase="graph_enrich")
                    if f:
                        extra_findings.append(f)
                sse.progress(
                    "surface",
                    f"  → Investigated {person.display_name}: {len(raw)} findings",
                )
            except Exception as e:
                logger.warning("graph_person_investigate_failed: %s → %s", person.value, e)

        # Feed each discovered ORG into the existing corporate investigation pipeline
        for org in discovered_orgs[:3]:
            try:
                from ..tools.corporate import CorporateTool
                corp_tool = CorporateTool()
                raw = await corp_tool.investigate(org.display_name)
                for rf in raw:
                    f = self._tool_finding_to_engine(rf, phase="graph_enrich")
                    if f:
                        extra_findings.append(f)
                sse.progress(
                    "surface",
                    f"  → Investigated {org.display_name}: {len(raw)} findings",
                )
            except Exception as e:
                logger.warning("graph_org_investigate_failed: %s → %s", org.value, e)

        # Feed discovered EMAILs into HIBP/breach check
        for email_entity in discovered_emails[:5]:
            # Skip role-based emails that we already have
            if any(
                email_entity.value.lower().startswith(r)
                for r in ("admin@", "support@", "info@", "contact@", "hello@",
                          "noreply@", "no-reply@", "postmaster@", "abuse@",
                          "security@", "webmaster@", "hostmaster@", "billing@",
                          "jobs@", "sales@")
            ):
                continue
            try:
                from ..tools.people import PeopleTool
                people_tool = PeopleTool()
                raw = await people_tool.investigate(email_entity.value)
                for rf in raw:
                    f = self._tool_finding_to_engine(rf, phase="graph_enrich")
                    if f:
                        extra_findings.append(f)
                if raw:
                    sse.progress(
                        "surface",
                        f"  → Investigated {email_entity.value}: {len(raw)} findings",
                    )
            except Exception as e:
                logger.warning("graph_email_investigate_failed: %s → %s", email_entity.value, e)

        # 5. Convert graph discoveries to findings
        graph_findings = graph.to_findings(source_transform="graph_enrichment")

        # Convert dict findings to objects compatible with the engine pipeline
        # (the rest of the pipeline expects .title, .description attributes)
        converted_findings: list[Finding] = []
        for gf in graph_findings:
            try:
                from dataclasses import dataclass as _dc
                converted_findings.append(Finding(
                    title=gf.get("title", ""),
                    description=gf.get("description", ""),
                    source_type=gf.get("source", "graph_enrichment"),
                    source_url=gf.get("evidence", [None])[0] if gf.get("evidence") else "",
                    confidence=gf.get("confidence", 0.5),
                    phase="graph_enrich",
                ))
            except Exception:
                # Fallback: create a minimal finding
                converted_findings.append(Finding(
                    title=str(gf.get("title", "Graph discovery")),
                    description=str(gf.get("description", "")),
                    phase="graph_enrich",
                ))

        # 5. Enrich with OSINT Framework links
        framework = get_framework()
        for entity in graph.iter_entities():
            if entity.source in (
                "dns_resolution", "subdomain_enum", "ip_geolocation",
                "email_discovery", "graph_enrichment",
            ):
                # Add OSINT Framework tool links as evidence
                tools = framework.get_search_urls(
                    entity.entity_type,
                    entity.value,
                    max_results=5,
                )
                if tools:
                    # Attach to the entity's properties for the finding
                    entity.properties["osint_framework_tools"] = [
                        {"name": t["tool"], "url": t["url"]}
                        for t in tools
                    ]

        # Re-generate findings with enriched properties
        graph_findings = graph.to_findings(source_transform="graph_enrichment")

        # Merge graph findings with reverse-pivot extra findings
        all_graph_findings = converted_findings + extra_findings

        logger.info(
            "graph_enrichment_complete: ingested=%d graph_new=%d extra=%d total=%d findings=%d",
            ingested, new_count, len(extra_findings),
            graph.entity_count, len(all_graph_findings),
        )

        return all_graph_findings

    # ── Phase 3: Identifier Pivoting ──────────────────────────

    async def _phase_pivot(self, query: str, profile,
                           context: str, sse: SSEEmitter) -> list[Finding]:
        """Identifier pivoting — REAL tools: HIBP, OpenSanctions, blockchain + LLM analysis."""
        sse.phase_start("pivot", "Identifier Pivoting — HIBP, OpenSanctions, blockchain…")
        sse.progress("pivot", f"Pivoting from {len(context.split(chr(10))) if context else 0} lines of context")

        tool_findings: list[Finding] = []

        # Crypto targets: run blockchain tool (Etherscan/Blockscout + Blockchain.info)
        if profile.target_type == "wallet" or query.startswith("0x") or query.startswith("bc1"):
            sse.progress("pivot", "→ Blockchain wallet investigation…")
            try:
                from ..tools.blockchain import BlockchainTool
                chain_tool = BlockchainTool()
                raw_findings = await chain_tool.investigate(query)
                for rf in raw_findings:
                    f = self._tool_finding_to_engine(rf, phase="pivot")
                    if f:
                        tool_findings.append(f)
                        sse.finding(f)
                        sse.track_tool("blockchain", query)
            except Exception as e:
                logger.warning("blockchain_tool_failed: %s", e)

        # Email targets: run people tool (HIBP, email check, social enumeration)
        # Person targets: SKIP — PeopleTool does social media profiling
        # which is useless for criminals, sanctioned individuals, and private persons.
        # Person OSINT is handled by Wikipedia + OpenSanctions + web search.
        if profile.target_type == "email" or "@" in query:
            sse.progress("pivot", "→ HIBP breach check + email lookup…")
            try:
                from ..tools.people import PeopleTool
                people_tool = PeopleTool()
                raw_findings = await people_tool.investigate(query)
                for rf in raw_findings:
                    f = self._tool_finding_to_engine(rf, phase="pivot")
                    if f:
                        tool_findings.append(f)
                        sse.finding(f)
                        sse.track_tool("people", query)
            except Exception as e:
                logger.warning("people_tool_failed: %s", e)

        # All targets: OpenSanctions check
        # SKIP for company/org targets: Phase 2 scraper already ran this.
        # SKIP for wallet targets: 0x addresses are not entity names in sanctions DBs.
        # Only check sanctions for non-org, non-wallet targets.
        if profile.target_type not in ("company", "organization", "domain", "wallet"):
            sse.progress("pivot", "→ OpenSanctions check…")
            try:
                from ..tools.corporate import CorporateTool
                corp_tool = CorporateTool()
                sanctions_findings = await corp_tool._check_sanctions(profile.primary_name)
                for rf in sanctions_findings:
                    f = self._tool_finding_to_engine(rf, phase="pivot")
                    if f:
                        tool_findings.append(f)
                        sse.finding(f)
                        sse.track_tool("opensanctions", profile.primary_name)
            except Exception as e:
                logger.warning("sanctions_check_failed: %s", e)

        # All targets: Wikidata ownership + key people
        # Skip for wallet (not Wikidata entities) and person (slow, redundant with profile enrichment)
        if profile.target_type not in ("wallet", "person"):
            sse.progress("pivot", "→ Wikidata ownership + key people…")
            try:
                from ..tools.wikidata import WikidataTool
                wiki_tool = WikidataTool()
                wiki_findings = await wiki_tool.investigate(profile.primary_name)
                for rf in wiki_findings:
                    f = self._tool_finding_to_engine(rf, phase="pivot")
                    if f:
                        tool_findings.append(f)
                        sse.finding(f)
                        sse.track_tool("wikidata", profile.primary_name)
            except Exception as e:
                logger.warning("wikidata_pivot_failed: %s", e)

        # LLM analysis — skip for company/org, wallet, AND person (targeted DDG handles all)
        if profile.target_type not in ("company", "organization", "wallet", "person"):
            sse.progress("pivot", "→ Web search + LLM analysis…")
            prompt = _pivot_prompt(query, profile, context)
            raw = await self._investigation_call(prompt, phase="pivot", sse=sse)
            llm_findings = self._parse_findings(raw, phase="pivot")
        elif profile.target_type == "wallet":
            # Wallet targets: targeted claim verification via DDG (no LLM hallucination)
            sse.progress("pivot", "→ Claim verification + wallet investigation…")
            try:
                from ddgs import DDGS
                wallet_addr = query
                # Search for any mentions of this wallet in news/investigations
                search_queries = [
                    f'{wallet_addr} Alameda OR FTX',
                    f'{wallet_addr} investigation OR fraud OR scam',
                    f'{wallet_addr} wallet',
                ]
                def _ddg_search(q):
                    try:
                        with DDGS() as ddgs:
                            return list(ddgs.text(q, max_results=3))
                    except Exception:
                        return []
                all_raw = await asyncio.gather(*[
                    asyncio.to_thread(_ddg_search, q) for q in search_queries
                ])
                seen = set()
                wallet_findings = []
                for raw_list in all_raw:
                    for r in raw_list:
                        href = r.get("href", "")
                        if href and href not in seen:
                            seen.add(href)
                            wallet_findings.append(Finding(
                                title=f"🔍 {r.get('title', '')[:150]}",
                                description=r.get("body", "")[:300],
                                source_type="web_search",
                                source_url=href,
                                confidence=0.6,
                                phase="pivot",
                            ))
                for f in wallet_findings:
                    tool_findings.append(f)
                    sse.finding(f)
                    sse.track_tool("wallet_web_search", wallet_addr)
                if wallet_findings:
                    sse.progress("pivot", f"→ Found {len(wallet_findings)} wallet references")
            except Exception as e:
                logger.warning("wallet_web_search_failed: %s", e)
                llm_findings = []
        else:
            sse.progress("pivot", "→ Skipping LLM (Phase 2 surface already searched)")
            llm_findings = []

        all_findings = tool_findings + llm_findings
        sse.phase_done("pivot", len(all_findings))
        return all_findings

    # ── Phase 4: Deep Investigation ───────────────────────────

    async def _phase_deep(self, query: str, profile,
                          context: str, sse: SSEEmitter) -> list[Finding]:
        """Deep investigation — REAL tools: OpenCorporates, SEC EDGAR + LLM analysis."""
        sse.phase_start("deep", "Deep Investigation — OpenCorporates, sanctions, courts, media…")
        sse.progress("deep", f"Deep-diving with real API tools on: {query}")

        tool_findings: list[Finding] = []

        # Wallet targets: counterparty analysis + claim verification
        # No Wikidata/OpenCorporates/Shodan/MarineTraffic — those are irrelevant for 0x hashes.
        if profile.target_type == "wallet":
            sse.progress("deep", "→ Claim verification (news, investigations)…")

            # 1. Verify third-party claims via targeted DDG
            # Counterparty analysis is already done by the blockchain tool in Phase 3.
            # We only need to search for external mentions/claims about this wallet.
            try:
                from ddgs import DDGS
                wallet_addr = query
                claim_queries = [
                    f'{wallet_addr} Alameda Research FTX',
                    f'"{wallet_addr}" investigation',
                    f'{wallet_addr} scam OR hack OR stolen',
                ]
                def _ddg_search(q):
                    try:
                        with DDGS() as ddgs:
                            return list(ddgs.text(q, max_results=4))
                    except Exception:
                        return []
                all_raw = await asyncio.gather(*[
                    asyncio.to_thread(_ddg_search, q) for q in claim_queries
                ])
                seen = set()
                claim_findings = []
                for raw_list in all_raw:
                    for r in raw_list:
                        href = r.get("href", "")
                        if href and href not in seen:
                            seen.add(href)
                            claim_findings.append(Finding(
                                title=f"📰 {r.get('title', '')[:150]}",
                                description=r.get("body", "")[:300],
                                source_type="web_search",
                                source_url=href,
                                confidence=0.6,
                                phase="deep",
                            ))
                for f in claim_findings:
                    tool_findings.append(f)
                    sse.finding(f)
                    sse.track_tool("wallet_claim_verification", wallet_addr)
                if claim_findings:
                    sse.progress("deep", f"→ Found {len(claim_findings)} claim references")
                else:
                    sse.progress("deep", "→ No external claims found — wallet has no public footprint")
            except Exception as e:
                logger.warning("wallet_claim_verification_failed: %s", e)

            # Wallet: continue to infrastructure/LLM in deep_investigation mode
            # Only return early for due_diligence / background_check (which don't reach _phase_deep anyway)
            investig_mode = getattr(self, '_investigation_mode', '')
            if investig_mode != "deep_investigation":
                sse.phase_done("deep", len(tool_findings))
                return tool_findings
            sse.progress("deep", "→ Continuing to Wikidata, infrastructure, and LLM synthesis…")
        if profile.target_type == "email":
            sse.progress("deep", "→ Email deep check: Google profile + identity search…")

            # Google profile
            try:
                import httpx
                async with httpx.AsyncClient(timeout=10) as raw:
                    resp = await raw.get(
                        f"https://www.google.com/s2/photos/profile/{profile.primary_name}?sz=200",
                        headers={"User-Agent": "WatsonOSINT/0.3"},
                    )
                    if resp.status_code == 200 and len(resp.content) > 100:
                        tool_findings.append(Finding(
                            title=f"🖼 Google profile picture found for {profile.primary_name}",
                            description="A public Google profile is linked to this email address.",
                            source_type="google_profile",
                            confidence=0.85,
                            phase="deep",
                        ))
            except Exception:
                pass

            # Multi-query identity search — LinkedIn, GitHub, employer, pastebin
            # Direct DDG search WITHOUT LLM re-interpretation. The LLM hallucinates
            # "no matches found" even when DDG returns real results (DeepSeek V4).
            sse.progress("deep", "→ Identity search (LinkedIn, GitHub, employer, pastebin)…")
            try:
                email = profile.primary_name
                username = email.split("@")[0] if "@" in email else email
                from ddgs import DDGS

                # Build targeted search queries
                search_queries = [
                    f'{username} linkedin',
                    f'{username} github',
                    email,
                    f'{username} twitter OR x.com',
                ]

                def _ddg_search(q: str) -> list:
                    try:
                        with DDGS() as ddgs:
                            return list(ddgs.text(q, max_results=4))
                    except Exception:
                        return []

                all_raw = await asyncio.gather(*[
                    asyncio.to_thread(_ddg_search, q) for q in search_queries
                ])

                # Deduplicate by URL
                seen_urls = set()
                identity_findings = []
                for raw_list in all_raw:
                    for r in raw_list:
                        href = r.get("href", "")
                        if href and href not in seen_urls:
                            seen_urls.add(href)
                            title = r.get("title", "")[:150]
                            body = r.get("body", "")[:300]
                            # Create finding directly — no LLM hallucination
                            identity_findings.append(Finding(
                                title=f"🔍 {title}",
                                description=body,
                                source_type="web_search",
                                source_url=href,
                                confidence=0.6,
                                phase="deep",
                            ))

                for f in identity_findings:
                    tool_findings.append(f)
                    sse.finding(f)
                    sse.track_tool("identity_search", email)

                if identity_findings:
                    sse.progress("deep", f"→ Found {len(identity_findings)} identity references")
                else:
                    sse.progress("deep", "→ No identity references found")
            except Exception as e:
                logger.warning("email_identity_failed: %s", e)

            # Email: continue to Wikidata, infrastructure, LLM in deep_investigation mode
            investig_mode = getattr(self, '_investigation_mode', '')
            if investig_mode != "deep_investigation":
                sse.phase_done("deep", len(tool_findings))
                return tool_findings
            sse.progress("deep", "→ Continuing to Wikidata, infrastructure, and LLM synthesis…")
        if profile.target_type in ("company", "organization", "domain"):
            sse.progress("deep", "→ OpenCorporates registry search…")
            try:
                from ..tools.corporate import CorporateTool
                corp_tool = CorporateTool()
                raw_findings = await corp_tool.investigate(query)
                for rf in raw_findings:
                    f = self._tool_finding_to_engine(rf, phase="deep")
                    if f:
                        tool_findings.append(f)
                        sse.finding(f)
                        sse.track_tool("corporate", query)
            except Exception as e:
                logger.warning("corporate_tool_failed: %s", e)

            # Targeted DDG search — org name + person/controversy keywords
            sse.progress("deep", "→ Targeted research (news, controversies, key people)…")
            try:
                from ddgs import DDGS
                org_query = profile.primary_name or query
                search_queries = [
                    f'{org_query} CEO founder',
                    f'{org_query} lawsuit controversy investigation',
                    f'{org_query} sanctions OR fraud OR SEC fine',
                    f'{org_query} government contract military surveillance',
                    f'{org_query} data privacy FTC GDPR regulation',
                ]
                def _ddg_search(q):
                    try:
                        with DDGS() as ddgs:
                            return list(ddgs.text(q, max_results=4))
                    except Exception:
                        return []
                all_raw = await asyncio.gather(*[
                    asyncio.to_thread(_ddg_search, q) for q in search_queries
                ])
                seen = set()
                org_identity = []
                for raw_list in all_raw:
                    for r in raw_list:
                        href = r.get("href", "")
                        if href and href not in seen:
                            seen.add(href)
                            org_identity.append(Finding(
                                title=f"🔍 {r.get('title', '')[:150]}",
                                description=r.get("body", "")[:300],
                                source_type="web_search",
                                source_url=href,
                                confidence=0.6,
                                phase="deep",
                            ))
                for f in org_identity:
                    tool_findings.append(f)
                    sse.finding(f)
                    sse.track_tool("org_research", org_query)

                # Auto-detect key people from search results and flag for pivot
                people_found = set()
                for f in org_identity:
                    desc = (f.description or "") + (f.title or "")
                    for match in re.finditer(
                        r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b', desc
                    ):
                        name = match.group(1)
                        if name.lower() not in ('the', 'and', 'for', 'Inc', 'Llc'):
                            people_found.add(name)
                if people_found:
                    # Auto-pivot: run lightweight background checks on key employees
                    employee_findings = await self._auto_pivot_employees(
                        people_found, org_query, sse
                    )
                    if employee_findings:
                        tool_findings.extend(employee_findings)
            except Exception as e:
                logger.warning("org_ddg_search_failed: %s", e)

        # Person targets: OpenSanctions deep check via scraper
        if profile.target_type == "person":
            sse.progress("deep", "→ OpenSanctions deep scrape…")
            try:
                from ..tools.scraper import ScraperTool
                scraper = ScraperTool()
                sanctions_findings = await scraper._scrape_opensanctions(profile.primary_name)
                for rf in sanctions_findings:
                    f = self._tool_finding_to_engine(rf, phase="deep")
                    if f:
                        tool_findings.append(f)
                        sse.finding(f)
                        sse.track_tool("opensanctions_scrape", profile.primary_name)
            except Exception as e:
                logger.warning("sanctions_scrape_failed: %s", e)

            # Deep person search — mode-appropriate queries
            investig_mode = getattr(self, '_investigation_mode', '')
            
            if investig_mode == "deep_investigation" or self._person_escalated:
                # Run BOTH professional identity queries AND criminal/legal queries.
                # Professional queries establish the person's background (LinkedIn,
                # employment, board positions) — essential context even for criminal
                # investigations. Criminal queries add sanctions, court records, and
                # wanted notices. Without professional queries, deep investigations
                # miss entire professional profiles (e.g. "Marco Rossi" → only found
                # jail lookup sites, never discovered eurodefense.tech).
                search_label = "searching professional history + court records, legal databases"
                search_mode = "both"
            elif investig_mode == "due_diligence":
                # PROFESSIONAL/BUSINESS: employment, adverse media, regulatory
                search_label = "searching professional history, adverse media, regulatory"
                search_mode = "professional"
            else:
                search_label = None
                search_mode = None
            
            if search_label:
                sse.progress("deep", f"→ {search_label}…")
                try:
                    from ddgs import DDGS
                    person_name = profile.primary_name or query
                    
                    if search_mode == "criminal":
                        search_queries = [
                            f'"{person_name}" site:wikipedia.org',
                            f'"{person_name}" convicted OR sentenced OR prison',
                            f'"{person_name}" court OR trial OR guilty',
                            f'"{person_name}" arrested OR charged OR indictment',
                            f'"{person_name}" crime OR murder OR homicide',
                            f'"{person_name}" interpol OR wanted OR fugitive',
                        ]
                    elif search_mode == "professional":
                        search_queries = [
                            f'"{person_name}" linkedin professional',
                            f'"{person_name}" lawsuit OR controversy OR fraud',
                            f'"{person_name}" regulatory action OR fine OR penalty',
                            f'"{person_name}" board member OR executive OR director',
                            f'"{person_name}" adverse media OR negative news',
                        ]
                    elif search_mode == "both":
                        # Combine professional identity + criminal/legal queries.
                        # Professional queries map the person's employment, network,
                        # and affiliations (critical for any investigation). Criminal
                        # queries surface sanctions, court records, and wanted notices.
                        search_queries = [
                            # ── Professional identity ──
                            f'"{person_name}" linkedin professional',
                            f'"{person_name}" board member OR executive OR director',
                            f'"{person_name}" adverse media OR negative news',
                            # ── Criminal/legal ──
                            f'"{person_name}" site:wikipedia.org',
                            f'"{person_name}" convicted OR sentenced OR prison',
                            f'"{person_name}" arrested OR charged OR indictment',
                            f'"{person_name}" interpol OR wanted OR fugitive',
                            f'"{person_name}" lawsuit OR controversy OR fraud',
                        ]
                    # Add locale-specific queries if profile has location data
                    locale = _get_locale(profile, query)
                    if locale:
                        if search_mode == "criminal":
                            lk = locale.get("criminal_keywords", [])
                            nd = locale.get("news_domains", "")
                            if lk:
                                kw_query = " OR ".join(lk[:6])
                                search_queries.append(f'"{person_name}" {kw_query}')
                            if nd:
                                search_queries.append(f'"{person_name}" {nd}')
                        elif search_mode == "professional":
                            pk = locale.get("person_keywords", [])
                            nd = locale.get("news_domains", "")
                            if pk:
                                kw_query = " OR ".join(pk[:6])
                                search_queries.append(f'"{person_name}" {kw_query}')
                            if nd:
                                search_queries.append(f'"{person_name}" {nd}')
                        elif search_mode == "both":
                            # Add both criminal and professional locale queries
                            lk = locale.get("criminal_keywords", [])
                            pk = locale.get("person_keywords", [])
                            nd = locale.get("news_domains", "")
                            if lk:
                                kw_query = " OR ".join(lk[:6])
                                search_queries.append(f'"{person_name}" {kw_query}')
                            if pk:
                                kw_query = " OR ".join(pk[:6])
                                search_queries.append(f'"{person_name}" {kw_query}')
                            if nd:
                                search_queries.append(f'"{person_name}" {nd}')
                    def _ddg_search(q):
                        try:
                            with DDGS() as ddgs:
                                return list(ddgs.text(q, max_results=3))
                        except Exception:
                            return []
                    all_raw = await asyncio.gather(*[
                        asyncio.to_thread(_ddg_search, q) for q in search_queries
                    ])
                    # Deduplicate and collect for article reading
                    seen = set()
                    search_results = []
                    for raw_list in all_raw:
                        for r in raw_list:
                            href = r.get("href", "")
                            if href and href not in seen:
                                seen.add(href)
                                search_results.append(r)
                    
                    if search_results:
                        # Sort: Wikipedia first (richest source), then by relevance
                        search_results.sort(key=lambda r: 0 if "wikipedia.org" in r.get("href","") else 1)
                        
                        # ── Fetch full Wikipedia article in one pass (50k chars) ──
                        # This is THE single biggest improvement: instead of truncated snippets,
                        # the LLM gets the complete article and extracts every fact.
                        wiki_full_text = ""
                        try:
                            wiki_full_text = await self._fetch_wikipedia_full_text(person_name)
                            if wiki_full_text:
                                sse.progress("deep", 
                                    f"→ Wikipedia full text: {len(wiki_full_text)} chars — complete article")
                        except Exception as e:
                            logger.debug("wiki_full_fetch_failed: %s", e)
                        
                        # Read top 5 articles for deep analysis — need depth for criminal targets
                        sse.progress("deep", f"→ Reading {min(5, len(search_results))} articles for deep analysis…")
                        article_text = await self._read_top_articles(search_results, max_articles=5)
                        
                        # Prepend Wikipedia full text for complete extraction
                        if wiki_full_text:
                            article_text = wiki_full_text + "\n\n===SUPPLEMENTARY ARTICLES===\n" + (article_text or "")
                        
                        # LLM-powered extraction with full article text — 50k chars for depth
                        if article_text:
                            if search_mode in ("criminal", "both"):
                                prompt = (
                                    f"CRIMINAL/LEGAL DEEP DIVE: {person_name}\n\n"
                                    f"FULL ARTICLE TEXT:\n{article_text[:50000]}\n\n"
                                    f"Extract EVERY specific fact — names, dates, dollar amounts, locations:\n"
                                    f"1. CHARGES: Every specific charge (by statute name/number), indictment date, jurisdiction\n"
                                    f"2. TRIALS: Court name, judge name, trial dates, verdict date, every count\n"
                                    f"3. SENTENCING: Exact date, prison term length, prison name/location, inmate number\n"
                                    f"4. FINES/FORFEITURE: Exact dollar amounts, assets named\n"
                                    f"5. ESCAPES: Date, prison name, method, accomplices named, bribes paid\n"
                                    f"6. SANCTIONS: OFAC/UN/EU/Kingpin Act — exact designation date, program name\n"
                                    f"7. ASSOCIATES: Every named co-conspirator, cartel member, family member\n"
                                    f"8. FAMILY: Spouses by name, children by name, their legal status\n"
                                    f"9. ASSETS: Properties, companies, bank accounts, shell companies by name\n"
                                    f"10. NOVEL ANGLES: 3 investigation questions not answered in the text\n\n"
                                    f"For each: FINDING: fact | SOURCE: url | DATA: verbatim quote | TIER: PRIMARY/SECONDARY\n"
                                    f"Include dollar signs, dates in YYYY-MM-DD format, full names.\n\n"
                                    f"─── STAGE 2: CROSS-SOURCE SYNTHESIS ───\n"
                                    f"After extracting facts, identify the 5 most important connected entities\n"
                                    f"(people, companies, organizations, events) mentioned in the article.\n"
                                    f"For EACH connected entity, search the web and find:\n"
                                    f"- How they connect to {person_name}\n"
                                    f"- Their own criminal/legal status (sanctions, convictions, investigations)\n"
                                    f"- Any financial or operational links\n"
                                    f"Then report CROSS-CONNECTIONS: 'X was {person_name}'s front company →\n"
                                    f"X was also used by Y for Z → this means the network spans...'\n"
                                    f"Report as: CONNECTION: description | ENTITIES: A, B, C | SOURCES: url1, url2"
                                )
                            else:  # professional / due diligence
                                prompt = (
                                    f"PROFESSIONAL DUE DILIGENCE: {person_name}\n\n"
                                    f"FULL ARTICLE TEXT:\n{article_text[:5000]}\n\n"
                                    f"Extract all professional, business, and adverse media findings:\n"
                                    f"- Employment history, professional roles, board positions\n"
                                    f"- Business affiliations, corporate connections\n"
                                    f"- Lawsuits, regulatory actions, fines, penalties\n"
                                    f"- Controversies, negative media coverage, reputation issues\n"
                                    f"- Fraud allegations, ethics violations, professional misconduct\n"
                                    f"- Industry standing, notable achievements, credentials\n\n"
                                    f"For each finding, provide: FINDING: title | SOURCE: url | DATA: description | TIER: PRIMARY/SECONDARY\n"
                                    f"Only report verified facts from the articles. Skip speculation."
                                )
                            raw = await self._investigation_call(prompt, phase="deep_criminal", sse=sse)
                            parsed = self._parse_findings(raw, phase="deep")
                            for pf in parsed:
                                tool_findings.append(pf)
                                sse.finding(pf)
                        
                        # Also keep direct snippets as supporting evidence
                        for r in search_results[:10]:
                            f = Finding(
                                title=f"⚖️ {r.get('title', '')[:150]}",
                                description=r.get("body", "")[:300],
                                source_type="criminal_search",
                                source_url=r.get("href", ""),
                                confidence=0.65,
                                phase="deep",
                            )
                            tool_findings.append(f)
                            sse.finding(f)
                        
                        sse.progress("deep", f"→ Found {len(search_results)} criminal/legal references + LLM analysis")
                        sse.track_tool("criminal_deep_search", person_name)
                except Exception as e:
                    logger.warning("criminal_deep_search_failed: %s", e)

        # All targets: Wikidata structured intelligence (ownership, subsidiaries, sanctions)
        # Skip for person (Wikidata already queried during classification; person queries hang on location collisions)
        if profile.target_type not in ("person",):
            sse.progress("deep", "→ Wikidata structured intelligence…")
            try:
                from ..tools.wikidata import WikidataTool
                wiki_tool = WikidataTool()
                wiki_findings = await wiki_tool.investigate(query)
                for rf in wiki_findings:
                    f = self._tool_finding_to_engine(rf, phase="deep")
                    if f:
                        tool_findings.append(f)
                        sse.finding(f)
                        sse.track_tool("wikidata_deep", profile.primary_name)
            except Exception as e:
                logger.warning("wikidata_deep_failed: %s", e)

        # Location-aware targets: map strategic infrastructure
        # ONLY for company/org/domain with actual location data (profile.locations).
        # NEVER for person, email, wallet — geocoding person names produces garbage.
        infra_locations = list(profile.locations) if profile.locations else []
        if profile.target_type in ("person", "email", "wallet"):
            infra_locations = []  # infrastructure is irrelevant for these types
        elif profile.target_type in ("company", "organization") and not infra_locations:
            pass  # company without location data — skip infrastructure

        if infra_locations:
            sse.progress("deep", f"→ Infrastructure mapping near: {', '.join(infra_locations[:3])}…")
            try:
                from ..tools.geolocation import GeolocationTool
                geo_tool = GeolocationTool()
                for loc in infra_locations[:3]:
                    infra_findings = await geo_tool.investigate_infrastructure(loc)
                    for rf in infra_findings:
                        f = self._tool_finding_to_engine(rf, phase="deep")
                        if f:
                            tool_findings.append(f)
                            sse.finding(f)
                            sse.track_tool("geolocation_infra", loc)
            except Exception as e:
                logger.warning("geolocation_infra_failed: %s", e)

        # Paid API tools — Shodan infrastructure scan (if key configured)
        # Skip for targets without domains — Shodan needs IPs/hostnames to scan.
        # Persons, companies, orgs — all skip Shodan unless they have associated domains.
        skip_shodan = (
            profile.target_type in ("company", "organization", "person")
            and not profile.associated_domains
        )
        if not skip_shodan:
            sse.progress("deep", "→ Shodan infrastructure scan…")
            try:
                from ..tools.shodan import ShodanTool
                shodan = ShodanTool()
                shodan_findings = await shodan.investigate(query)
                for rf in shodan_findings:
                    f = self._tool_finding_to_engine(rf, phase="deep")
                    if f:
                        tool_findings.append(f)
                        sse.finding(f)
                        sse.track_tool("shodan", query)
            except Exception as e:
                logger.warning("shodan_tool_failed: %s", e)
        else:
            sse.progress("deep", "→ Skipping Shodan (no domains to scan)")

        # Paid API tools — MarineTraffic AIS (if key configured, for maritime targets)
        if profile.target_type in ("company", "organization"):
            maritime_keywords = ["shipping", "tanker", "vessel", "port", "maritime",
                                "fleet", "cargo", "shipowner", "sanctions evasion"]
            if any(kw in query.lower() for kw in maritime_keywords) or \
               any(kw in " ".join(profile.associated_orgs).lower() for kw in maritime_keywords):
                sse.progress("deep", "→ MarineTraffic AIS vessel tracking…")
                try:
                    from ..tools.marinetraffic import MarineTrafficTool
                    mt = MarineTrafficTool()
                    mt_findings = await mt.investigate(query)
                    for rf in mt_findings:
                        f = self._tool_finding_to_engine(rf, phase="deep")
                        if f:
                            tool_findings.append(f)
                            sse.finding(f)
                            sse.track_tool("marinetraffic", query)
                except Exception as e:
                    logger.warning("marinetraffic_tool_failed: %s", e)

        # LLM analysis — English + native-language queries in parallel
        # LLM web search: skip for person targets in ALL modes.
        # Person deep phase already runs targeted DDG + article reading + LLM extraction.
        # Company/org: skip in due_diligence (targeted DDG suffices), run in deep_investigation.
        investig_mode = getattr(self, '_investigation_mode', '')
        skip_llm = profile.target_type == "person" or (
            investig_mode != "deep_investigation"
            and profile.target_type in ("company", "organization")
        )
        if not skip_llm:
            sse.progress("deep", "→ Web search + LLM synthesis…")
            prompt = _deep_prompt(query, profile, context)
            
            languages = self._detect_languages(profile)
            tasks = [self._investigation_call(prompt, phase="deep", sse=sse)]
            
            if languages:
                sse.progress("deep", f"→ Native-language queries: {', '.join(languages)}")
                for lang in languages:
                    native_queries = self._build_native_queries(lang, profile.primary_name)
                    if native_queries:
                        native_query = " ; ".join(native_queries[:5])
                        native_prompt = _deep_prompt(query, profile, context)
                        native_prompt += f"\n\nCRITICAL: Search and analyze in {lang.upper()} language. "
                        native_prompt += f"Use these native-language search queries: {native_query}"
                        tasks.append(self._investigation_call(native_prompt, phase=f"deep_{lang}", sse=sse))
            
            results = await asyncio.gather(*tasks)
            llm_findings = []
            for raw in results:
                llm_findings.extend(self._parse_findings(raw, phase="deep"))
        else:
            sse.progress("deep", "→ Skipping LLM synthesis (due diligence — targeted search suffices)")
            llm_findings = []

        all_findings = tool_findings + llm_findings
        sse.phase_done("deep", len(all_findings))
        return all_findings

    # ── Auto-pivot: Company → Key Employees ──────────────────

    async def _auto_pivot_employees(
        self, people: set[str], org_query: str, sse: SSEEmitter
    ) -> list[Finding]:
        """Run lightweight person background checks on key employees detected
        during a company investigation. Uses passive DDG search only — no
        LinkedIn credentials, no scraping, fully enterprise-legal.

        Each person gets 2-3 targeted DDG queries (sanctions/controversy,
        professional profile, adverse media). Results are injected into the
        company investigation as phase='employee_pivot' findings.
        """
        if not people:
            return []

        # Filter noise — skip single-word names, common false positives
        _SKIP_WORDS = {
            "the", "and", "for", "inc", "llc", "ltd", "corp", "group",
            "holdings", "company", "limited", "plc", "gmbh", "sa", "ag",
            "technologies", "solutions", "systems", "services", "global",
            "international", "capital", "partners", "management", "security",
            "national", "united", "states", "america", "europe", "china",
        }
        names = sorted([
            n for n in people
            if " " in n  # must be multi-word
            and n.lower() not in _SKIP_WORDS
            and len(n.split()) >= 2
            and all(len(w) > 1 for w in n.split())
        ])
        if not names:
            return []

        top_names = names[:5]  # Cap at 5 to keep it fast
        sse.progress(
            "deep",
            f"→ Auto-pivoting to {len(top_names)} key people: "
            f"{', '.join(top_names[:3])}{'...' if len(top_names) > 3 else ''}",
        )

        findings: list[Finding] = []
        try:
            from ddgs import DDGS

            async def _check_person(name: str) -> list[Finding]:
                """Run 2-3 targeted DDG searches on a single person."""
                person_findings: list[Finding] = []

                queries = [
                    f'"{name}" sanctions OR controversy OR fraud OR investigation',
                    f'"{name}" linkedin OR github OR professional',
                    f'"{name}" wikipedia OR news',
                ]

                def _ddg_search(q: str) -> list:
                    try:
                        with DDGS() as ddgs:
                            return list(ddgs.text(q, max_results=3))
                    except Exception:
                        return []

                all_raw = await asyncio.gather(*[
                    asyncio.to_thread(_ddg_search, q) for q in queries
                ])

                seen: set[str] = set()
                for raw_list in all_raw:
                    for r in raw_list:
                        href = r.get("href", "")
                        if not href or href in seen:
                            continue
                        # Skip noise domains — business directories, aggregators
                        _NOISE = {
                            "yelp.", "tripadvisor.", "maps.google.", "facebook.com",
                            "instagram.com", "pinterest.", "yellowpages.", "manta.com",
                            "zoominfo.com", "rocketreach.", "signalhire.",
                        }
                        if any(d in href for d in _NOISE):
                            continue
                        seen.add(href)
                        title = r.get("title", "")[:150]
                        body = r.get("body", "")[:300]
                        person_findings.append(Finding(
                            id=f"emp-{uuid.uuid4().hex[:10]}",
                            title=f"👤 [{name}] {title}",
                            description=body,
                            source_type="employee_pivot",
                            source_url=href,
                            source_tier="SECONDARY",
                            confidence=0.55,
                            phase="employee_pivot",
                            entities=[{"name": name, "type": "person", "role": "key_employee"}],
                        ))

                return person_findings

            # Run all person checks in parallel
            all_person_findings = await asyncio.gather(*[
                _check_person(name) for name in top_names
            ])

            for pf_list in all_person_findings:
                for f in pf_list:
                    findings.append(f)
                    sse.finding(f)

            total = sum(len(pf) for pf in all_person_findings)
            if total:
                sse.progress(
                    "deep",
                    f"→ Employee pivot: {total} findings across {len(top_names)} key people",
                )
            else:
                sse.progress("deep", "→ Employee pivot: no public intel found on key people")

        except Exception as e:
            logger.warning("auto_pivot_employees_failed: %s", e)

        return findings

    # ── Auto-pivot: Person → OpenSanctions Re-query ───────────

    async def _auto_pivot_opensanctions(
        self, findings: list[Finding], query: str,
        primary_name: str, sse: SSEEmitter
    ) -> list[Finding]:
        """Scan findings for discovered full names and re-query OpenSanctions.

        When a person investigation starts with a partial name (e.g. first name +
        patronymic "Volodymyr Viktorovych" with no surname), the initial OpenSanctions
        API call returns noisy/generic results. The DDG deep search later discovers
        the full name ("Volodymyr Viktorovych Tymoshchuk"), but OpenSanctions is
        never re-queried with it.

        This method extracts all discovered person names from accumulated findings,
        compares them against the original query, and runs the OpenSanctions API for
        any NEW full names that contain criminal/sanctions signals. This ensures
        structured sanctions data (schema, datasets, topics, related entities) is
        surfaced for the actual target, not just raw web search results.
        """
        import re as _re

        # ── Step 1: Extract all person names from findings ──
        # Look for full names in finding titles, descriptions, and entity lists.
        # Ukrainian/Russian names use patronymics (Viktorovych, Ivanovich, etc.)
        # so we match 3-part names and 2-part names with criminal indicators.
        discovered_names: set[str] = set()

        for f in findings:
            # Collect text from title, description, and entities
            texts = [f.title or "", f.description or ""]
            for ent in (f.entities or []):
                if isinstance(ent, dict):
                    texts.append(ent.get("name", ""))
                elif isinstance(ent, str):
                    texts.append(ent)
            
            combined = " ".join(texts)
            
            # Extract name-like patterns from criminal/sanctions context
            # Match: "Volodymyr Viktorovych Tymoshchuk" (3-part naming)
            # Match: "Tymoshchuk, Volodymyr" (reverse)
            # Match: "Volodymyr Tymoshchuk" (2-part)
            for match in _re.finditer(
                r'\b([A-Z][a-zà-ü]+(?:\s+[A-Z][a-zà-ü]+){1,3})\b',
                combined
            ):
                name = match.group(1).strip()
                # Skip names that look like titles/orgs
                if len(name.split()) >= 2 and len(name) >= 8:
                    discovered_names.add(name)

        if not discovered_names:
            return []

        # ── Step 2: Filter to NEW names different from the original query ──
        query_lower = query.lower().strip()
        primary_lower = primary_name.lower().strip()

        new_names: list[str] = []
        for name in discovered_names:
            nl = name.lower()
            # Skip if it's just the original query with extra junk
            if nl == query_lower or nl == primary_lower:
                continue
            # Skip if the name IS the original query (original query is substring)
            # but only if the query is substantial (3+ words). A 2-word query like
            # "Volodymyr Viktorovych" shouldn't block "Volodymyr Viktorovych Tymoshchuk"
            query_words = query_lower.split()
            primary_words = primary_lower.split()
            if len(query_words) >= 3 and query_lower in nl:
                continue
            if len(primary_words) >= 3 and primary_lower in nl:
                continue
            # Include the name regardless — even if original query is a prefix
            new_names.append(name)

        if not new_names:
            return []

        # Deduplicate and keep unique names
        new_names = list(dict.fromkeys(new_names))  # preserve order, deduplicate

        # ── Step 3: Prioritize names with criminal/sanctions signals ──
        CRIMINAL_SIGNALS = [
            "sanction", "wanted", "fbi", "interpol", "indictment", "convicted",
            "sentenced", "arrested", "fugitive", "ransomware", "cybercriminal",
            "ofac", "red notice", "extradition", "fraud", "money laundering",
            "conspiracy", "prison", "charged", "guilty",
        ]
        
        priority_names: list[str] = []
        other_names: list[str] = []
        for name in new_names:
            nl = name.lower()
            # Check if any finding mentioning this name has criminal signals
            has_signal = False
            for f in findings:
                combined = (f.title or "") + " " + (f.description or "")
                if name.lower() in combined.lower():
                    if any(sig in combined.lower() for sig in CRIMINAL_SIGNALS):
                        has_signal = True
                        break
            if has_signal:
                priority_names.append(name)
            else:
                other_names.append(name)

        # Re-query OpenSanctions: priority names first, capped at 4 total
        names_to_query = priority_names[:3] + other_names[:1]
        names_to_query = names_to_query[:4]

        if not names_to_query:
            return []

        sse.progress(
            "deep",
            f"→ OpenSanctions auto-pivot: re-querying {len(names_to_query)} discovered names: "
            f"{', '.join(names_to_query[:2])}{'...' if len(names_to_query) > 2 else ''}",
        )

        # ── Step 4: Run OpenSanctions API for each discovered name ──
        pivot_findings: list[Finding] = []
        try:
            from ..tools.scraper import ScraperTool

            async def _os_query(name: str) -> list[Finding]:
                scraper = ScraperTool()
                return await scraper._scrape_opensanctions(name)

            all_results = await asyncio.gather(*[_os_query(n) for n in names_to_query])

            for name, result_list in zip(names_to_query, all_results):
                for rf in result_list:
                    f = self._tool_finding_to_engine(rf, phase="os_pivot")
                    if f:
                        # Tag as auto-pivot finding so synthesis knows this is structured data
                        f.title = f"🔄 [auto-pivot] {f.title}"
                        pivot_findings.append(f)
                        sse.finding(f)

            if pivot_findings:
                sse.progress(
                    "deep",
                    f"→ OpenSanctions auto-pivot: {len(pivot_findings)} structured findings "
                    f"from discovered names",
                )

        except Exception as e:
            logger.warning("auto_pivot_opensanctions_failed: %s", e)

        return pivot_findings

    # ── Phase 5: Dark Web ─────────────────────────────────────

    async def _phase_dark(self, query: str, profile, context: str, sse: SSEEmitter) -> list[Finding]:
        """Dark web investigation — REAL tools: ransomware.live, RansomWatch + LLM analysis."""
        sse.phase_start("dark", "Dark Web — ransomware.live, RansomWatch, pastebin…")

        tool_findings: list[Finding] = []

        # Run real darkweb tools
        sse.progress("dark", "→ ransomware.live + RansomWatch…")
        try:
            from ..tools.darkweb import DarkWebTool
            dark_tool = DarkWebTool()
            raw_findings = await dark_tool.investigate(query)
            for rf in raw_findings:
                f = self._tool_finding_to_engine(rf, phase="dark")
                if f:
                    tool_findings.append(f)
                    sse.finding(f)
                    sse.track_tool("darkweb", query)
        except Exception as e:
            logger.warning("darkweb_tool_failed: %s", e)

        # LLM analysis — English + native-language queries in parallel
        sse.progress("dark", "→ Web search + LLM analysis…")
        prompt = _dark_prompt(query, context)
        
        languages = self._detect_languages(profile) if hasattr(self, '_detect_languages') else []
        tasks = [self._investigation_call(prompt, phase="dark", sse=sse)]
        
        if languages:
            for lang in languages:
                native_queries = self._build_native_queries(lang, query)
                if native_queries:
                    native_query = " ; ".join(native_queries[:3])
                    native_prompt = _dark_prompt(query, context)
                    native_prompt += f"\n\nCRITICAL: Search and analyze in {lang.upper()} language. "
                    native_prompt += f"Use these native-language search queries: {native_query}"
                    tasks.append(self._investigation_call(native_prompt, phase=f"dark_{lang}", sse=sse))
        
        results = await asyncio.gather(*tasks)
        
        llm_findings = []
        for raw in results:
            llm_findings.extend(self._parse_findings(raw, phase="dark"))

        all_findings = tool_findings + llm_findings
        sse.phase_done("dark", len(all_findings))
        return all_findings

    # ── Phase 5.5: Cross-platform identity correlation ──────────

    @staticmethod
    def _correlate_identity(findings: list, query: str, sse) -> dict | None:
        """Cross-platform identity correlation for person/email targets.

        Extracts identity signals (names, usernames, emails, platforms,
        employers, locations) from findings and clusters them into
        confidence-scored identity groups.

        This answers: "Do all these profiles belong to the same person?"
        """
        import re as _re

        if not findings:
            return None

        # ── Extract signals from each finding ──
        signals: list[dict] = []
        for f in findings:
            title = getattr(f, "title", "") or ""
            desc = getattr(f, "description", "") or ""
            url = getattr(f, "source_url", "") or ""
            combined = f"{title} {desc}"

            sig: dict = {
                "finding_title": title[:100],
                "names": set(),
                "usernames": set(),
                "emails": set(),
                "platforms": set(),
                "locations": set(),
                "employers": set(),
            }

            # Extract emails
            for m in _re.finditer(r'[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}', combined):
                sig["emails"].add(m.group(0).lower())

            # Extract names (2-3 capitalized words)
            for m in _re.finditer(r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b', combined):
                name = m.group(1)
                if name.lower() not in ("the", "and", "for", "inc", "llc", "ltd", "corp", "gmbh"):
                    sig["names"].add(name)

            # Extract platforms from URLs
            for platform_domain in ["linkedin.com", "twitter.com", "x.com", "instagram.com",
                                      "github.com", "researchgate.net", "facebook.com",
                                      "tiktok.com", "youtube.com", "behance.net"]:
                if platform_domain in url.lower():
                    sig["platforms"].add(platform_domain)

            # Extract usernames (@handles)
            for m in _re.finditer(r'@(\w{3,30})', combined):
                sig["usernames"].add(m.group(1).lower())

            # Simple employer detection
            for kw in [" at ", " works at ", " google", " microsoft", " amazon", " apple",
                        " meta", " tesla", " openai", " linkedin"]:
                if kw in combined.lower():
                    # Crude but effective for now
                    pass

            signals.append(sig)

        # ── Score identity match between each pair ──
        matches: list[dict] = []
        for i in range(len(signals)):
            for j in range(i + 1, len(signals)):
                a, b = signals[i], signals[j]
                score = 0.0
                reasons: list[str] = []

                # Same email = near-certain match
                if a["emails"] & b["emails"]:
                    score = 1.0
                    reasons.append("shared email")
                # Same name
                elif a["names"] & b["names"]:
                    score += 0.6
                    reasons.append("shared name")
                    # Same name + same platform domain = higher confidence
                    if a["platforms"] & b["platforms"]:
                        score += 0.2
                        reasons.append("shared platform")
                # Same username across platforms
                elif a["usernames"] & b["usernames"]:
                    score += 0.8
                    reasons.append("shared username")

                if score >= 0.5:
                    matches.append({
                        "finding_a": a["finding_title"][:80],
                        "finding_b": b["finding_title"][:80],
                        "confidence": round(min(score, 1.0), 2),
                        "signals": reasons,
                    })

        if not matches:
            sse.progress("correlate", "→ No cross-platform identity matches found")
            return None

        # ── Report ──
        confirmed = [m for m in matches if m["confidence"] >= 0.9]
        probable = [m for m in matches if 0.7 <= m["confidence"] < 0.9]
        possible = [m for m in matches if 0.5 <= m["confidence"] < 0.7]

        sse.progress("correlate",
            f"→ Identity correlation: {len(confirmed)} confirmed, "
            f"{len(probable)} probable, {len(possible)} possible matches")

        return {
            "total_matches": len(matches),
            "confirmed": confirmed[:5],
            "probable": probable[:5],
            "possible": possible[:5],
            "summary": (
                f"Cross-platform identity correlation found {len(confirmed)} confirmed, "
                f"{len(probable)} probable, and {len(possible)} possible identity matches "
                f"across {len(signals)} signals."
            ) if matches else None,
        }

    # ── Phase 6: Analyze ──────────────────────────────────────

    async def _phase_analyze(self, query: str, focus: str,
                              findings: list[Finding], sse: SSEEmitter,
                              target_type: str = "",
                              graph_context: dict | None = None,
                              correlation: dict | None = None) -> dict | None:
        """Cross-reference, entity resolution, LLM synthesis."""
        if not findings:
            return None

        # Entity resolution
        try:
            from .resolution import build_intelligence_picture
            resolved, cross_refs = build_intelligence_picture(findings)
            if resolved and sse._on_event:
                # ── Cap entities to avoid JSON serialization blowout ──
                # Entity resolution can produce 100s of entities when PeopleTool
                # adds identity findings — json.dumps on 500+ nested entity dicts
                # chokes the SSE stream. Send top 100 by confidence, enough for
                # the frontend graph.
                sorted_entities = sorted(resolved, key=lambda e: e.confidence, reverse=True)
                capped = sorted_entities[:100]
                if len(resolved) > 100:
                    logger.info("entity_resolution_capped: %d → %d", len(resolved), len(capped))
                sse.emit("entity_resolution", {
                    "entities": [e.to_dict() for e in capped],
                    "total": len(resolved),
                    "capped": len(resolved) > 100,
                })
            if cross_refs and sse._on_event:
                # Cap cross-reference patterns too — rarely huge but be safe
                capped_refs = cross_refs[:200] if len(cross_refs) > 200 else cross_refs
                sse.emit("cross_reference", {
                    "patterns": capped_refs,
                    "total": len(cross_refs),
                    "capped": len(cross_refs) > 200,
                })
        except Exception as e:
            logger.warning("resolution_failed: %s", e)

        # Synthesis
        try:
            from .synthesis import synthesize_brief
            from .llm_config import call_llm
            brief = await synthesize_brief(
                query=query,
                focus=focus or query,
                findings=findings,
                call_llm=call_llm,
                target_type=target_type,
                executed_tools=sse.executed_tools,
                investigation_mode=getattr(self, '_investigation_mode', ''),
                graph_context=graph_context or {},
                correlation=correlation,
            )
            if brief and sse._on_event:
                sse.emit("brief", brief)
            return brief
        except Exception as e:
            logger.warning("synthesis_failed: %s", e)
            return None

    # ── Phase 6.5: Fill Evidence Gaps ──────────────────────────

    async def _phase_fill_gaps(
        self, query: str, focus: str,
        gaps: list[str], sse: SSEEmitter,
    ) -> list[Finding]:
        """Run targeted REAL tool calls to fill evidence gaps.

        Instead of generic web search, this dispatches to the appropriate
        real API tool for each gap type:
          - sanctions/OFAC → OpenSanctions scraper
          - corporate/registry/filing → OpenCorporates + SEC EDGAR
          - ownership/structure → Wikidata SPARQL
          - legal/court → web search (no PACER yet)
        """
        if not gaps:
            return []

        gap_findings: list[Finding] = []
        focus_name = focus or query

        # Filter out synthetic/fallback gap messages that are NOT real gaps.
        # These leak from synthesis fallback when LLM call fails.
        SYNTHETIC_GAP_PATTERNS = [
            "llm synthesis unavailable",
            "themes detected from finding titles only",
            "re-run for full ai analysis",
        ]
        real_gaps = [g for g in gaps[:3]
                     if not any(p in g.lower() for p in SYNTHETIC_GAP_PATTERNS)]
        if not real_gaps:
            sse.progress("gaps", "⏭ No actionable gaps (synthetic markers only)")
            return []

        for gap in real_gaps:
            gap_lower = gap.lower()

            # ── Sanctions gap → OpenSanctions + OpenCorporates ──
            if any(kw in gap_lower for kw in ("sanction", "ofac", "eu sanction", "un sanction",
                                                 "designation", "blacklist", "restricted",
                                                 "asset freeze", "travel ban", "interpol",
                                                 "red notice", "wanted", "extradition")):
                sse.progress("gaps", f"  → OpenSanctions check for: {gap[:80]}")
                try:
                    from ..tools.scraper import ScraperTool
                    scraper = ScraperTool()
                    findings = await scraper._scrape_opensanctions(focus_name)
                    for f_raw in findings:
                        f = self._tool_finding_to_engine(f_raw, phase="gap_fill")
                        if f:
                            gap_findings.append(f)
                            sse.finding(f)
                except Exception as e:
                    logger.warning("gap_sanctions_failed: %s", e)

            # ── Corporate/ownership gap → Wikidata + OpenCorporates ──
            elif any(kw in gap_lower for kw in ("corporate", "registry", "ownership",
                                                  "subsidiary", "structure", "filing",
                                                  "edgar", "shareholder", "beneficial")):
                sse.progress("gaps", f"  → Wikidata ownership for: {gap[:80]}")
                try:
                    from ..tools.wikidata import WikidataTool
                    wiki = WikidataTool()
                    findings = await wiki.investigate(focus_name)
                    for f_raw in findings:
                        f = self._tool_finding_to_engine(f_raw, phase="gap_fill")
                        if f:
                            gap_findings.append(f)
                            sse.finding(f)
                except Exception as e:
                    logger.warning("gap_wikidata_failed: %s", e)

                sse.progress("gaps", f"  → OpenCorporates search for: {gap[:80]}")
                try:
                    from ..tools.corporate import CorporateTool
                    corp = CorporateTool()
                    findings = await corp.investigate(focus_name)
                    for f_raw in findings:
                        f = self._tool_finding_to_engine(f_raw, phase="gap_fill")
                        if f:
                            gap_findings.append(f)
                            sse.finding(f)
                except Exception as e:
                    logger.warning("gap_corporate_failed: %s", e)

            # ── Legal/court gap → targeted web search ──
            elif any(kw in gap_lower for kw in ("legal", "court", "lawsuit", "litigation",
                                                  "ruling", "fine", "penalty", "verdict",
                                                  "conviction", "sentence", "prison", "incarceration",
                                                  "parole", "appeal", "indictment", "prosecution")):
                sse.progress("gaps", f"  → Legal research for: {gap[:80]}")
                try:
                    prompt = (
                        f"Find recent court rulings, legal cases, fines, or regulatory "
                        f"penalties involving {focus_name}. Focus on: {gap}\n"
                        f"Search for specific case numbers, amounts, dates. "
                        f"Return findings with source URLs."
                    )
                    raw = await self._investigation_call(prompt, phase="gap_legal", sse=sse)
                    if raw:
                        parsed = self._parse_findings(raw, phase="gap_fill")
                        gap_findings.extend(parsed)
                except Exception as e:
                    logger.warning("gap_legal_failed: %s", e)

            # ── Financial gap → SEC EDGAR + targeted search ──
            elif any(kw in gap_lower for kw in ("financial", "revenue", "profit", "asset",
                                                  "debt", "market cap", "valuation")):
                sse.progress("gaps", f"  → Financial search for: {gap[:80]}")
                try:
                    prompt = (
                        f"Find financial data for {focus_name}: {gap}\n"
                        f"Search for annual reports, SEC filings, investor presentations, "
                        f"or credible financial news with specific figures. "
                        f"Return findings with source URLs."
                    )
                    raw = await self._investigation_call(prompt, phase="gap_finance", sse=sse)
                    if raw:
                        parsed = self._parse_findings(raw, phase="gap_fill")
                        gap_findings.extend(parsed)
                except Exception as e:
                    logger.warning("gap_finance_failed: %s", e)

            # ── Generic fallback → targeted web search ──
            else:
                # Extract keywords from gap — never search for the gap text literally.
                # "No information on convictions" → search for "focus_name convictions"
                gap_keywords = gap.lower()\
                    .replace("no information on ", "")\
                    .replace("no verified ", "")\
                    .replace("no ", "")\
                    .replace("any ", "")\
                    .replace("the ", "")\
                    .strip(" .")
                search_query = f"{focus_name} {gap_keywords}" if gap_keywords else focus_name
                sse.progress("gaps", f"  → Targeted search for: {search_query[:80]}")
                try:
                    prompt = (
                        f"Search for: {search_query}\n"
                        f"Intelligence gap to fill: {gap}\n"
                        f"Find specific, verifiable data with source URLs. "
                        f"If the gap cannot be filled, say so clearly."
                    )
                    raw = await self._investigation_call(prompt, phase="gap_generic", sse=sse)
                    if raw:
                        parsed = self._parse_findings(raw, phase="gap_fill")
                        gap_findings.extend(parsed)
                except Exception as e:
                    logger.warning("gap_generic_failed: %s", e)

        return gap_findings

    # ── Phase 7: Report ───────────────────────────────────────

    def _phase_report(self, report: InvestigationReport) -> str:
        """Generate structured markdown intelligence report."""
        findings = report.findings
        total = len(findings)
        confirmed = sum(1 for f in findings if f.tier == "CONFIRMED")
        probable = sum(1 for f in findings if f.tier == "PROBABLE")
        possible = sum(1 for f in findings if f.tier == "POSSIBLE")
        primary = sum(1 for f in findings if f.source_tier == "PRIMARY")
        has_url = sum(1 for f in findings if f.source_url)

        # Verifiability score — weighted: URL sources + high-confidence tiers
        # Most OSINT findings are SECONDARY (news, Wikipedia) — PRIMARY tier
        # (court docs, sanctions lists) is rare. Weight PROBABLE heavily.
        report.verifiability_score = (
            0.25 * (primary / max(total, 1)) +
            0.25 * (has_url / max(total, 1)) +
            0.15 * (confirmed / max(total, 1)) +
            0.35 * (probable / max(total, 1))
        )

        lines = [
            f"# 🔍 Watson Intelligence Brief",
            f"",
            f"**Case ID:** {report.case_id}",
            f"**Date:** {report.created_at[:10]}",
            f"**Target:** {report.query}",
            f"**Target Type:** {report.target_type}",
            f"**Phases Completed:** {', '.join(report.phases_completed)}",
            f"**Findings:** {total} ({confirmed} CONFIRMED, {probable} PROBABLE, {possible} POSSIBLE)",
            f"**Verifiability:** {report.verifiability_score:.0%}",
            f"",
        ]

        # Brief summary
        if report.brief:
            lines.extend([
                f"## Executive Summary",
                f"",
                report.brief.get("executive_summary", "No summary available."),
                f"",
            ])

            risk_themes = report.brief.get("risk_themes", [])
            if risk_themes:
                lines.extend(["## Risk Themes", ""])
                for theme in risk_themes:
                    sev = theme.get("severity", "?")
                    badge = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(sev, "⚪")
                    lines.append(f"### {badge} {theme.get('theme', 'Theme')} — {sev}")
                    lines.append(theme.get("summary", ""))
                    lines.append("")

        # Key findings
        lines.extend(["## Key Findings", ""])
        for f in findings[:50]:
            icon = {"CONFIRMED": "🟢", "PROBABLE": "🟡",
                    "POSSIBLE": "🟠", "UNLIKELY": "🔴",
                    "UNSUBSTANTIATED": "⚪"}.get(f.tier, "⚪")
            lines.append(f"- {icon} **{f.title[:150]}** "
                         f"[{f.source_tier}] "
                         f"({f.confidence:.0%} confidence)")
            if f.description:
                desc = f.description[:1000].replace("\n", " ")
                lines.append(f"  {desc}")
            if f.source_url:
                lines.append(f"  Source: {f.source_url}")

        # Notable entities
        if report.brief:
            ents = report.brief.get("notable_entities", [])
            if ents:
                lines.extend(["", "## Notable Entities", ""])
                for e in ents:
                    lines.append(f"- **{e.get('name', '?')}** "
                                 f"({e.get('role', '?')}): {e.get('context', '')}")

        # Evidence gaps
        if report.brief:
            gaps = report.brief.get("evidence_gaps", [])
            if gaps:
                lines.extend(["", "## Evidence Gaps", ""])
                for g in gaps:
                    lines.append(f"- 🔍 {g}")

        # Next steps
        if report.brief:
            steps = report.brief.get("recommended_next_steps", [])
            if steps:
                lines.extend(["", "## Recommended Next Steps", ""])
                for s in steps:
                    if isinstance(s, dict):
                        lines.append(f"- **{s.get('entity', '?')}**: "
                                     f"{s.get('action', '?')} [{s.get('tool_hint', '?')}]")
                    else:
                        lines.append(f"- {s}")

        # Methodology
        lines.extend([
            "",
            "---",
            "",
            "## Methodology",
            "",
            f"**Pipeline:** 7-phase sequential OSINT (v4)",
            f"**Source Tiering:** Bazzell-standard (PRIMARY > SECONDARY > TERTIARY > UNVERIFIED)",
            f"**Phases executed:** {', '.join(report.phases_completed)}",
            f"**Confidence model:** Source tier × corroboration count × URL presence",
            "",
        ])

        # Source appendix
        urls = list(dict.fromkeys(f.source_url for f in findings if f.source_url))[:30]
        if urls:
            lines.extend(["## Source Appendix", ""])
            for url in urls:
                lines.append(f"- {url}")
            lines.append("")

        # Ethics
        lines.extend([
            "## Data Ethics & Methodology",
            "",
            "This investigation follows Bellingcat Digital Research Ethics Framework:",
            "",
            "- **Open Source**: All data from publicly available information",
            "- **Verification**: Multi-source cross-referencing applied",
            "- **Privacy**: PII redacted unless clearly in public interest",
            "- **Attribution**: Every finding carries source URL and timestamp",
            "- **Correction**: Errors promptly corrected when identified",
            "- **Proportionality**: Only relevant information included",
            "",
            f"Generated by Watson v4 | {report.created_at}",
        ])

        return "\n".join(lines)

    # ── Tool finding converter ────────────────────────────────

    _NEGATIVE_PATTERNS = [
        # Empty/no-result findings — these are API status, not intelligence
        r"^no\s+(dark[\s-]?web|ransomware|pastebin|results?)\s",
        r"^no\s+matches?\s+found",
        r"^no\s+records?\s+found",
        r"^no\s+results?\s+for",
        r"^could\s+not\s+(find|locate|retrieve)",
        r"^unable\s+to\s+(find|locate|retrieve)",
        r"^nothing\s+found",
        r"^search\s+returned\s+no\s+results",
        r"^no\s+information\s+available",
        r"^0\s+results?\s",
        # LLM summary headers that aren't actual findings
        r"^(summary|overview|conclusion|assessment)\s+of\s",
        r"^(executive|key)\s+(summary|findings|intelligence)",
        r"^confidence\s+assessment",
    ]

    @staticmethod
    def _is_negative_finding(title: str) -> bool:
        """Return True if a finding title is just an empty/negative API result."""
        title_lower = title.strip().lower()
        for pat in OrchestrationEngine._NEGATIVE_PATTERNS:
            if re.search(pat, title_lower):
                return True
        return False

    @staticmethod
    def _tool_finding_to_engine(tool_finding, phase: str = "") -> Finding | None:
        """Convert a pydantic/core Finding (from tools) to an engine Finding.
        
        Tool modules use the pydantic Finding from core/models.py.
        The engine uses its own dataclass Finding. This bridges them.
        """
        try:
            # Handle pydantic Finding (from core/models.py)
            title = getattr(tool_finding, "title", "") or ""
            description = getattr(tool_finding, "description", "") or ""

            # Reject negative/empty findings
            if OrchestrationEngine._is_negative_finding(title):
                return None

            confidence = getattr(tool_finding, "confidence", 0.5)
            evidence = getattr(tool_finding, "evidence", []) or []
            tool_name = getattr(tool_finding, "tool", "") or ""
            source = getattr(tool_finding, "source", None)
            source_val = source.value if hasattr(source, "value") else str(source) if source else "osint"
            
            # Map source to tier
            tier_map = {
                "corporate": "SECONDARY",
                "websites": "TERTIARY",
                "people": "SECONDARY",
                "osint": "SECONDARY",
                "socmint": "TERTIARY",
            }
            source_tier = tier_map.get(source_val, "SECONDARY")
            
            # Use first evidence URL as source_url
            source_url = ""
            if evidence and isinstance(evidence, list):
                for e in evidence:
                    if isinstance(e, str) and e.startswith("http"):
                        source_url = e
                        break
            
            # If no URL in evidence, check description for URLs
            if not source_url:
                urls = re.findall(r'https?://[^\s\)\]]+', description)
                if urls:
                    source_url = urls[0]

            # URL boost: tool findings with verified URLs are more reliable
            if source_url:
                confidence = min(0.99, confidence + 0.15)

            return Finding(
                title=f"[{tool_name}] {title}" if tool_name else title,
                description=description,
                source_url=source_url,
                source_tier=source_tier,
                confidence=confidence,
                source_type=tool_name or source_val,
                phase=phase,
            )
        except Exception as e:
            logger.warning("finding_convert_failed: %s", e)
            return None

    # ── Hermes subprocess call ────────────────────────────────

    async def _fetch_wikipedia_full_text(self, person_name: str) -> str:
        """Fetch the full Wikipedia article text for a person using the MediaWiki API.
        
        Returns the complete plain-text extract (up to 50k chars) — enough for the
        deep phase LLM to extract every fact instead of relying on truncated snippets.
        """
        import urllib.parse
        import httpx
        
        # Use the API to get the full page extract
        encoded = urllib.parse.quote(person_name)
        api_url = (
            f"https://en.wikipedia.org/w/api.php"
            f"?action=query&format=json&prop=extracts"
            f"&titles={encoded}&explaintext=1&exintro=0"
            f"&redirects=1"
        )
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(api_url, headers={
                    "User-Agent": "WatsonOSINT/0.4 (research; contact@example.com)"
                })
                if resp.status_code != 200:
                    return ""
                data = resp.json()
                pages = data.get("query", {}).get("pages", {})
                for page_id, page in pages.items():
                    if page_id == "-1":
                        continue  # Page not found
                    extract = page.get("extract", "")
                    if extract:
                        return extract[:50000]  # Cap at 50k chars
        except Exception as e:
            logger.debug("wikipedia_full_text_failed: %s", e)
        return ""

    async def _investigation_call(
        self,
        prompt: str,
        phase: str = "",
        sse: SSEEmitter | None = None,
        timeout: int = 60,
    ) -> str:
        """Run an investigation phase using direct search + LLM reasoning.

        Two-step: search DuckDuckGo for real results, then pass them to
        the LLM for analysis. No Hermes subprocess, no tool-calling
        dependency — just real API calls.
        """
        import asyncio
        import os as _os

        if sse:
            sse.progress(phase, f"  → Searching + reasoning…")

        # Step 1: Search DuckDuckGo — run queries in target's native language(s) too
        search_results = []
        search_query = ""
        try:
            from ddgs import DDGS
            # Extract the base search query and generate multilingual variants
            search_query = self._extract_search_query(prompt)
            if not search_query:
                search_query = prompt.split("\n")[0][:200]

            # Parse profile context from the prompt for language inference
            search_queries = self._build_search_queries(search_query, prompt)

            def _search(q: str) -> list:
                try:
                    with DDGS() as ddgs:
                        return list(ddgs.text(q, max_results=6))
                except Exception:
                    return []

            loop = asyncio.get_event_loop()
            # Run all queries in parallel
            all_raw = await asyncio.gather(*[
                loop.run_in_executor(None, _search, q) for q in search_queries
            ])
            # Merge and deduplicate by URL
            seen = set()
            for raw_list in all_raw:
                for r in raw_list:
                    href = r.get("href", "")
                    if href and href not in seen:
                        seen.add(href)
                        search_results.append({
                            "title": r.get("title", "")[:200],
                            "body": r.get("body", "")[:600],
                            "href": href,
                        })
            # Limit to 12 total across all languages
            search_results = search_results[:12]

            if sse and search_results:
                sse.progress(phase, f"  → Found {len(search_results)} search results")
        except ImportError:
            pass
        except Exception as e:
            logger.warning("search_failed: phase=%s error=%s", phase, e)

        # Step 2: Build LLM prompt with search results
        search_context = ""
        if search_results:
            search_context = "SEARCH RESULTS:\n"
            for i, r in enumerate(search_results, 1):
                search_context += f"[{i}] {r['title']}\n    {r['body']}\n    URL: {r['href']}\n\n"

        # Step 2.5: Read top non-Wikipedia articles for deeper context
        article_context = ""
        if search_results:
            article_context = await self._read_top_articles(search_results, max_articles=3)
            if article_context:
                article_context = "FULL ARTICLE TEXT:\n" + article_context

        full_prompt = f"""{prompt}
{self._user_context if self._user_context else ""}
{search_context}
{article_context}
Analyze the search results above. Extract intelligence findings, source URLs,
and confidence assessments. Follow the OUTPUT FORMAT specified above."""

        # Step 3: Call LLM for analysis — but skip if no search results AND no
        # structured data from earlier phases to analyze (prevents LLM refusal noise
        # when the LLM has nothing to work with)
        if not search_results:
            logger.info("no_search_results: phase=%s query=%s — skipping LLM call",
                       phase, search_query[:100] if search_query else "unknown")
            # Return a minimal structured response rather than feeding an empty
            # prompt to the LLM (which produces refusal meta-commentary)
            return ""

        try:
            return await self._call_llm(full_prompt, max_tokens=4000, timeout=timeout)
        except Exception as e:
            logger.warning("llm_call_failed: phase=%s error=%s", phase, e)
            # Return search results directly if LLM fails
            if search_context:
                return f"SEARCH RESULTS (LLM analysis unavailable):\n{search_context}"
            return ""

    @staticmethod
    def _extract_search_query(prompt: str) -> str:
        """Extract the best search query from the investigation prompt."""
        # Try to find TARGET: or quoted phrases
        import re
        target_match = re.search(r'TARGET:\s*(.+?)(?:\n|$)', prompt)
        if target_match:
            return target_match.group(1).strip()

        # Find quoted phrases
        quoted = re.findall(r'"([^"]+)"', prompt)
        if quoted:
            return " ".join(quoted[:3])

        # First non-instruction line
        lines = [l.strip() for l in prompt.split("\n") if l.strip()
                and not l.startswith(("You are", "TARGET:", "TYPE:", "OBJECTIVES:",
                                     "SEARCH STRATEGY:", "PREVIOUS", "For each"))]
        if lines:
            return lines[0][:200]

        return prompt[:200]

    # ── Multilingual OSINT query engine ─────────────────────────
    # Maps countries to language codes with deep OSINT query patterns.
    # Each language gets three categories of search terms:
    #   crime    — criminal investigation (murder, arrest, trial, conviction)
    #   corp     — corporate/financial (sanctions, shell companies, money laundering)
    #   political — state-linked, party affiliation, government position
    #
    # Russian, Chinese, and Arabic get extended patterns because they're
    # critical for sanctions evasion, state-linked entities, and opaque
    # corporate structures.

    def _detect_languages(self, profile) -> list[str]:
        """Detect native languages to query based on target profile locations and aliases.
        
        Returns a list of language codes (e.g. ['ru', 'zh']) for which native-language
        OSINT queries should be run in parallel with English queries.
        """
        detected: list[str] = []
        locations = [loc.lower() for loc in (profile.locations or [])]
        aliases = [a.lower() for a in (profile.known_aliases or [])]
        orgs = [o.lower() for o in (profile.associated_orgs or [])]
        all_text = " ".join(locations + aliases + orgs)
        
        for lang_code, lang_data in self._LANG_PROFILES.items():
            countries = lang_data.get("countries", [])
            # Check if any country from the profile is in this language's country list
            for country in countries:
                if country in all_text:
                    if lang_code not in detected:
                        detected.append(lang_code)
                    break
        
        # Also detect Cyrillic, CJK, or Arabic characters in aliases AND target name
        all_names = list(profile.known_aliases or []) + [profile.primary_name or ""]
        for name in all_names:
            if any('\u0400' <= c <= '\u04ff' for c in name) and 'ru' not in detected:
                detected.insert(0, 'ru')  # Russian priority
            if any('\u4e00' <= c <= '\u9fff' for c in name) and 'zh' not in detected:
                detected.insert(0, 'zh')  # Chinese priority
            if any('\u0600' <= c <= '\u06ff' for c in name) and 'ar' not in detected:
                detected.insert(0, 'ar')  # Arabic priority
            # Hungarian-specific: ő, ű characters
            if any(c in name for c in 'őŐűŰ') and 'hu' not in detected:
                detected.insert(0, 'hu')
            # Czech/Slovak: ě, š, č, ř, ž, ý, á, í, é, ď, ť, ň, ů
            if any(c in name for c in 'ěščřžýáíéďťňůĚŠČŘŽÝÁÍÉĎŤŇŮ') and 'cs' not in detected:
                detected.insert(0, 'cs')
            # Romanian: ă, â, î, ș, ț
            if any(c in name for c in 'ăâîșțĂÂÎȘȚ') and 'ro' not in detected:
                detected.insert(0, 'ro')
            # Turkish: ı, ğ, ş, ç, ö, ü (dotless i)
            if any(c in name for c in 'ığşçöüİĞŞÇÖÜ') and 'tr' not in detected:
                detected.insert(0, 'tr')
            # Polish: ą, ć, ę, ł, ń, ó, ś, ź, ż
            if any(c in name for c in 'ąćęłńóśźżĄĆĘŁŃÓŚŹŻ') and 'pl' not in detected:
                detected.insert(0, 'pl')
            # German: ö, ü, ä, ß
            if any(c in name for c in 'öüäßÖÜÄẞ') and 'de' not in detected:
                detected.insert(0, 'de')
        
        logger.info("detected_languages", extra={"languages": detected, "locations": locations[:3]})
        return detected

    def _build_native_queries(self, lang_code: str, query: str) -> list[str]:
        """Build native-language OSINT search queries for a given language."""
        lang_data = self._LANG_PROFILES.get(lang_code)
        if not lang_data:
            return []
        
        queries = []
        for category in ("crime", "corp", "political"):
            for template in lang_data.get(category, []):
                queries.append(template.replace("{q}", query))
        return queries

    _LANG_PROFILES: dict[str, dict] = {
        # ── Priority: Russian (sanctions evasion, shell companies, state contracts) ──
        "ru": {
            "countries": ["russia", "russian federation", "moscow", "ussr", "soviet",
                         "belarus", "ukraine", "kazakhstan", "kyrgyzstan", "uzbekistan",
                         "tajikistan", "turkmenistan", "armenia", "azerbaijan", "georgia",
                         "moldova", "chechnya", "dagestan", "tatarstan"],
            "crime": [
                "{q} приговор суд",          # conviction, court
                "{q} убийство расследование", # murder, investigation
                "{q} арест задержание",       # arrest, detention
                "{q} уголовное дело",          # criminal case
            ],
            "corp": [
                "{q} офшор компания",         # offshore company
                "{q} санкции OFAC",            # sanctions OFAC
                "{q} отмывание денег",         # money laundering
                "{q} бенефициар владелец",     # beneficiary, owner
                "{q} гендиректор учредитель",   # CEO, founder
            ],
            "political": [
                "{q} государственный контракт", # state contract
                "{q} единая россия чиновник",   # United Russia, official
                "{q} ФСБ МВД связан",           # FSB, Interior Ministry, linked
            ],
        },
        # ── Priority: Chinese (SOEs, Belt & Road, opaque corporate, WeChat ecosystem) ──
        "zh": {
            "countries": ["china", "people's republic of china", "beijing", "shanghai",
                         "hong kong", "taiwan", "macau", "guangdong", "shenzhen",
                         "singapore", "malaysia"],
            "crime": [
                "{q} 判决 法院",               # verdict, court
                "{q} 逮捕 调查",               # arrest, investigation
                "{q} 刑事案件",                 # criminal case
            ],
            "corp": [
                "{q} 离岸公司 壳公司",          # offshore company, shell company
                "{q} 制裁 OFAC 实体制裁",       # sanctions, OFAC, entity sanctions
                "{q} 洗钱 非法资金",            # money laundering, illicit funds
                "{q} 法人代表 股东 实际控制人",  # legal rep, shareholder, beneficial owner
                "{q} 注册资本 工商信息",         # registered capital, business registry
            ],
            "political": [
                "{q} 一带一路 国家项目",         # Belt & Road, state project
                "{q} 国企 央企 国有资产",        # SOE, central enterprise, state assets
                "{q} 共产党 政府 官员",          # Communist Party, government, official
                "{q} 军工 涉密 敏感",            # military industry, classified, sensitive
            ],
        },
        # ── Priority: Arabic (RTL script, sanctions, regional media, different dialects) ──
        "ar": {
            "countries": ["saudi arabia", "uae", "united arab emirates", "qatar", "kuwait",
                         "bahrain", "oman", "yemen", "egypt", "jordan", "lebanon", "syria",
                         "iraq", "libya", "algeria", "morocco", "tunisia", "sudan",
                         "palestine", "dubai", "abu dhabi", "riyadh", "cairo", "doha",
                         "middle east", "arab"],
            "crime": [
                "{q} حكم محكمة",                # court verdict
                "{q} تحقيق جنائي",              # criminal investigation
                "{q} اعتقال توقيف",              # arrest, detention
                "{q} قضية جنائية",               # criminal case
            ],
            "corp": [
                "{q} شركة وهمية offshore",       # shell company, offshore (mixed Arabic/English)
                "{q} عقوبات دولية تجميد أصول",    # international sanctions, asset freeze
                "{q} غسيل أموال تمويل",           # money laundering, financing
                "{q} مالك مستفيد حقيقي",          # owner, beneficial owner
                "{q} سجل تجاري شركة",             # commercial registry, company
            ],
            "political": [
                "{q} عقد حكومي مناقصة",           # government contract, tender
                "{q} مسؤول حكومي وزير",           # government official, minister
                "{q} جهاز أمن استخبارات",         # security apparatus, intelligence
                "{q} حزب سياسي ارتباطات",          # political party, connections
            ],
        },
        # ── Expanded: Italian ──
        "it": {
            "countries": ["italy"],
            "crime": [
                "{q} condanna ergastolo",               # life sentence
                "{q} omicidio processo indagine",        # murder, trial, investigation
                "{q} arresto mandato cattura",           # arrest, arrest warrant
                "{q} mafia ndrangheta camorra",          # mafia, 'ndrangheta, camorra
                "{q} processo penale appello",           # criminal trial, appeal
            ],
            "corp": [
                "{q} società offshore schermo",          # offshore shell company
                "{q} riciclaggio denaro indagine",       # money laundering, investigation
                "{q} sanzioni OFAC UE",                  # sanctions OFAC EU
                "{q} titolare effettivo prestanome",     # beneficial owner, front man
                "{q} appalto pubblico corruzione",       # public contract, corruption
            ],
            "political": [
                "{q} corruzione politica indagine",      # political corruption, investigation
                "{q} finanziamento illecito partito",    # illicit party financing
            ],
        },
        # ── Expanded: French (Francophone Africa priority — DRC, Mali, Sahel, etc.) ──
        "fr": {
            "countries": ["france", "belgium", "switzerland", "luxembourg", "monaco",
                         "democratic republic of the congo", "drc", "congo", "rwanda",
                         "burundi", "mali", "burkina faso", "senegal", "ivory coast",
                         "côte d'ivoire", "niger", "chad", "cameroon", "gabon",
                         "central african republic", "benin", "togo", "guinea",
                         "madagascar", "djibouti", "morocco", "algeria", "tunisia",
                         "mauritania", "haiti", "quebec", "montreal"],
            "crime": [
                "{q} exploitation illégale mines",       # illegal mining
                "{q} groupe armé contrôle",              # armed group, control
                "{q} contrebande trafic minerais",       # smuggling, mineral trafficking
                "{q} effondrement mine morts",           # mine collapse, deaths
                "{q} condamnation crime guerre",         # war crimes conviction
                "{q} enquête criminelle CPI",            # ICC criminal investigation
                "{q} mandat arrêt international",        # international arrest warrant
            ],
            "corp": [
                "{q} société écran offshore",            # shell company, offshore
                "{q} blanchiment d'argent",              # money laundering
                "{q} sanctions internationale",          # international sanctions
                "{q} chaîne approvisionnement minerais", # mineral supply chain
                "{q} certification ITSCI traçabilité",   # ITSCI certification, traceability
                "{q} bénéficiaire effectif société",     # beneficial owner
                "{q} paradis fiscal enregistrement",     # tax haven registration
            ],
            "political": [
                "{q} contrat minier gouvernement",       # mining contract, government
                "{q} corruption ministère mines",        # corruption, ministry of mines
                "{q} financement groupe armé",           # armed group financing
                "{q} conseil sécurité ONU rapport",      # UN Security Council report
                "{q} sanctions UE gel avoirs",           # EU sanctions, asset freeze
            ],
        },
        # ── Expanded: Spanish (Latin America priority — cartels, sanctions, corruption) ──
        "es": {
            "countries": ["spain", "españa", "mexico", "méxico", "colombia", "venezuela",
                         "argentina", "chile", "peru", "perú", "ecuador", "bolivia",
                         "paraguay", "uruguay", "cuba", "panama", "panamá", "costa rica",
                         "nicaragua", "honduras", "el salvador", "guatemala",
                         "dominican republic", "república dominicana", "puerto rico",
                         "equatorial guinea", "guinea ecuatorial", "belize"],
            "crime": [
                "{q} cartel narcotráfico",               # cartel, drug trafficking
                "{q} lavado dinero investigación",       # money laundering, investigation
                "{q} desaparición forzada caso",         # forced disappearance, case
                "{q} homicidio juicio condena",          # homicide, trial, conviction
                "{q} extorsión secuestro grupo",         # extortion, kidnapping, group
                "{q} contrabando minería ilegal",        # smuggling, illegal mining
                "{q} tráfico armas investigación",       # arms trafficking, investigation
            ],
            "corp": [
                "{q} empresa fantasma offshore",          # shell company, offshore
                "{q} sanciones OFAC lista negra",        # OFAC sanctions, blacklist
                "{q} blanqueo capitales investigación",  # capital laundering, investigation
                "{q} testaferro beneficiario real",      # front man, beneficial owner
                "{q} registro mercantil paraíso fiscal", # commercial registry, tax haven
                "{q} minería ilegal exportación",        # illegal mining, export
                "{q} corrupción contrato público",       # corruption, public contract
            ],
            "political": [
                "{q} contrato estatal corrupción",       # state contract, corruption
                "{q} financiación campaña ilegal",       # illegal campaign financing
                "{q} funcionario público investigación", # public official, investigation
                "{q} sanciones internacionales bloqueo", # international sanctions, blockage
                "{q} vínculos gobierno grupo armado",    # government links, armed group
                "{q} lavado activos corrupción política",# asset laundering, political corruption
            ],
        },
        "de": {
            "countries": ["germany"],
            "crime": ["{q} Verurteilung Mord", "{q} Prozess Ermittlung"],
            "corp": ["{q} Briefkastenfirma Offshore", "{q} Geldwäsche", "{q} Sanktionen"],
            "political": ["{q} Staatsauftrag", "{q} politische Korruption"],
        },
        "es": {
            "countries": ["spain", "mexico", "argentina", "colombia", "chile", "venezuela",
                         "peru", "cuba"],
            "crime": ["{q} condena asesinato", "{q} juicio investigación"],
            "corp": ["{q} empresa fantasma offshore", "{q} lavado dinero", "{q} sanciones"],
            "political": ["{q} contrato público", "{q} corrupción política"],
        },
        "pt": {
            "countries": ["brazil", "portugal"],
            "crime": ["{q} condenação homicídio", "{q} julgamento investigação"],
            "corp": ["{q} empresa de fachada offshore", "{q} lavagem dinheiro", "{q} sanções"],
            "political": ["{q} contrato público licitação", "{q} corrupção política"],
        },
        # ── Extended: Other regions ──
        "ja": {
            "countries": ["japan"],
            "crime": ["{q} 判決 裁判", "{q} 殺人 捜査"],
            "corp": ["{q} オフショア ペーパーカンパニー", "{q} 資金洗浄", "{q} 制裁"],
            "political": ["{q} 公共事業 入札", "{q} 政治資金"],
        },
        "ko": {
            "countries": ["korea", "south korea"],
            "crime": ["{q} 판결 법원", "{q} 살인 수사"],
            "corp": ["{q} 역외 페이퍼컴퍼니", "{q} 자금세탁", "{q} 제재"],
            "political": ["{q} 정부계약 입찰", "{q} 정치자금"],
        },
        "tr": {
            "countries": ["turkey"],
            "crime": ["{q} mahkumiyet mahkeme", "{q} cinayet soruşturma"],
            "corp": ["{q} paravan şirket offshore", "{q} kara para aklama", "{q} yaptırımlar"],
            "political": ["{q} kamu ihalesi", "{q} siyasi yolsuzluk"],
        },
        "pl": {
            "countries": ["poland"],
            "crime": ["{q} wyrok sąd", "{q} zabójstwo śledztwo"],
            "corp": ["{q} spółka fasadowa offshore", "{q} pranie pieniędzy"],
            "political": ["{q} zamówienie publiczne", "{q} korupcja polityczna"],
        },
        "nl": {
            "countries": ["netherlands", "holland"],
            "crime": ["{q} veroordeling rechtbank", "{q} moord onderzoek"],
            "corp": ["{q} brievenbusfirma offshore", "{q} witwassen", "{q} sancties"],
            "political": ["{q} overheidsopdracht", "{q} politieke corruptie"],
        },
        # ── Hungarian (EU, Central Europe — child custody, corporate, political) ──
        "hu": {
            "countries": ["hungary", "magyarország", "budapest"],
            "crime": [
                "{q} ítélet bíróság",                 # verdict, court
                "{q} körözés elfogatóparancs",         # warrant, arrest warrant
                "{q} bűnügy nyomozás",                 # criminal case, investigation
                "{q} letartóztatás őrizet",            # arrest, detention
                "{q} gyermekrablás ügy",               # child abduction case
            ],
            "corp": [
                "{q} offshore cég",                    # offshore company
                "{q} pénzmosás",                       # money laundering
                "{q} szankciók",                       # sanctions
                "{q} cégjegyzék tulajdonos",           # company registry, owner
                "{q} végrehajtás adósság",             # enforcement, debt
            ],
            "political": [
                "{q} közbeszerzés szerződés",          # public procurement, contract
                "{q} politikai korrupció",             # political corruption
            ],
        },
        # ── Czech/Slovak (Central Europe — EU, corporate registries) ──
        "cs": {
            "countries": ["czech republic", "czechia", "slovakia", "slovak"],
            "crime": [
                "{q} rozsudek soud",                   # verdict, court
                "{q} vyšetřování trestní",             # investigation, criminal
                "{q} zatčení vazba",                   # arrest, custody
            ],
            "corp": [
                "{q} offshore společnost",             # offshore company
                "{q} praní špinavých peněz",           # money laundering
                "{q} sankce obchodní rejstřík",        # sanctions, commercial registry
            ],
            "political": ["{q} veřejná zakázka", "{q} politická korupce"],
        },
        # ── Romanian (EU — Eastern Europe, cross-border crime) ──
        "ro": {
            "countries": ["romania", "moldova"],
            "crime": [
                "{q} condamnare instanță",             # conviction, court
                "{q} anchetă cercetare penală",        # investigation, criminal inquiry
                "{q} arestare mandat",                 # arrest, warrant
            ],
            "corp": [
                "{q} firmă fantomă offshore",          # shell company, offshore
                "{q} spălare de bani",                 # money laundering
                "{q} sancțiuni registrul comerțului",  # sanctions, trade registry
            ],
            "political": ["{q} achiziție publică", "{q} corupție politică"],
        },
    }

    @staticmethod
    def _infer_language(prompt: str) -> str | None:
        """Infer target language from prompt context (locations, org names)."""
        prompt_lower = prompt.lower()
        for lang, profile in OrchestrationEngine._LANG_PROFILES.items():
            for country in profile.get("countries", []):
                if country in prompt_lower:
                    return lang
        return None

    @staticmethod
    def _build_search_queries(base_query: str, prompt: str) -> list[str]:
        """Build OSINT search queries in English + target's native language(s).

        Always includes English base query. For Russian/Chinese/Arabic targets,
        adds deep OSINT queries spanning crime, corporate, and political domains.
        """
        queries = [base_query]
        lang = OrchestrationEngine._infer_language(prompt)
        if not lang:
            return queries

        profile = OrchestrationEngine._LANG_PROFILES.get(lang, {})
        # Russian/Chinese/Arabic get ALL categories (most important for OSINT)
        # Other languages get crime + corp only
        if lang in ("ru", "zh", "ar"):
            categories = ["crime", "corp", "political"]
            max_each = 2  # 2 queries per category = 6 native queries + English
        else:
            categories = ["crime", "corp"]
            max_each = 1  # 1 query per category = 2 native queries + English

        for cat in categories:
            terms = profile.get(cat, [])
            for t in terms[:max_each]:
                queries.append(t.format(q=base_query))

        return queries[:7]  # Cap at 7 total (English + up to 6 native)

    async def _read_top_articles(
        self, search_results: list[dict], max_articles: int = 3
    ) -> str:
        """Read the top non-Wikipedia articles from DDG search results.

        DDG snippets are only ~300 chars — nowhere near enough for the LLM to
        extract proper intelligence. This fetches full article text from the top
        results so the LLM has real content to work with.
        """
        import aiohttp
        import asyncio as _asyncio

        # Filter out Wikipedia, Reddit, social media, user-generated content.
        # Keep news sources in ALL languages — a real OSINT investigator
        # reads Italian, French, German, Spanish, etc. sources.
        skip_domains = {
            "wikipedia.org", "reddit.com", "facebook.com", "twitter.com",
            "x.com", "instagram.com", "youtube.com", "tiktok.com",
            "whatsmyname.app",
        }
        candidates = []
        for r in search_results:
            href = r.get("href", "")
            if not href.startswith("http"):
                continue
            domain = href.split("/")[2] if "/" in href else ""
            if any(sd in domain for sd in skip_domains):
                continue
            candidates.append(href)

        if not candidates:
            return ""

        texts = []
        timeout = aiohttp.ClientTimeout(total=15)

        async def _fetch(url: str, session: aiohttp.ClientSession) -> str:
            try:
                async with session.get(url, timeout=timeout, headers={
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9,it;q=0.9,fr;q=0.9,de;q=0.9,es;q=0.9,pt;q=0.9,ru;q=0.9",
                }) as resp:
                    if resp.status != 200:
                        return ""
                    html = await resp.text()
                    # Basic HTML text extraction
                    import re as _re
                    # Remove scripts and styles
                    html = _re.sub(r'<script[^>]*>.*?</script>', '', html, flags=_re.DOTALL | _re.IGNORECASE)
                    html = _re.sub(r'<style[^>]*>.*?</style>', '', html, flags=_re.DOTALL | _re.IGNORECASE)
                    # Strip all tags
                    text = _re.sub(r'<[^>]+>', ' ', html)
                    # Clean whitespace
                    text = _re.sub(r'\s+', ' ', text).strip()
                    # Truncate to 3000 chars — enough for detail, not too much token cost
                    return text[:3000]
            except Exception:
                return ""

        async with aiohttp.ClientSession() as session:
            tasks = [_fetch(url, session) for url in candidates[:max_articles]]
            results = await _asyncio.gather(*tasks)

        for i, (url, text) in enumerate(zip(candidates[:max_articles], results)):
            if text and len(text) > 100:
                texts.append(f"[Article {i+1}] {url}\n{text}\n")

        return "\n".join(texts) if texts else ""

    async def _call_llm(
        self, prompt: str, max_tokens: int = 4000, timeout: int = 60,
        system: str = "",
    ) -> str:
        """Call LLM via provider config for reasoning/synthesis.

        Uses the same provider as _phase_analyze (WATSON_LLM_PROVIDER env var).
        Falls back gracefully to empty string on any failure.
        """
        from .llm_config import call_llm

        if not system:
            system = "You are a professional OSINT intelligence analyst. Provide factual, sourced analysis. Never invent information."

        try:
            result = await call_llm(prompt, timeout=timeout, max_tokens=max_tokens, system=system)
            return result or ""
        except Exception as e:
            logger.warning("llm_call_failed: %s", e)
            return ""

    @staticmethod
    def _extract_response(raw: str) -> str:
        """Extract Hermes response from raw output (strip ANSI, UI chrome, XML blocks)."""
        # Strip ANSI escape codes
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean = ansi_escape.sub('', raw)

        # Strip ANSI cursor movement and carriage returns
        clean = re.sub(r'\r[^\n]', '', clean)
        clean = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', clean)

        # Remove XML/function-call blocks (model thinking about tools)
        clean = re.sub(r'<\s*function-call\s*>.*?<\s*/\s*function-call\s*>', '', clean, flags=re.DOTALL)
        clean = re.sub(r'<\s*function-results\s*.*?>.*?<\s*/\s*function-results\s*>', '', clean, flags=re.DOTALL)

        # Remove tool call JSON blocks
        clean = re.sub(r'\n\s*(?:search_web|read_url|browser_navigate|browser_snapshot)\s*\([^)]*\)\s*\n', '\n', clean)

        # Find the actual response content — look for "Hermes" header
        lines = clean.split("\n")
        content_lines = []
        in_response = False
        for line in lines:
            stripped = line.strip()
            # Skip UI chrome
            if not stripped:
                continue
            if any(skip in stripped for skip in [
                'Initializing agent', 'Query:', '───', '╚', '╔', '║',
                'Session:', 'Duration:', 'Messages:', 'Resume this',
                'hermes --resume', 'Iteration budget', '⚠',
                'hermes chat', 'Model:', 'Provider:',
            ]):
                continue
            if stripped.startswith('⚕') or stripped.startswith('┌') or stripped.startswith('└'):
                continue
            # Hermes response header
            if 'Hermes' in stripped and len(stripped) < 80:
                in_response = True
                continue
            if in_response or stripped:
                in_response = True
                content_lines.append(line)

        result = "\n".join(content_lines).strip()

        # If we got nothing useful, try removing all blank lines and UI noise
        if not result or len(result) < 20:
            meaningful = [l.strip() for l in lines if l.strip()
                         and not l.strip().startswith(('Query:', 'Initializing', '───', 'Session:',
                         'Duration:', 'Messages:', 'Resume', 'hermes --resume', 'Iteration', '⚠', '⚕'))]
            meaningful = [l for l in meaningful if len(l) > 3 and not l.startswith(('\x1b', '\r'))]
            result = "\n".join(meaningful)

        return result

    # ── Finding parsing ───────────────────────────────────────

    # Refusal / meta-commentary patterns: the LLM sometimes refuses to produce
    # intelligence and instead explains what input it needs, describes
    # methodology, or explains why it can't complete the request.
    # These are NOT findings — they're noise that must be filtered.
    # Also: broad catch for any finding that starts with "I " followed by
    # a capability/request verb (refusal pattern).
    _LLM_NOISE = re.compile(
        r"(I will now conduct|I will run|Since I cannot|I will simulate"
        r"|Based on the provided|NOTES FOR PHASE|NEW IDENTIFIERS PIVOTED"
        r"|SUMMARY OF NEXT PIVOTS|SUMMARY OF NEW IDENTIFIERS"
        r"|PHASE \d:|Phase \d:|^# PHASE \d"
        r"|I cannot complete this"
        r"|I cannot fabricate"
        r"|I would need you to"
        r"|Instruct me to simulate"
        r"|Provide the actual search"
        r"|If you can supply the raw"
        r"|To proceed with Phase"
        r"|you have not included any search"
        r"|you have provided a detailed methodology"
        r"|as an AI, I cannot execute"
        r"|I am unable to"
        r"|^I need you to"
        r"|^You have (?:provided|asked|given|shared)"
        r"|^I (?:cannot|can't|would need|require|must ask|am not|do not have)"
        r"|^Of course"
        r"|^Based on the (?:provided|search|findings|available)"
        # ── Universal LLM garbage patterns (from Volodymyr investigation and beyond) ──
        r"|^# (?:CRIMINAL|LEGAL|DEEP DIVE|INVESTIGATION|INTELLIGENCE|ANALYSIS)"
        r"|^EXECUTIVE SUMMARY"
        r"|^CONFIDENCE ASSESSMENT"
        r"|^CROSS[- ]CONNECTIONS REPORT"
        r"|^\d+\. (?:CHARGES|TRIALS|SENTENCING|FINES|FORFEITURE|ESCAPES|SANCTIONS|ASSOCIATES|FAMILY|ASSETS|NOVEL ANGLES)"
        r"|^Connected Entity \d+:"
        r"|^Connected Entity Analysis"
        r"|^\|\s*FINDING\s*\|"  # Markdown tables
        r"|^\|\s*CONNECTION\s*\|"
        r"|^Question \d+: What"
        r"|^No (?:specific|confirmed|known) "
        r"|^CROSS[- ]CONNECTIONS"
        r"|^## (?:Executive Summary|Risk Themes|Key Findings|Notable Entities|Evidence Gaps|Recommended|Methodology|Source Appendix|Data Ethics)"
        r"|^I have (?:analyzed|reviewed|examined|synthesized)"
        r"|^Let me (?:analyze|synthesize|summarize|break down)"
        r"|^Here(?:'|\s*is) (?:a |my |the )?(?:summary|analysis|report|breakdown|synthesis)"
        r"|^The (?:following|above|below) (?:analysis|report|summary|findings)"
        r"|^(?:This|The) (?:report|analysis|investigation|brief|synthesis) (?:is|was|has been|provides|contains))",
        re.IGNORECASE,
    )

    # Phrases that indicate an entire response is a refusal/meta-commentary
    # rather than intelligence output
    _REFUSAL_MARKERS = [
        "I cannot complete this request",
        "I would need you to either",
        "as an AI, I cannot execute live queries",
        "I cannot fabricate intelligence",
        "you have not included any search results",
        "To proceed with Phase",
    ]

    @staticmethod
    def _is_llm_noise(title: str) -> bool:
        """Filter out LLM self-reference / procedural noise from findings."""
        if OrchestrationEngine._LLM_NOISE.search(title):
            return True
        # Check refusal markers in the full text, not just title
        title_lower = title.lower()
        if any(m.lower() in title_lower for m in OrchestrationEngine._REFUSAL_MARKERS):
            return True
        return False

    @staticmethod
    def _is_refusal_text(raw: str) -> bool:
        """Check if the entire LLM response is a refusal rather than intelligence.

        The LLM sometimes returns a long explanation of what it needs or why it
        can't proceed, instead of synthesizing findings. If the response is >50%
        refusal/meta-commentary lines, treat it as a refusal.
        """
        if not raw or len(raw) < 30:
            return True  # Too short to be intelligence
        lines = [l.strip() for l in raw.split("\n") if l.strip()]
        if not lines:
            return True

        refusal_count = 0
        for line in lines:
            line_lower = line.lower()
            if any(m.lower() in line_lower for m in OrchestrationEngine._REFUSAL_MARKERS):
                refusal_count += 1
            elif OrchestrationEngine._LLM_NOISE.search(line):
                refusal_count += 1

        # If >50% of non-empty lines are refusal/noise, the whole response is garbage
        if len(lines) > 0 and refusal_count / len(lines) > 0.5:
            logger.warning("refusal_response_detected: %d/%d lines are noise",
                          refusal_count, len(lines))
            return True
        return False


    @staticmethod
    def _relevance_score(target: str, text: str) -> float:
        """Compute token-overlap relevance between target query and finding text.

        Returns 0.0 – 1.0. A score of 0 means zero word overlap — the finding
        is almost certainly unrelated (e.g., "Idaho murders" for "KOVÁCS Anna").
        """
        import unicodedata
        if not target or not text:
            return 0.0

        # Normalize: lowercase, strip diacritics, split into tokens
        def normalize(s: str) -> set[str]:
            s = unicodedata.normalize('NFKD', s.lower())
            s = ''.join(c for c in s if not unicodedata.combining(c))
            # Extract alphanumeric tokens, min 2 chars
            tokens = set()
            for token in s.split():
                token = ''.join(c for c in token if c.isalnum())
                if len(token) >= 2:
                    tokens.add(token)
            return tokens

        target_tokens = normalize(target)
        if not target_tokens:
            return 0.5  # Can't assess, don't penalize

        text_tokens = normalize(text)
        if not text_tokens:
            return 0.0

        # Jaccard similarity
        intersection = target_tokens & text_tokens
        union = target_tokens | text_tokens
        return len(intersection) / len(union) if union else 0.0
    @staticmethod
    def _filter_irrelevant(findings: list, query: str) -> list:
        """Drop findings with zero token overlap against the target query.

        A finding about "Idaho murders" with no mention of "BÓDI" or "Ildikó"
        should be dropped — it's a false positive from a scraper substring match.
        Only drops findings with confidence < 0.65 to avoid removing legit
        findings that use different terminology (e.g., an article about
        "Hungarian mother wanted in Luxembourg" without the target's name).
        """
        kept = []
        for f in findings:
            combined_text = f"{f.title or ''} {f.description or ''}"
            score = OrchestrationEngine._relevance_score(query, combined_text)

            # If zero token overlap AND low confidence, it's almost certainly
            # an unrelated false positive from scraper substring matching
            if score == 0.0 and (f.confidence or 0.5) < 0.65:
                continue

            # If very low overlap (< 0.05) and no source URL, likely garbage
            if score < 0.05 and not (f.source_url and f.source_url.startswith("http")):
                continue

            kept.append(f)
        return kept


    @staticmethod
    def _dedupe_findings(findings: list) -> list:
        """Remove duplicate findings by URL + title similarity.

        Two findings are duplicates if:
        - Same source URL, OR
        - Title similarity > 80% (case-insensitive Jaccard on words)
        """
        if len(findings) <= 1:
            return findings

        seen_urls: set[str] = set()
        seen_titles: list[set[str]] = []
        deduped = []

        for f in findings:
            url = (f.source_url or "").strip().rstrip("/")
            title_lower = (f.title or "").lower()
            title_tokens = set(title_lower.split())

            # Check URL duplicate
            if url and url in seen_urls:
                continue

            # Check title similarity
            is_dup = False
            for prev_tokens in seen_titles:
                if not title_tokens or not prev_tokens:
                    continue
                overlap = len(title_tokens & prev_tokens)
                union = len(title_tokens | prev_tokens)
                if union > 0 and overlap / union > 0.8:
                    is_dup = True
                    break

            if is_dup:
                continue

            if url:
                seen_urls.add(url)
            seen_titles.append(title_tokens)
            deduped.append(f)

        return deduped

    @staticmethod
    def _filter_quality(findings: list, query: str = "") -> list:
        """Post-parse quality filter: remove findings that are just LLM commentary,
        API-key-placeholder spam, generic geolocation POI dumps, markdown tables,
        self-assessment meta-reports, or evidence-gap placeholders.

        A finding passes quality if it has:
        - A source URL (real data), OR
        - Description with >50 chars and contains actual entities (names, dates, numbers)

        Findings that are purely meta-commentary (the LLM describing what it would
        do, rather than producing intelligence) are stripped.
        """
        if not findings:
            return findings

        # ── Patterns to drop entirely ──
        API_KEY_PLACEHOLDERS = [
            "api key not configured", "api key required",
            "install your api key", "get a key", "get your key",
            "no api key", "missing api key", "set your api key",
            "api key is not set", "configure your api key",
        ]
        GEOLOCATION_NOISE = [
            "mines & quarries near", "industrial facilities near",
            "military installations near", "ports & harbours near",
            "unnamed way", "unnamed node",
            "asphalt plant", "home gas", "rubis fuel",
            "ice plant", "solar park", "puc",
            "jetty", "ferry", "passenger terminal",
        ]
        # ── LLM garbage: section headers that leak as findings ──
        SECTION_HEADERS = [
            "executive summary", "confidence assessment",
            "cross-connections report", "cross connections report",
            "novel angles", "investigation questions",
            "methodology", "source appendix", "data ethics",
            # ── Leaked through BÓDI investigation ──
            "connected entity analysis",
            "cross-connections",
            "key findings",
            "risk themes",
            "evidence gaps",
            "recommended next steps",
            "notable entities",
            "findings summary",
        ]
        # ── Markdown table rows that leak as findings ──
        TABLE_ROW_PATTERNS = [
            "| finding |", "| connection |", "| source |",
            "|---------|",  # Table separator
        ]
        # ── Self-directed questions ──
        QUESTION_PATTERNS = [
            "question 1:", "question 2:", "question 3:",
            "what specific", "what cryptocurrency",
            "which specific companies",
        ]
        # ── Gaps posing as findings ──
        GAP_AS_FINDING = [
            "no specific victim", "no specific ransom",
            "no co-conspirator", "no cryptocurrency wallet",
            "no current location", "no extradition",
            "no family member", "no associate",
            "no confirmed sanction", "no specific asset",
            "no specific company", "no prison term",
            "not in bop custody", "no trial has occurred",
            "no court name", "no inmate number",
            "no family members identified",
            "no specific co-conspirator names",
            "no specific fine", "no specific asset",
            # ── Leaked through KOVÁCS investigation ──
            "no specific legal citations",
            "no court identifiers",
            "no child details",
            "no father details",
            "no financial information",
            "no prior criminal history",
            "no dark web indicators",
            "no dark web",
            # ── Universal gap patterns ──
            "no confirmed indictment",
            "no specific charges",
            "no known associates",
            "no current employment",
            "no arrest record",
            "no criminal record",
            "no social media presence",
            "no address found",
            "no phone number",
            "no email address",
            "no domain registrations",
            "no corporate filings",
        ]
        # ── How-to guides, login pages, tool homepages — noise when
        #     DDG returns generic results instead of person-specific intel ──
        HOW_TO_AND_LOGIN_NOISE_TITLES = [
            "how do i log in", "how to find the owner",
            "how to find out who owns", "sign in to ",
            "gmail - google accounts", "accounts.google.com",
            "search twitter posts", "free public twitter",
            "a relentless interview", "sihirli annem",
        ]
        HOW_TO_AND_LOGIN_NOISE_DOMAINS = [
            "androidpolice.com", "supereasy.com", "socialcatfish.com",
            "x-sou.com", "xarchive.net", "skills.sh",
        ]

        kept = []
        for f in findings:
            title_lower = (f.title or "").lower()
            desc_lower = (f.description or "").lower()

            # ── Drop: API key placeholder "findings" ──
            if any(phrase in title_lower or phrase in desc_lower
                   for phrase in API_KEY_PLACEHOLDERS):
                continue

            # ── Drop: geolocation POI dumps with no target connection ──
            if any(noise in title_lower for noise in GEOLOCATION_NOISE):
                continue

            # ── Drop: how-to guides, login pages, tool homepages ──
            if any(noise in title_lower for noise in HOW_TO_AND_LOGIN_NOISE_TITLES):
                continue
            source_url = getattr(f, "source_url", "") or ""
            if any(d in source_url for d in HOW_TO_AND_LOGIN_NOISE_DOMAINS):
                continue

            # ── Drop: section headers leaked as findings ──
            if any(title_lower.strip("# ").startswith(h) for h in SECTION_HEADERS):
                continue

            # ── Drop: markdown table rows ──
            if any(p in title_lower for p in TABLE_ROW_PATTERNS):
                continue
            # Also catch: title IS a pipe-table row
            if title_lower.strip().startswith("|"):
                continue

            # ── Drop: self-directed questions ──
            if any(q in desc_lower for q in QUESTION_PATTERNS):
                continue

            # ── Drop: gaps posing as findings (negative findings with no source) ──
            if any(g in title_lower for g in GAP_AS_FINDING) and not f.source_url:
                continue

            # ── Drop: "Connected Entity X:" synthesized summaries ──
            if "connected entity" in title_lower and not f.source_url:
                continue

            # Has a real URL → keep it
            if f.source_url and f.source_url.startswith("http"):
                kept.append(f)
                continue

            # No URL and no description → drop
            if not f.description or len(f.description) < 50:
                continue

            # Check if description contains real data (names, dates, numbers,
            # proper nouns) vs pure LLM meta-commentary
            desc = f.description
            # Real data indicators: proper names (CapWords), dates, specific numbers,
            # organization references, source citations
            has_proper_names = bool(re.search(r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b', desc))
            has_dates = bool(re.search(r'\b(?:19|20)\d{2}\b', desc))
            has_numbers = bool(re.search(r'\b\d{2,}\b', desc))
            has_source_ref = bool(re.search(r'\[(\d+|\w+)\]|Source:|According to', desc, re.IGNORECASE))

            # Meta-commentary indicators: the LLM talking about itself
            is_meta = any(phrase in desc.lower() for phrase in [
                "i would need", "you have provided", "to proceed",
                "as an ai", "i cannot", "i am unable", "i will now",
                "i will run", "i will simulate", "i must ask",
                "you have not", "if you can", "instruct me",
                "once you provide", "example of what",
                # ── Leaked through Mohammadzadeh investigation ──
                "let's first extract", "let's first",
                "i will open", "i'll open", "i can use python",
                "i'm not actually able", "i recall the",
                "for each fact", "i'll also", "i'll keep",
                "i'll treat", "i'll use", "i can use",
                "the youtube video is likely",
                "however, the user also",
                "i will incorporate", "i can incorporate",
                "i could open", "i could use",
                "i don't have the full", "i can view",
                "i could mention", "i'll rely on",
                "but i can't see", "i can't see the full",
                "the search result snippet says",
                "for iran:", "i can mention that",
                "as an ai in this simulation",
                "i need to fetch", "i might need",
                "i will treat", "i can mention",
            ])

            if is_meta and not (has_proper_names or has_dates or has_source_ref):
                continue

            # Down-trust findings with no URL to UNVERIFIED tier
            if not f.source_url:
                f.source_tier = "UNVERIFIED"
                f.confidence = min(f.confidence, 0.25)

            kept.append(f)

        # ── Relevance check: universal pre-synthesis pipeline (any target type, any language) ──
        if query:
            try:
                from ..pipeline import relevance_filter as _rf
                kept, _dropped = _rf(kept, query)
                if _dropped:
                    logger.info("pre_synthesis_dropped: %d irrelevant findings for '%s'",
                                len(_dropped), str(query)[:60])
            except ImportError:
                kept = OrchestrationEngine._filter_irrelevant(kept, query)

        # ── Duplicate detection ──
        kept = OrchestrationEngine._dedupe_findings(kept)

        return kept

    def _parse_findings(self, raw: str, phase: str = "") -> list[Finding]:
        """Parse Hermes response into structured Finding objects.

        Hermes produces free-form investigative text. We extract:
        1. Section breaks (##, ###, numbered lists, FINDING: blocks)
        2. Source URLs from each section
        3. The actual intelligence content

        Refusal detection: if the entire response is LLM refusal/meta-commentary
        (e.g., "I cannot complete this request as stated"), return empty findings
        rather than logging refusal text as intelligence.
        """
        if not raw or len(raw) < 20:
            return []

        # ── Refusal gate: if the whole response is the LLM refusing to work ──
        if self._is_refusal_text(raw):
            return []

        findings = []

        # Strategy 1: FINDING:/SOURCE:/DATA: blocks (structured prompt response)
        if "FINDING:" in raw:
            blocks = re.split(r'\n(?=FINDING:)', raw)
            for block in blocks:
                if not block.strip():
                    continue
                f = Finding(phase=phase)
                for line in block.split("\n"):
                    line = line.strip()
                    if line.startswith("FINDING:"):
                        f.title = line[8:].strip()
                    elif line.startswith("SOURCE:"):
                        url = line[7:].strip()
                        if url.startswith("http"):
                            f.source_url = url
                    elif line.startswith("DATA:"):
                        f.description = line[5:].strip()
                    elif line.startswith("TIER:"):
                        tier_val = line[5:].strip().upper()
                        f.source_tier = tier_val if tier_val in ("PRIMARY", "SECONDARY", "TERTIARY", "UNVERIFIED") else "SECONDARY"
                        # Boosted: SECONDARY sources (Guardian, CSMonitor, BBC, etc.) with URLs
                        # are as reliable as PRIMARY for most OSINT purposes.
                        tier_conf = {"PRIMARY": 0.95, "SECONDARY": 0.75, "TERTIARY": 0.50, "UNVERIFIED": 0.25}
                        f.confidence = tier_conf.get(f.source_tier, 0.50)
                    elif line.startswith("CONFIDENCE:"):
                        conf_val = line[11:].strip().upper()
                        conf_map = {"HIGH": 0.85, "MEDIUM": 0.60, "LOW": 0.30}
                        f.confidence = conf_map.get(conf_val, 0.50)
                    elif line.startswith("CHAIN:") or line.startswith("PIVOT:"):
                        pass  # Pivot hint — informational only
                if f.title and len(f.title) > 3 and not self._is_llm_noise(f.title) and not self._is_negative_finding(f.title):
                    # Extract URLs from description
                    if not f.source_url:
                        urls = re.findall(r'https?://[^\s\)\]]+', f.description or "")
                        if urls:
                            f.source_url = urls[0]
                    # URL boost: findings with verified source URLs are much more reliable.
                    # SECONDARY (0.75) + URL → 0.90 (CONFIRMED). TERTIARY (0.50) + URL → 0.65.
                    if f.source_url:
                        f.confidence = min(0.99, f.confidence + 0.15)
                    findings.append(f)
            if findings:
                return findings

        # Strategy 2: Split by markdown headers or numbered sections
        sections = re.split(r'\n(?:###?\s+|(?:\d+\.)\s+)', raw)
        if len(sections) <= 1:
            # Try double-newline paragraph splits for longer content
            paras = [p.strip() for p in raw.split("\n\n") if len(p.strip()) > 30]
            if len(paras) > 3:
                sections = paras
            else:
                sections = [raw]

        for section in sections:
            section = section.strip()
            if len(section) < 20:
                continue

            # Extract first meaningful line as title
            lines = section.split("\n")
            title = lines[0].strip()
            # Clean up title (remove markdown formatting)
            title = re.sub(r'^\*+\s*', '', title)
            title = re.sub(r'\*+$', '', title)
            title = title[:200]

            # ── Skip sections that are LLM meta-headers, tables, or self-talk ──
            if self._is_llm_noise(title):
                continue
            # Also check first few lines for table content (Strategy 1 already handled
            # structured FINDING: blocks, so tables leaking here are garbage)
            if any(line.strip().startswith("|") for line in lines[:3]):
                continue

            # Extract URLs
            urls = re.findall(r'https?://[^\s\)\]]+', section)
            source_url = urls[0] if urls else ""

            # Description = rest of the section
            description = "\n".join(lines[1:]).strip() if len(lines) > 1 else ""
            if not description:
                description = section[:2000]

            # Detect source tier from content
            source_tier = "SECONDARY"
            confidence = 0.50
            section_lower = section.lower()

            primary_indicators = ["ofac", "sanctions list", "court record", "indictment",
                                  "doj ", "department of justice", "interpol", "sec filing",
                                  "government registry", "official document", "un security council"]
            tertiary_indicators = ["wikipedia", "social media", "twitter.com", "reddit.com",
                                   "forum", "blog post", "self-reported"]
            unverified_indicators = ["anonymous", "rumor", "unconfirmed", "alleged"]

            if any(ind in section_lower for ind in primary_indicators):
                source_tier = "PRIMARY"
                confidence = 0.95
            elif any(ind in section_lower for ind in tertiary_indicators):
                source_tier = "TERTIARY"
                confidence = 0.35
            elif any(ind in section_lower for ind in unverified_indicators):
                source_tier = "UNVERIFIED"
                confidence = 0.15

            f = Finding(
                title=title,
                description=description[:3000],
                source_url=source_url,
                source_tier=source_tier,
                confidence=confidence,
                phase=phase,
            )
            if not self._is_llm_noise(title):
                findings.append(f)

        # ── Post-parse quality filter ──
        # Strip findings that have no source URL AND whose description is
        # pure LLM meta-commentary (talking about methodology, not producing intel)
        findings = self._filter_quality(findings)

        return findings

    # ── Helpers ───────────────────────────────────────────────

    @staticmethod
    def _findings_context(findings: list[Finding]) -> str:
        """Build a condensed context string from findings for the next phase."""
        if not findings:
            return "(no previous findings)"
        lines = []
        for f in findings[:20]:
            lines.append(f"• [{f.tier}] {f.title}")
            if f.description:
                desc = f.description[:400].replace("\n", " ")
                lines.append(f"  {desc}")
            if f.source_url:
                lines.append(f"  Source: {f.source_url}")
        return "\n".join(lines)

    @staticmethod
    def _should_escalate_to_dark(findings: list[Finding], query: str) -> bool:
        """Check if dark web escalation is warranted."""
        all_text = query.lower() + " " + " ".join(
            f"{f.title} {f.description}" for f in findings
        ).lower()
        return any(trigger in all_text for trigger in DARK_WEB_TRIGGERS)

    def _save_and_update_graph(self, report: InvestigationReport):
        """Offloaded from investigate() — save case + update graph in background."""
        try:
            self._save_case(report)
        except Exception as e:
            logger.warning("bg_save_case_failed: %s", e)
        try:
            self._update_graph(report)
        except Exception as e:
            logger.warning("bg_update_graph_failed: %s", e)

    def _save_case(self, report: InvestigationReport):
        """Save case markdown to disk."""
        try:
            from watson.memory import memory as mem
            mem.save_investigation(
                query=report.query,
                findings=[f.to_dict() for f in report.findings],
                target_type=report.target_type,
            )
        except Exception:
            pass

        try:
            CASES_DIR.mkdir(parents=True, exist_ok=True)
            fname = f"{report.case_id}_{report.created_at[:10]}.md"
            path = CASES_DIR / fname
            path.write_text(report.markdown)
            logger.info("case_saved: %s", path)
        except Exception as e:
            logger.warning("case_save_failed: %s", e)

    @staticmethod
    def _classify_entity(value: str, hint_type: str = "") -> str:
        """Classify an entity value into a proper type.
        
        Uses regex patterns for deterministic types, falls back to hint_type if valid,
        otherwise returns 'unknown'.
        """
        v = (value or "").strip()
        if not v:
            return "unknown"
        # Wallet addresses
        if re.match(r'^0x[a-fA-F0-9]{40}$', v) or re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', v):
            return "wallet"
        # Domains
        if re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}$', v):
            return "domain"
        # Email
        if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', v):
            return "email"
        # IP addresses
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', v):
            return "ip"
        # URL
        if v.startswith("http://") or v.startswith("https://"):
            return "url"
        # Valid hint types
        valid_types = {"person", "company", "organization", "domain", "email", 
                       "wallet", "ip", "location", "phone", "url"}
        hint = (hint_type or "").strip().lower()
        if hint in valid_types:
            return hint
        # Heuristic: short strings with spaces are likely person names
        # Long strings are likely organization/company names
        if len(v.split()) >= 2 and len(v) < 60:
            return "person"
        if len(v) >= 3:
            return "organization"
        return "unknown"
    
    @staticmethod
    def _extract_entities_from_text(text: str) -> list[dict]:
        """Extract potential entity mentions from free text using regex patterns.
        
        Returns list of {value, type} dicts for domains, emails, wallets, IPs,
        and capitalized multi-word phrases (likely person/org names).
        """
        entities: list[dict] = []
        seen: set[str] = set()
        
        # Domains (e.g., stripe.com, opencorporates.com)
        for m in re.finditer(r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b', text):
            domain = m.group(1).strip('.').lower()
            if domain not in seen and '.' in domain and len(domain) > 5:
                seen.add(domain)
                entities.append({"value": domain, "type": "domain"})
        
        # Emails
        for m in re.finditer(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', text):
            email = m.group(1).lower()
            if email not in seen:
                seen.add(email)
                entities.append({"value": email, "type": "email"})
        
        # Wallet addresses (Ethereum-style)
        for m in re.finditer(r'\b(0x[a-fA-F0-9]{40})\b', text):
            wallet = m.group(1)
            if wallet not in seen:
                seen.add(wallet)
                entities.append({"value": wallet, "type": "wallet"})
        
        # IPs
        for m in re.finditer(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text):
            ip = m.group(1)
            if ip not in seen:
                seen.add(ip)
                entities.append({"value": ip, "type": "ip"})
        
        # Capitalized multi-word names (likely Person or Organization)
        # Match: "Patrick Collison", "House Financial Services Committee", "Stripe"
        for m in re.finditer(r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,4})\b', text):
            name = m.group(1).strip()
            # Skip common words and noise
            skip_words = {'The', 'This', 'That', 'Here', 'There', 'What', 'When', 'Where',
                         'Which', 'Find', 'Help', 'Support', 'Source', 'Data', 'Search',
                         'Case', 'Phase', 'Finding', 'Target', 'Report', 'Brief',
                         'Summary', 'Key', 'Risk', 'Executive', 'Intelligence',
                         'OpenSanctions', 'Sanctions', 'Programs', 'Country', 'Office',
                         'Foreign', 'Assets', 'Control', 'List', 'Service', 'Supreme',
                         'Leaders', 'Politically', 'Exposed', 'Persons', 'Datasets',
                         'Changelog', 'Investigation', 'Committee', 'White', 'Stripes',
                         'Seven', 'Nation', 'Army', 'Hacker', 'News', 'Help',
                         'Myths', 'Fraud', 'Board', 'Dive', 'Payments', 'Approved',
                         'Interview', 'Sources', 'Layer', 'Capital', 'Family',
                         'Response', 'Financial', 'Services', 'Github', 'CEO',
                         'Culture', 'Ben', 'Lang'}
            if name in skip_words:
                continue
            if len(name) < 5:
                continue
            # Filter out things that look like section headers (all caps words followed by lowercase)
            if name not in seen:
                seen.add(name)
                entities.append({"value": name, "type": ""})  # let classifier decide
        
        return entities

    def _update_graph(self, report: InvestigationReport):
        """Index case entities in knowledge graph with proper typing, relations, and MCP publish."""
        import httpx
        
        try:
            from watson.graph import KnowledgeGraph
            g = KnowledgeGraph()
            entity_ids: list[str] = []
            ingested_entities: list[dict] = []
            
            for f in report.findings:
                # Use structured entities if available, otherwise extract from text
                raw_entities = f.entities if f.entities else []
                if not raw_entities:
                    # Fallback: extract entities from the finding title + description
                    text = f"{f.title} {f.description}"
                    raw_entities = self._extract_entities_from_text(text)
                
                if not raw_entities:
                    continue
                
                finding_entity_pairs: list[tuple[str, str, str]] = []  # (id, type, value)
                for entity in raw_entities:
                    raw_type = entity.get("type", "")
                    raw_value = entity.get("value", entity.get("name", ""))
                    if not raw_value or not raw_value.strip():
                        continue
                    
                    # Properly classify the entity type
                    real_type = self._classify_entity(raw_value, raw_type)
                    if real_type == "unknown":
                        continue
                    
                    label = entity.get("label", entity.get("name", raw_value))
                    e = g.add_entity(
                        entity_type=real_type,
                        value=raw_value.strip(),
                        case_id=report.case_id,
                        label=label[:200] if label else raw_value.strip()[:200],
                    )
                    finding_entity_pairs.append((e.id, real_type, raw_value.strip()))
                    ingested_entities.append({
                        "value": raw_value.strip(),
                        "type": real_type,
                        "tier": f.tier if hasattr(f, 'tier') else "PROBABLE",
                        "source": getattr(f, 'source_url', ''),
                    })
                
                entity_ids.extend(eid for eid, _, _ in finding_entity_pairs)
            
            # Create relations between ALL entities in the report (not just per-finding)
            # This captures cross-finding connections
            all_pairs: list[tuple[str, str, str]] = []
            for eid in entity_ids:
                if eid in g._entities:
                    ent = g._entities[eid]
                    all_pairs.append((eid, ent.type, ent.value))
            
            for i in range(len(all_pairs)):
                for j in range(i + 1, len(all_pairs)):
                    _, src_type, src_val = all_pairs[i]
                    _, tgt_type, tgt_val = all_pairs[j]
                    g.add_relation(
                        source_type=src_type, source_value=src_val,
                        relation_type="co_occurs_with",
                        target_type=tgt_type, target_value=tgt_val,
                        case_id=report.case_id,
                        confidence=0.4,
                        evidence=f"Co-occur in investigation: {report.query}",
                    )
            
            g.add_case(report.case_id, report.query)
            logger.info("graph_updated", extra={
                "case_id": report.case_id,
                "entities": len(entity_ids),
                "ingested": len(ingested_entities),
            })
            
            # Publish to MCP community graph
            self._publish_to_mcp(report, ingested_entities)
            
        except Exception as e:
            logger.warning("graph_update_failed: %s", e)
    
    def _publish_to_mcp(self, report: InvestigationReport, entities: list[dict]):
        """Publish investigation entities to the MCP community knowledge graph."""
        import httpx
        import os
        
        mcp_url = os.environ.get("WATSON_MCP_URL", "http://localhost:8700")
        mcp_key = os.environ.get("MCP_API_KEY", "")
        
        try:
            conf_count = sum(1 for f in report.findings if getattr(f, 'tier', '') == 'CONFIRMED')
            payload = {
                "case_id": report.case_id,
                "target": report.query,
                "target_type": report.target_type or "",
                "findings_count": len(report.findings),
                "confirmed_count": conf_count,
                "verifiability": f"{report.verifiability_score:.0%}" if hasattr(report, 'verifiability_score') else "",
                "date": report.created_at[:10] if hasattr(report, 'created_at') else "",
                "entities": entities,
                "markdown": getattr(report, 'markdown', '')[:10000],
            }
            headers = {"X-API-Key": mcp_key} if mcp_key else {}
            resp = httpx.post(
                f"{mcp_url}/api/ingest",
                json=payload,
                headers=headers,
                timeout=10,
            )
            if resp.status_code == 200:
                logger.info("mcp_published", extra={
                    "case_id": report.case_id,
                    "entities": len(entities),
                })
            else:
                logger.warning("mcp_publish_failed: status=%s url=%s", resp.status_code, mcp_url, extra={
                    "case_id": report.case_id,
                    "status": resp.status_code,
                })
        except Exception as e:
            logger.warning("mcp_publish_error: %s", e)


# ── Singleton ──────────────────────────────────────────────────

_engine: Optional[OrchestrationEngine] = None


def get_engine(depth: int = 2, max_hops: int | None = None) -> OrchestrationEngine:
    """Get or create the orchestration engine singleton."""
    global _engine
    if _engine is None:
        d = max_hops if max_hops is not None else depth
        _engine = OrchestrationEngine(depth=d)
    return _engine
