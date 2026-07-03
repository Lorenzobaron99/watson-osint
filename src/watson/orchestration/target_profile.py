"""
Target profiler — fast, accurate classification + rich decomposition.

Layered approach so the orchestrator knows not just WHAT is being
investigated but WHERE to start looking first.

  Elon Musk → person + @elonmusk + Tesla/SpaceX + wikidata:Q317521
  Stripe    → company + stripe.com + founders + opencorp lookup
  0xdead... → wallet + ETH chain + etherscan link

Architecture:
  Layer 1: Regex (instant) — email, IP, domain, phone, crypto wallets
  Layer 2: GLiNER (CPU, ~50ms) — person vs organization disambiguation
  Layer 3: Wikidata API (REST) — QID, occupation, employer, social handles
  Layer 4: LLM (fallback only) — truly ambiguous cases
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import quote

logger = logging.getLogger(__name__)


# ── Data model ────────────────────────────────────────────────────


@dataclass
class TargetProfile:
    """Rich decomposition of an investigation target.

    The orchestrator uses this to decide which sources to hit first.
    """

    target_type: str  # person | company | organization | domain | wallet | ip | email
    primary_name: str  # cleaned canonical form
    confidence: float  # 0.0 — 1.0
    raw_query: str = ""

    # ── Associated entities ──
    associated_orgs: list[str] = field(default_factory=list)  # Tesla, SpaceX
    associated_domains: list[str] = field(default_factory=list)  # tesla.com
    social_handles: list[str] = field(default_factory=list)  # @elonmusk
    known_aliases: list[str] = field(default_factory=list)
    locations: list[str] = field(default_factory=list)

    # ── Wikidata enrichment ──
    wikidata_qid: Optional[str] = None  # Q317521
    wikidata_label: Optional[str] = None
    wikidata_description: Optional[str] = None

    # ── Orchestrator hints ──
    suggested_sources: list[str] = field(default_factory=list)
    # e.g. ["wikidata", "web_search", "twitter", "opencorporates"]
    investigation_angles: list[str] = field(default_factory=list)
    # e.g. ["social_media", "corporate_affiliations", "domain_infra"]

    # ── Source-specific IDs ──
    source_ids: dict[str, str] = field(default_factory=dict)
    # e.g. {"opencorporates": "https://opencorporates.com/companies/us_de/..."}

    # ── Classification path (for debugging) ──
    classified_by: str = ""  # "regex", "gliner", "wikidata", "llm"

    def __post_init__(self):
        if not self.suggested_sources:
            self.suggested_sources = _DEFAULT_SOURCES.get(self.target_type, ["web_search"])
        if not self.investigation_angles:
            self.investigation_angles = _DEFAULT_ANGLES.get(self.target_type, ["general"])


# ── Default source mappings per target type ───────────────────────

_DEFAULT_SOURCES: dict[str, list[str]] = {
    "person": ["wikidata", "web_search", "social_media", "news_search", "sanctions"],
    "company": ["opencorporates", "crtsh", "web_search", "wikidata", "sanctions", "secedgar"],
    "organization": ["opencorporates", "crtsh", "web_search", "wikidata", "sanctions"],
    "domain": ["crtsh", "wayback", "dns", "web_search", "shodan"],
    "wallet": ["blockchain_explorer", "web_search", "dark_web"],
    "ip": ["shodan", "geolocation", "abuseipdb", "web_search"],
    "email": ["hibp", "social_enumeration", "web_search", "dark_web"],
}

_DEFAULT_ANGLES: dict[str, list[str]] = {
    "person": ["identity", "social_media", "professional", "legal", "web_presence"],
    "company": ["corporate_structure", "domain_infra", "legal_regulatory", "leadership", "web_presence"],
    "organization": ["structure", "domain_infra", "legal", "leadership", "web_presence"],
    "domain": ["ssl_certs", "dns_records", "wayback_history", "associated_ips", "subdomains"],
    "wallet": ["transaction_graph", "exchange_links", "entity_attribution", "dark_web_mentions"],
    "ip": ["geolocation", "hosting", "abuse_history", "associated_domains", "ports"],
    "email": ["breaches", "social_accounts", "dark_web", "domain_owner"],
}


# ── Layer 1: Deterministic regex ──────────────────────────────────
# Extended from SpiderFoot's battle-tested regexes, plus modern types

_REGEX_RULES: list[tuple[re.Pattern, str, float]] = [
    # ── Email (must come before domain to catch user@host) ──
    (re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"), "email", 0.98),

    # ── Ethereum / EVM wallet ──
    (re.compile(r"^0x[a-fA-F0-9]{40}$"), "wallet", 0.98),

    # ── Solana wallet ──
    (re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$"), "wallet", 0.85),

    # ── Bitcoin address (legacy P2PKH) ──
    (re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$"), "wallet", 0.85),

    # ── IPv4 ──
    (re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    ), "ip", 0.95),

    # ── IPv4 CIDR ──
    (re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/\d{1,2}$"
    ), "ip", 0.95),

    # ── IPv6 (simplified) ──
    (re.compile(r"^[0-9a-fA-F:]+$"), "ip", 0.80),

    # ── Phone (E.164) ──
    (re.compile(r"^\+[1-9]\d{6,14}$"), "email", 0.90),  # will be overridden by phone type

    # ── Domain with known TLD ──
    (re.compile(
        r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"(?:com|org|net|io|gov|edu|mil|ru|cn|de|uk|fr|br|in|jp|kr|"
        r"au|ca|ch|nl|se|no|dk|fi|pl|ua|ir|ng|sg|hk|tw|"
        r"info|biz|co|me|tv|ai|app|dev|xyz|site|online|shop|"
        r"tech|blog|news|media|wiki|finance|law|health|"
        r"design|agency|consulting|ventures|capital|partners|"
        r"foundation|institute|international)$",
        re.IGNORECASE,
    ), "domain", 0.90),

    # ── URL ──
    (re.compile(r"^https?://[^\s]+$", re.IGNORECASE), "domain", 0.70),
]


def _regex_classify(query: str) -> Optional[TargetProfile]:
    """Try deterministic regex classification. Fastest path."""
    q = query.strip()

    for pattern, ttype, conf in _REGEX_RULES:
        if pattern.match(q):
            # ── Enrich email ──
            if ttype == "email" and "@" in q:
                domain = q.split("@")[-1].lower()
                profile = TargetProfile(
                    target_type="email",
                    primary_name=q.lower(),
                    confidence=conf,
                    raw_query=query,
                    associated_domains=[domain],
                    classified_by="regex",
                )
                return profile

            # ── Enrich wallet ──
            if ttype == "wallet":
                chain = "eth" if q.startswith("0x") else "btc" if q[0] in "13" else "sol"
                explorers = {
                    "eth": f"https://etherscan.io/address/{q}",
                    "btc": f"https://www.blockchain.com/explorer/addresses/btc/{q}",
                    "sol": f"https://solscan.io/account/{q}",
                }
                return TargetProfile(
                    target_type="wallet",
                    primary_name=q,
                    confidence=conf,
                    raw_query=query,
                    source_ids={"explorer": explorers.get(chain, "")},
                    investigation_angles=["transaction_graph", "exchange_links", "entity_attribution"],
                    classified_by="regex",
                )

            # ── Enrich IP ──
            if ttype == "ip":
                return TargetProfile(
                    target_type="ip",
                    primary_name=q,
                    confidence=conf,
                    raw_query=query,
                    source_ids={"shodan": f"https://www.shodan.io/host/{q}"},
                    classified_by="regex",
                )

            # ── Enrich domain ──
            if ttype == "domain":
                clean = q.replace("https://", "").replace("http://", "").rstrip("/")
                # Extract base domain
                parts = clean.split(".")
                if len(parts) >= 2:
                    base = ".".join(parts[-2:]) if len(parts) > 2 else clean
                else:
                    base = clean
                return TargetProfile(
                    target_type="domain",
                    primary_name=clean,
                    confidence=conf,
                    raw_query=query,
                    associated_domains=[clean],
                    source_ids={
                        "crtsh": f"https://crt.sh/?q=%25.{base}",
                        "wayback": f"https://web.archive.org/web/*/{clean}",
                    },
                    classified_by="regex",
                )

    return None


# ── Layer 2: GLiNER NER ──────────────────────────────────────────
# Person vs organization disambiguation, runs locally on CPU

_GLINER_MODEL = None
_GLINER_LOADED = False

# Entity labels GLiNER extracts
_ENTITY_LABELS = [
    "person",
    "organization",
    "company",
    "email",
    "phone number",
    "cryptocurrency wallet",
    "domain",
    "location",
    "username",
    "product",
    "hacker group",
    "criminal organization",
]


def _load_gliner():
    """Lazy-load GLiNER model — only loaded once, on first use."""
    global _GLINER_MODEL, _GLINER_LOADED
    if _GLINER_LOADED:
        return _GLINER_MODEL
    _GLINER_LOADED = True
    try:
        from gliner import GLiNER
        _GLINER_MODEL = GLiNER.from_pretrained("urchade/gliner_medium-v2.1")
        logger.info("GLiNER model loaded (medium-v2.1, CPU)")
    except Exception as e:
        logger.warning(f"GLiNER failed to load: {e}. Falling back to regex + LLM.")
        _GLINER_MODEL = None
    return _GLINER_MODEL


def _gliner_classify(query: str) -> Optional[TargetProfile]:
    """Use GLiNER to extract entities and determine target type.

    Calibrated thresholds (empirically validated):
      - person: 0.5 (Elon Musk 0.93, Dmitry Khoroshev 0.92)
      - organization/company: 0.2 (Stripe 0.22, Binance 0.30, OpenAI 0.45)
      - domain/email: 0.4
    """
    model = _load_gliner()
    if model is None:
        return None

    try:
        # Use lower threshold for org detection to catch single-word company names
        entities = model.predict_entities(query, _ENTITY_LABELS, threshold=0.2)
    except Exception as e:
        logger.warning(f"GLiNER prediction failed: {e}")
        return None

    if not entities:
        return None

    # Separate entities by type
    persons = []
    orgs = []
    domains_found = []
    emails = []
    locations = []
    wallets = []

    for ent in entities:
        label = ent.get("label", "").lower()
        text = ent.get("text", "").strip()
        score = ent.get("score", 0.0)

        # Person: high precision (0.5+) to avoid false positives
        if label == "person" and score > 0.5:
            persons.append(text)
        # Organization/company: calibrated at 0.2 for single-word detection
        elif label in ("organization", "company") and score > 0.25:
            orgs.append(text)
        elif label == "domain" and score > 0.4:
            domains_found.append(text)
        elif label == "email" and score > 0.5:
            emails.append(text)
        elif label == "location" and score > 0.4:
            locations.append(text)
        elif label in ("cryptocurrency wallet",) and score > 0.5:
            wallets.append(text)

    # ── Determine primary type ──
    # Priority: wallet > email > domain > person > organization
    if wallets:
        return TargetProfile(
            target_type="wallet",
            primary_name=wallets[0],
            confidence=0.85,
            raw_query=query,
            classified_by="gliner",
        )

    if emails:
        domain = emails[0].split("@")[-1] if "@" in emails[0] else ""
        return TargetProfile(
            target_type="email",
            primary_name=emails[0],
            confidence=0.85,
            associated_domains=[domain] if domain else [],
            classified_by="gliner",
        )

    if domains_found:
        return TargetProfile(
            target_type="domain",
            primary_name=domains_found[0],
            confidence=0.80,
            associated_domains=domains_found,
            classified_by="gliner",
        )

    if persons:
        profile = TargetProfile(
            target_type="person",
            primary_name=persons[0],
            confidence=0.80,
            raw_query=query,
            known_aliases=persons[1:],
            locations=locations,
            classified_by="gliner",
        )
        if orgs:
            profile.associated_orgs = orgs
        return profile

    if orgs:
        return TargetProfile(
            target_type="organization",
            primary_name=orgs[0],
            confidence=0.75,
            raw_query=query,
            associated_orgs=orgs[1:],
            locations=locations,
            classified_by="gliner",
        )

    return None


# ── Layer 3: Wikidata enrichment ──────────────────────────────────

async def _wikidata_enrich(profile: TargetProfile) -> TargetProfile:
    """Enrich a profile with Wikidata data. No API key needed."""
    search_term = profile.primary_name
    if profile.raw_query and profile.raw_query != profile.primary_name:
        search_term = profile.raw_query

    try:
        # Search for entity
        url = (
            "https://www.wikidata.org/w/api.php"
            f"?action=wbsearchentities&search={quote(search_term)}"
            "&language=en&format=json&limit=3"
        )
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                data = await resp.json()
    except Exception as e:
        logger.debug(f"Wikidata search failed: {e}")
        return profile

    results = data.get("search", [])
    if not results:
        return profile

    best = results[0]
    profile.wikidata_qid = best.get("id")
    profile.wikidata_label = best.get("label")
    profile.wikidata_description = best.get("description", "")

    # ── Fetch detailed entity data ──
    if profile.wikidata_qid:
        try:
            detail_url = (
                f"https://www.wikidata.org/wiki/Special:EntityData/"
                f"{profile.wikidata_qid}.json"
            )
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(detail_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    entity_data = await resp.json()
        except Exception:
            return profile

        claims = (
            entity_data.get("entities", {})
            .get(profile.wikidata_qid, {})
            .get("claims", {})
        )

        # ── Extract social handles ──
        # P2002 = Twitter username, P4264 = LinkedIn, P2013 = Facebook
        twitter = _extract_wikidata_prop(claims, "P2002")
        if twitter:
            profile.social_handles.append(f"@{twitter}")

        linkedin = _extract_wikidata_prop(claims, "P4264")
        if linkedin:
            profile.social_handles.append(f"linkedin:{linkedin}")

        # ── Extract associated domains ──
        # P856 = official website
        website = _extract_wikidata_prop(claims, "P856")
        if website:
            domain = website.replace("https://", "").replace("http://", "").rstrip("/")
            profile.associated_domains.append(domain)

        # ── Extract employer / founder relationships ──
        # P108 = employer, P112 = founded by
        if profile.target_type == "person":
            employer = _extract_wikidata_prop(claims, "P108")
            if employer:
                profile.associated_orgs.append(employer)

        if profile.target_type in ("company", "organization"):
            founder = _extract_wikidata_prop(claims, "P112")
            if founder:
                profile.known_aliases.append(founder)

        # ── Extract location ──
        # P17 = country, P159 = HQ location, P19 = place of birth
        country = _extract_wikidata_prop(claims, "P17")
        if country and country not in profile.locations:
            profile.locations.append(country)

        hq = _extract_wikidata_prop(claims, "P159")
        if hq and hq not in profile.locations:
            profile.locations.append(hq)

        birthplace = _extract_wikidata_prop(claims, "P19")
        if birthplace and birthplace not in profile.locations:
            profile.locations.append(birthplace)

        # ── Source-specific IDs ──
        if profile.target_type in ("company", "organization"):
            # OpenCorporates ID
            oc_id = _extract_wikidata_prop(claims, "P1320")
            if oc_id:
                profile.source_ids["opencorporates"] = (
                    f"https://opencorporates.com/companies/{oc_id}"
                )

        # ── Correct misclassified type using Wikidata ──
        # GLiNER/LLM can misclassify orgs as persons (e.g., "Aviloop" looks like a name).
        # Wikidata is authoritative — use its instance_of and description to fix.
        if profile.wikidata_qid and profile.wikidata_description:
            desc_lower = profile.wikidata_description.lower()
            org_keywords = [
                "company", "corporation", "organization", "organisation",
                "business", "website", "enterprise", "aviation", "airline",
                "startup", "brand", "service", "platform", "firm", "agency",
                "studio", "foundation", "institute", "association",
            ]
            is_org_by_desc = any(kw in desc_lower for kw in org_keywords)

            # Check instance_of (P31) for business/org Wikidata types
            instance_of = _extract_wikidata_prop(claims, "P31")
            is_org_by_p31 = instance_of in (
                "Q4830453",  # business
                "Q6881511",  # enterprise
                "Q43229",    # organization
                "Q35127",    # website
                "Q783794",   # company
                "Q167270",   # trademark
                "Q431289",   # brand
            )

            if profile.target_type == "person" and (is_org_by_desc or is_org_by_p31):
                logger.info(
                    f"wikidata_type_correction: '{profile.primary_name}' "
                    f"was classified as PERSON but Wikidata says '{profile.wikidata_description}' "
                    f"— switching to organization"
                )
                profile.target_type = "organization"
                profile.investigation_angles = _DEFAULT_ANGLES.get("organization", ["general"])
                profile.suggested_sources = _DEFAULT_SOURCES.get("organization", ["web_search"])
                profile.classified_by = f"{profile.classified_by}+type_corrected"

        # ── Update suggested sources based on what Wikidata told us ──
        profile.suggested_sources = _DEFAULT_SOURCES.get(profile.target_type, ["web_search"])
        profile.investigation_angles = _DEFAULT_ANGLES.get(profile.target_type, ["general"])

        profile.classified_by = f"{profile.classified_by}+wikidata"
        profile.confidence = min(profile.confidence + 0.1, 0.99)

    return profile


def _extract_wikidata_prop(claims: dict, prop_id: str) -> Optional[str]:
    """Extract a simple string value from Wikidata claims."""
    prop = claims.get(prop_id, [])
    if not prop:
        return None
    mainsnak = prop[0].get("mainsnak", {})
    if mainsnak.get("snaktype") != "value":
        return None
    datavalue = mainsnak.get("datavalue", {}).get("value", {})

    # String
    if isinstance(datavalue, str):
        return datavalue
    # Entity reference (Q-item)
    if isinstance(datavalue, dict):
        item = datavalue.get("id", "")
        # For Q-items, we return the ID — caller must resolve labels
        return item
    return None


# ── Layer 4: LLM fallback ────────────────────────────────────────

_LLM_FALLBACK_PROMPT = """You are an OSINT target classifier. Analyze this query and return STRICT JSON.

QUERY: {query}

Return:
{{
  "target_type": "person|company|organization|domain|wallet|ip|email",
  "primary_name": "canonical name",
  "confidence": 0.0-1.0,
  "associated_orgs": ["any orgs mentioned or implied"],
  "associated_domains": ["any domains mentioned or implied"],
  "social_handles": ["any social handles mentioned"],
  "known_aliases": ["aliases"],
  "locations": ["locations"],
  "investigation_angles": ["angles to investigate"]
}}

RULES:
- "Stripe" is a company, never a topic
- "Elon Musk" is a person associated with Tesla, SpaceX, xAI
- "LockBit 3.0" is a criminal organization / hacker group
- Email addresses with @ → email type
- 0x... addresses → wallet type
- IP addresses → ip type
- Domains with TLD → domain type

SINGLE-WORD DISAMBIGUATION (CRITICAL):
- A SINGLE made-up word (not a dictionary word, not a real first/last name)
  is almost always a COMPANY, BRAND, or ORGANIZATION — NOT a person.
  Examples: "Aviloop", "Spotify", "Canva", "Figma", "Stripe", "Notion", "Shopify"
  → target_type: "organization"
- A word that IS a real first name or last name (e.g., "Michael", "Chen", "Maria")
  → target_type: "person"
- Two words that look like First Last (e.g., "Satoshi Nakamoto", "Jane Smith")
  → target_type: "person"
- If the word contains company-like suffixes or patterns
  (loop, ify, hub, ly, io, ai, oo, up, ify, box, pad, folio, base, flow, sync)
  it is almost certainly a company → target_type: "organization"
- If the word sounds like a brand or product name, not a human name
  → target_type: "organization"
- When in doubt between person and organization for a single word,
  PREFER organization — companies are far more common single-word OSINT targets.

JSON:"""


async def _llm_classify(query: str, call_llm) -> TargetProfile:
    """LLM fallback — only called when regex + GLiNER + Wikidata can't resolve."""
    prompt = _LLM_FALLBACK_PROMPT.format(query=query[:500])

    try:
        raw = await call_llm(prompt, timeout=20)
    except Exception:
        return TargetProfile(
            target_type="topic",
            primary_name=query.strip(),
            confidence=0.3,
            raw_query=query,
            classified_by="llm_timeout",
        )

    if not raw:
        return TargetProfile(
            target_type="topic",
            primary_name=query.strip(),
            confidence=0.3,
            raw_query=query,
            classified_by="llm_empty",
        )

    # Parse JSON
    raw = raw.strip()
    raw = re.sub(r"^```(?:json)?\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            try:
                parsed = json.loads(m.group(0))
            except json.JSONDecodeError:
                parsed = {}
        else:
            parsed = {}

    target_type = str(parsed.get("target_type", "topic")).lower()
    valid_types = {"person", "company", "organization", "domain", "wallet", "ip", "email"}
    if target_type not in valid_types:
        target_type = "topic"

    # ── Post-LLM heuristic: single-word non-names are companies ──
    # The LLM sometimes calls made-up words "person" (e.g., "Aviloop").
    # If the target has no spaces and doesn't look like a human name, it's an org.
    if target_type == "person" and " " not in query.strip():
        query_lower = query.strip().lower()
        # Real human first names (common ones — not exhaustive, just a safety check)
        common_names = {
            "john", "jane", "michael", "maria", "james", "sarah", "david",
            "anna", "robert", "lisa", "william", "emma", "thomas", "olivia",
            "daniel", "sophia", "matthew", "isabella", "alexander", "mia",
            "joseph", "charlotte", "andrew", "amelia", "ryan", "harper",
            "joshua", "evelyn", "ethan", "abigail", "christopher", "emily",
            "nicholas", "elizabeth", "anthony", "sofia", "benjamin", "avery",
            "samuel", "ella", "jacob", "scarlett", "logan", "grace",
            "mohammed", "wei", "yuki", "satoshi", "filippo", "giulia",
            "paolo", "lorenzo", "francesca", "marco", "elena", "andrea",
        }
        if query_lower not in common_names:
            logger.info(
                f"llm_type_correction: '{query}' classified as PERSON by LLM "
                f"but is a single non-name word — switching to organization"
            )
            target_type = "organization"

    return TargetProfile(
        target_type=target_type,
        primary_name=str(parsed.get("primary_name", query.strip())),
        confidence=float(parsed.get("confidence", 0.5)),
        raw_query=query,
        associated_orgs=_list_str(parsed.get("associated_orgs", [])),
        associated_domains=_list_str(parsed.get("associated_domains", [])),
        social_handles=_list_str(parsed.get("social_handles", [])),
        known_aliases=_list_str(parsed.get("known_aliases", [])),
        locations=_list_str(parsed.get("locations", [])),
        investigation_angles=_list_str(parsed.get("investigation_angles", [])),
        classified_by="llm",
    )


def _list_str(val) -> list[str]:
    if isinstance(val, list):
        return [str(v) for v in val if str(v).strip()]
    return []


# ── Main entry point ─────────────────────────────────────────────


async def profile_target(
    query: str,
    call_llm=None,
    skip_wikidata: bool = False,
) -> TargetProfile:
    """Profile an investigation target — fast, layered classification.

    Steps:
      1. Regex for unambiguous types (instant)
      2. GLiNER NER for person vs organization (CPU, ~50ms)
      3. Wikidata API for enrichment (REST, ~200ms)
      4. LLM fallback only when all above fail (API call)

    Returns a rich TargetProfile the orchestrator can use to drive
    investigation phases.
    """
    if not query or not query.strip():
        return TargetProfile(
            target_type="topic",
            primary_name=query or "",
            confidence=0.0,
            classified_by="empty",
        )

    # ── 1. Regex ──
    profile = _regex_classify(query)
    if profile and profile.confidence >= 0.90:
        if not skip_wikidata:
            profile = await _wikidata_enrich(profile)
        return profile

    # ── 2. GLiNER ──
    gliner_profile = _gliner_classify(query)
    if gliner_profile and gliner_profile.confidence >= 0.70:
        if not skip_wikidata:
            gliner_profile = await _wikidata_enrich(gliner_profile)
        return gliner_profile

    # If regex found something low-confidence and GLiNER also found something,
    # prefer the higher-confidence result
    if profile and gliner_profile:
        best = profile if profile.confidence >= gliner_profile.confidence else gliner_profile
        if not skip_wikidata:
            best = await _wikidata_enrich(best)
        return best

    if profile:
        if not skip_wikidata:
            profile = await _wikidata_enrich(profile)
        return profile

    # ── 3. LLM fallback ──
    if call_llm:
        llm_profile = await _llm_classify(query, call_llm)
        if not skip_wikidata and llm_profile.target_type in ("person", "company", "organization"):
            llm_profile = await _wikidata_enrich(llm_profile)
        return llm_profile

    # ── 4. Nothing worked ──
    return TargetProfile(
        target_type="topic",
        primary_name=query.strip(),
        confidence=0.2,
        raw_query=query,
        classified_by="none",
    )
