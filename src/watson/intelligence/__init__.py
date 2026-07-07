"""
Intelligence production layer for Watson OSINT.

Transforms raw findings into structured intelligence:
  - Evidence-based confidence scoring (source tiering + corroboration)
  - Entity relationship inference (co-occurrence → typed links)
  - Temporal chain extraction (date parsing → chronological timeline)
  - Pattern detection (modular, target-type-aware)

Design principles:
  - Zero network calls — operates on already-collected data
  - Target-agnostic reasoning — same logic for persons, companies, domains
  - Confidence from evidence, not LLM vibes
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("watson.intel")


# ═══════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════

@dataclass
class EvidenceConfidence:
    """Confidence score with full evidence trail."""
    score: float             # 0.0–1.0
    tier: str                # CONFIRMED | PROBABLE | POSSIBLE | UNLIKELY | UNSUBSTANTIATED
    source_count: int        # how many independent sources
    source_tiers: list[str]  # which tiers contributed
    corroboration_boost: float
    hallucination_risk: float  # 0.0–1.0, higher = likely LLM invention
    reasoning: str           # human-readable explanation


@dataclass
class EntityRelationship:
    """Typed connection between two entities with evidence."""
    source: str          # entity value
    source_type: str     # person | organization | domain | email | wallet | ip
    target: str
    target_type: str
    relationship: str    # co_founded | works_at | owns | resolves_to | located_in | co_occurs_with
    confidence: float
    evidence_finding_ids: list[str]
    evidence_summary: str


@dataclass
class TimelineEvent:
    """A dated event extracted from findings."""
    date: str            # ISO format or partial (YYYY, YYYY-MM)
    precision: str       # year | month | day
    event: str           # description
    category: str        # legal | financial | career | personal | infrastructure | other
    source_finding_id: str
    source_url: str
    confidence: float


@dataclass
class IntelligenceProduct:
    """Structured intelligence from raw findings."""
    confidence_scores: dict[str, EvidenceConfidence]   # finding_id → confidence
    relationships: list[EntityRelationship]
    timeline: list[TimelineEvent]
    adversarial_signals: list[dict]
    entity_corroboration: dict[str, int]               # entity → source count


# ═══════════════════════════════════════════════════════════════
# Source credibility tiers
# ═══════════════════════════════════════════════════════════════

SOURCE_TIER_WEIGHTS = {
    "PRIMARY":   1.0,   # Court records, SEC filings, official registries
    "SECONDARY": 0.75,  # Established media, Wikipedia, published research
    "TERTIARY":  0.45,  # Blogs, forums, social media, web search snippets
    "UNVERIFIED": 0.2,  # Anonymous sources, uncorroborated claims
    "UNKNOWN":   0.15,
}

SOURCE_TYPE_CREDIBILITY = {
    # Government / Legal (PRIMARY)
    "pacer":       ("PRIMARY", 0.95),
    "sec_edgar":   ("PRIMARY", 0.95),
    "court":       ("PRIMARY", 0.95),
    "opencorporates": ("PRIMARY", 0.90),
    "opensanctions":  ("PRIMARY", 0.90),
    "wikidata":    ("SECONDARY", 0.85),

    # Infrastructure (SECONDARY — deterministic, hard to fake)
    "crtsh":       ("SECONDARY", 0.85),
    "dns_resolve": ("SECONDARY", 0.85),
    "whois":       ("SECONDARY", 0.80),
    "shodan":      ("SECONDARY", 0.80),
    "censys":      ("SECONDARY", 0.80),

    # Breach / Identity
    "hibp":         ("SECONDARY", 0.85),
    "holehe":       ("SECONDARY", 0.80),
    "sherlock":     ("SECONDARY", 0.75),

    # Web — variable credibility
    "wikipedia":    ("SECONDARY", 0.80),
    "web_search":   ("TERTIARY", 0.50),
    "employee_pivot": ("TERTIARY", 0.55),
    "web_extract":  ("TERTIARY", 0.40),
    "wikipedia_extract": ("SECONDARY", 0.70),

    # LLM-generated — inherently unreliable
    "llm_synthesis": ("UNVERIFIED", 0.25),
    "llm_deep_dive": ("UNVERIFIED", 0.25),
    "llm_analysis":  ("UNVERIFIED", 0.20),

    # Scrapers
    "scraper":      ("TERTIARY", 0.40),
    "dark_web":     ("TERTIARY", 0.35),
}

# Sources that are purely LLM-invented (no external source URL)
_HALLUCINATION_RISK_SOURCES = {
    "llm_synthesis", "llm_deep_dive", "llm_analysis",
}

# URLs that indicate LLM hallucination (no real source)
_HALLUCINATION_URL_PATTERNS = [
    r"^$",                          # empty URL
    r"^https?://localhost",
    r"^none$", r"^n/a$", r"^unknown$",
]


# ═══════════════════════════════════════════════════════════════
# Confidence Scoring
# ═══════════════════════════════════════════════════════════════

def score_finding_confidence(finding) -> EvidenceConfidence:
    """Score a single finding's confidence based on source quality and evidence.

    Replaces the current LLM-assigned confidence with a deterministic,
    auditable score based on:
      1. Source type credibility
      2. Source tier (PRIMARY > SECONDARY > TERTIARY > UNVERIFIED)
      3. Presence of a verifiable source URL
      4. Corroboration potential (will be boosted later)

    Args:
        finding: A Finding object (or dict with 'source_type', 'source_url',
                 'source_tier', 'confidence' keys)

    Returns:
        EvidenceConfidence with score, tier, and reasoning.
    """
    source_type = getattr(finding, "source_type", "") or ""
    source_url = getattr(finding, "source_url", "") or ""
    source_tier = getattr(finding, "source_tier", "") or ""

    # Step 1: Base score from source type credibility table
    type_info = SOURCE_TYPE_CREDIBILITY.get(source_type, ("UNKNOWN", 0.15))
    base_tier, base_score = type_info

    # Step 2: If source_tier is explicitly set and better than the type default,
    # use it (e.g. crt.sh marked as SECONDARY but source_type lookup says SECONDARY)
    explicit_weight = SOURCE_TIER_WEIGHTS.get(source_tier, 0)
    if explicit_weight > base_score:
        base_score = explicit_weight

    # Step 3: Hallucination check
    hallucination_risk = 0.0
    if source_type in _HALLUCINATION_RISK_SOURCES:
        hallucination_risk = 0.9
    if not source_url or source_url.strip() == "":
        hallucination_risk = max(hallucination_risk, 0.7)
    for pattern in _HALLUCINATION_URL_PATTERNS:
        if re.match(pattern, source_url, re.IGNORECASE):
            hallucination_risk = max(hallucination_risk, 0.8)

    # Step 4: URL presence bonus (verifiable sources are more credible)
    url_bonus = 0.0
    if source_url and hallucination_risk < 0.3:
        # Real URL from a web source adds credibility
        if source_type in ("web_search", "employee_pivot", "web_extract", "wikipedia_extract"):
            url_bonus = 0.10
        else:
            url_bonus = 0.05

    # Step 5: Content length heuristic (empty/vague findings = low confidence)
    description = getattr(finding, "description", "") or ""
    title = getattr(finding, "title", "") or ""
    content_len = len(description) + len(title)
    content_penalty = 0.0
    if content_len < 30:
        content_penalty = 0.30
    elif content_len < 80:
        content_penalty = 0.15

    # Step 6: Apply hallucination penalty
    if hallucination_risk > 0.5:
        base_score *= (1.0 - hallucination_risk)
        base_score = max(base_score, 0.05)

    # Compose final score
    score = base_score + url_bonus - content_penalty
    score = max(0.01, min(1.0, score))  # clamp

    # Determine tier
    if score >= 0.85:
        tier = "CONFIRMED"
    elif score >= 0.70:
        tier = "PROBABLE"
    elif score >= 0.40:
        tier = "POSSIBLE"
    elif score >= 0.10:
        tier = "UNLIKELY"
    else:
        tier = "UNSUBSTANTIATED"

    # Build reasoning
    reasons = [f"source_type={source_type} (base={base_score:.2f})"]
    if url_bonus:
        reasons.append(f"url_bonus=+{url_bonus:.2f}")
    if content_penalty:
        reasons.append(f"content_penalty=-{content_penalty:.2f}")
    if hallucination_risk > 0:
        reasons.append(f"hallucination_risk={hallucination_risk:.2f}")

    return EvidenceConfidence(
        score=round(score, 3),
        tier=tier,
        source_count=1,
        source_tiers=[source_tier or base_tier],
        corroboration_boost=0.0,
        hallucination_risk=round(hallucination_risk, 2),
        reasoning=" | ".join(reasons),
    )


def apply_corroboration(confidence_scores: dict[str, EvidenceConfidence],
                         findings: list) -> dict[str, EvidenceConfidence]:
    """Boost confidence for findings corroborated by other findings.

    Two findings corroborate each other if:
      - They mention the same entities
      - They describe similar facts (title overlap)
      - They come from different source URLs
    """
    # Build entity → finding_id index
    entity_to_findings: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        fid = getattr(f, "id", str(f))
        ents = getattr(f, "entities", []) or []
        for e in ents:
            if isinstance(e, dict):
                name = (e.get("value") or e.get("name") or "").lower().strip()
                if name:
                    entity_to_findings[name].add(fid)

    # Build URL → finding_id index
    url_to_findings: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        fid = getattr(f, "id", str(f))
        url = (getattr(f, "source_url", "") or "").strip()
        if url:
            url_to_findings[url].add(fid)

    # For each finding, count corroborating findings
    for f in findings:
        fid = getattr(f, "id", str(f))
        if fid not in confidence_scores:
            continue

        corroborators: set[str] = set()
        ents = getattr(f, "entities", []) or []
        for e in ents:
            if isinstance(e, dict):
                name = (e.get("value") or e.get("name") or "").lower().strip()
                if name in entity_to_findings:
                    corroborators.update(entity_to_findings[name])

        # Remove self
        corroborators.discard(fid)

        # Only count corroborators from different URLs
        my_url = (getattr(f, "source_url", "") or "").strip()
        unique_sources = set()
        for cfid in corroborators:
            # Find the corroborating finding's URL
            for f2 in findings:
                if getattr(f2, "id", str(f2)) == cfid:
                    cf_url = (getattr(f2, "source_url", "") or "").strip()
                    if cf_url and cf_url != my_url:
                        unique_sources.add(cf_url)
                    break

        # Boost: each corroborating source adds 0.05, capped at 0.20
        n_corroborators = len(unique_sources)
        boost = min(0.20, n_corroborators * 0.05)

        if boost > 0:
            cs = confidence_scores[fid]
            new_score = min(1.0, cs.score + boost)
            cs.score = round(new_score, 3)
            cs.corroboration_boost = round(boost, 3)
            cs.source_count = 1 + n_corroborators
            cs.reasoning += f" | corroborated_by={n_corroborators}_sources (+{boost:.2f})"

            # Re-tier
            if new_score >= 0.85:
                cs.tier = "CONFIRMED"
            elif new_score >= 0.70:
                cs.tier = "PROBABLE"

    return confidence_scores


# ═══════════════════════════════════════════════════════════════
# Entity Relationship Inference
# ═══════════════════════════════════════════════════════════════

def infer_relationships(findings: list,
                        confidence_scores: dict[str, EvidenceConfidence],
                        ) -> list[EntityRelationship]:
    """Infer typed relationships between entities based on co-occurrence.

    Two entities that appear in the same finding have a relationship.
    The relationship type is inferred from:
      - The finding's source_type / phase
      - Entity types (person+org → works_at, domain+ip → resolves_to, etc.)
      - Explicit role hints in entity metadata
    """
    relationships: list[EntityRelationship] = []
    seen_pairs: set[tuple[str, str]] = set()

    for f in findings:
        fid = getattr(f, "id", str(f))
        ents = getattr(f, "entities", []) or []
        source_type = getattr(f, "source_type", "") or ""
        phase = getattr(f, "phase", "") or ""
        source_url = getattr(f, "source_url", "") or ""

        if len(ents) < 2:
            continue

        # Get confidence for this finding
        cs = confidence_scores.get(fid)
        base_conf = cs.score if cs else 0.3

        for i in range(len(ents)):
            for j in range(i + 1, len(ents)):
                e1 = ents[i] if isinstance(ents[i], dict) else {"value": str(ents[i]), "type": ""}
                e2 = ents[j] if isinstance(ents[j], dict) else {"value": str(ents[j]), "type": ""}

                v1 = (e1.get("value") or e1.get("name") or "").strip()
                v2 = (e2.get("value") or e2.get("name") or "").strip()
                if not v1 or not v2 or v1 == v2:
                    continue

                t1 = (e1.get("type") or "").lower()
                t2 = (e2.get("type") or "").lower()
                role1 = (e1.get("role") or "").lower()
                role2 = (e2.get("role") or "").lower()

                # Canonical pair key
                pair_key = tuple(sorted([v1.lower(), v2.lower()]))
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                # Infer relationship type
                rel_type = _infer_relation_type(t1, t2, role1, role2, source_type, phase)

                relationships.append(EntityRelationship(
                    source=v1,
                    source_type=t1 or "other",
                    target=v2,
                    target_type=t2 or "other",
                    relationship=rel_type,
                    confidence=round(base_conf, 3),
                    evidence_finding_ids=[fid],
                    evidence_summary=f"Co-occur in {source_type}: {source_url}"[:200],
                ))

    return relationships


def _infer_relation_type(type1: str, type2: str,
                         role1: str, role2: str,
                         source_type: str, phase: str) -> str:
    """Infer the type of relationship between two entities."""
    types = {type1, type2}

    # Explicit role hints
    if "key_employee" in (role1, role2) and "organization" in types:
        return "works_at"
    if "ceo" in (role1, role2) or "founder" in (role1, role2):
        return "leads"
    if "subsidiary" in (role1, role2):
        return "subsidiary_of"

    # Person + Organization
    if "person" in types and ("organization" in types or "company" in types):
        if phase == "employee_pivot" or source_type == "employee_pivot":
            return "works_at"
        if source_type == "opencorporates":
            return "director_of"
        return "associated_with"

    # Domain + IP
    if "domain" in types and ("ip" in types or "ip_address" in types):
        return "resolves_to"

    # Organization + Domain
    if ("organization" in types or "company" in types) and "domain" in types:
        return "owns"

    # Email + Domain
    if "email" in types and "domain" in types:
        return "email_at"

    # Person + Location
    if "person" in types and "location" in types:
        return "located_in"

    # Wallet + Organization/Person
    if "wallet" in types and ("organization" in types or "company" in types or "person" in types):
        return "controlled_by"

    # Same type entities
    if type1 == type2 == "person":
        return "connected_to"
    if type1 == type2 == "organization" or type1 == type2 == "company":
        return "related_to"

    # Generic
    return "co_occurs_with"


# ═══════════════════════════════════════════════════════════════
# Timeline Extraction
# ═══════════════════════════════════════════════════════════════

_DATE_PATTERNS = [
    # ISO: 2024-03-15
    (re.compile(r'\b(\d{4})-(\d{2})-(\d{2})\b'), "day"),
    # ISO-ish: 2024-03
    (re.compile(r'\b(\d{4})-(\d{2})\b(?!-\d)'), "month"),
    # US: March 15, 2024 or Mar 15 2024
    (re.compile(r'\b(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|'
                 r'Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|'
                 r'Dec(?:ember)?)\s+(\d{1,2}),?\s+(\d{4})\b'), "day"),
    # Year only: 2024 (but only if it looks like a date, not a number)
    (re.compile(r'\b(19|20)(\d{2})\b'), "year"),
]

_MONTH_MAP = {
    "jan": 1, "january": 1, "feb": 2, "february": 2, "mar": 3, "march": 3,
    "apr": 4, "april": 4, "may": 5, "jun": 6, "june": 6, "jul": 7, "july": 7,
    "aug": 8, "august": 8, "sep": 9, "september": 9, "oct": 10, "october": 10,
    "nov": 11, "november": 11, "dec": 12, "december": 12,
}

_EVENT_CATEGORIES = {
    "founded": "career", "born": "career", "died": "personal",
    "arrested": "legal", "charged": "legal", "convicted": "legal",
    "sentenced": "legal", "indicted": "legal", "pleaded": "legal",
    "settled": "legal", "sued": "legal", "lawsuit": "legal",
    "filed": "legal", "court": "legal", "judge": "legal",
    "raised": "financial", "funding": "financial", "invested": "financial",
    "acquired": "financial", "merged": "financial", "ipo": "financial",
    "stock": "financial", "shares": "financial", "revenue": "financial",
    "valuation": "financial", "billion": "financial", "million": "financial",
    "hired": "career", "resigned": "career", "appointed": "career",
    "promoted": "career", "joined": "career", "left": "career",
    "launched": "infrastructure", "released": "infrastructure",
    "breach": "infrastructure", "hacked": "infrastructure",
    "sanction": "legal", "ofac": "legal",
}


def extract_timeline(findings: list) -> list[TimelineEvent]:
    """Extract dated events from finding text.

    Scans finding titles and descriptions for date patterns and
    creates a chronological timeline of events.
    """
    events: list[TimelineEvent] = []
    seen_events: set[str] = set()

    for f in findings:
        fid = getattr(f, "id", str(f))
        title = getattr(f, "title", "") or ""
        desc = getattr(f, "description", "") or ""
        source_url = getattr(f, "source_url", "") or ""
        source_type = getattr(f, "source_type", "") or ""
        conf = getattr(f, "confidence", 0.5) or 0.5
        text = f"{title} {desc}"

        for pattern, precision in _DATE_PATTERNS:
            for m in pattern.finditer(text):
                try:
                    if precision == "day":
                        if pattern is _DATE_PATTERNS[0][0]:  # ISO
                            y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
                            date_str = f"{y:04d}-{mo:02d}-{d:02d}"
                        else:  # US format
                            month_name = m.group(1).lower()
                            mo = _MONTH_MAP.get(month_name, 1)
                            d = int(m.group(2))
                            y = int(m.group(3))
                            date_str = f"{y:04d}-{mo:02d}-{d:02d}"
                    elif precision == "month":
                        y, mo = int(m.group(1)), int(m.group(2))
                        date_str = f"{y:04d}-{mo:02d}"
                    else:  # year
                        y = int(m.group(0))
                        if y < 1990 or y > 2030:
                            continue  # not a plausible year
                        date_str = f"{y:04d}"
                except (ValueError, IndexError):
                    continue

                # Extract event description — text surrounding the date
                span_start = max(0, m.start() - 50)
                span_end = min(len(text), m.end() + 100)
                event_text = text[span_start:span_end].strip()

                # Truncate to a reasonable sentence
                if len(event_text) > 150:
                    event_text = event_text[:147] + "..."

                # Deduplicate
                event_key = f"{date_str}|{event_text[:60]}"
                if event_key in seen_events:
                    continue
                seen_events.add(event_key)

                # Categorize
                category = "other"
                event_lower = event_text.lower()
                for keyword, cat in _EVENT_CATEGORIES.items():
                    if keyword in event_lower:
                        category = cat
                        break

                # Only include if confidence is reasonable
                if conf < 0.15:
                    continue

                events.append(TimelineEvent(
                    date=date_str,
                    precision=precision,
                    event=event_text,
                    category=category,
                    source_finding_id=fid,
                    source_url=source_url,
                    confidence=round(conf, 3),
                ))

    # Sort chronologically
    events.sort(key=lambda e: e.date)
    return events


# ═══════════════════════════════════════════════════════════════
# Adversarial Signal Detection
# ═══════════════════════════════════════════════════════════════

_ADVERSARIAL_INDICATORS = [
    ("whois_redacted", ["redacted for privacy", "redacted for privacy purposes",
                        "registration private", "whoisguard", "domains by proxy",
                        "perfect privacy", "contact privacy"]),
    ("privacy_registrar", ["namecheap", "njalla", "njal.la", "tucows",
                           "domains by proxy", "whoisguard"]),
    ("encrypted_email", ["protonmail", "proton.me", "tutanota", "tuta.io",
                         "mailfence", "ctemplar"]),
    ("cloudflare_proxy", ["cloudflare", "cf-proxied"]),
    ("no_breach_data", []),  # detected programmatically
    ("tor_hidden_service", [".onion"]),
    ("crypto_only", ["bitcoin", "ethereum", "monero", "cryptocurrency",
                     "blockchain.com", "binance.com"]),
]


def detect_adversarial_signals(findings: list) -> list[dict]:
    """Detect signals that indicate the target is practicing operational security.

    Returns list of signal dicts with {signal, detected, evidence}.
    """
    signals = []
    all_text = " ".join(
        f"{getattr(f, 'title', '')} {getattr(f, 'description', '')}"
        for f in findings
    ).lower()

    for signal_name, keywords in _ADVERSARIAL_INDICATORS:
        if signal_name == "no_breach_data":
            # Check if HIBP returned no results
            hibp_findings = [f for f in findings
                           if "hibp" in (getattr(f, "source_type", "") or "").lower()]
            if hibp_findings:
                # Check if any HIBP finding reported zero breaches
                no_breaches = any(
                    "0 breaches" in (getattr(f, "description", "") or "").lower() or
                    "no breaches" in (getattr(f, "description", "") or "").lower() or
                    "not found" in (getattr(f, "title", "") or "").lower()
                    for f in hibp_findings
                )
                if no_breaches:
                    signals.append({
                        "signal": "identity_hygiene",
                        "detected": True,
                        "severity": "low",
                        "detail": "Target email has no known breach history — consistent with good opsec or new identity",
                    })
            continue

        matched = [kw for kw in keywords if kw in all_text]
        if matched:
            signals.append({
                "signal": signal_name,
                "detected": True,
                "severity": "medium" if signal_name in ("encrypted_email", "no_breach_data") else "low",
                "detail": f"Found: {matched[0]}",
            })

    # If no signals at all, target shows no adversarial posture
    if not signals:
        signals.append({
            "signal": "no_adversarial_posture",
            "detected": False,
            "severity": "none",
            "detail": "No opsec indicators detected — target has visible digital footprint",
        })

    return signals


# ═══════════════════════════════════════════════════════════════
# Main intelligence production
# ═══════════════════════════════════════════════════════════════

def produce_intelligence(findings: list,
                         target_type: str = "",
                         ) -> IntelligenceProduct:
    """Transform raw findings into structured intelligence.

    Args:
        findings: List of Finding objects from the investigation pipeline.
        target_type: 'person' | 'company' | 'domain' | 'email' | 'wallet'

    Returns:
        IntelligenceProduct with scored confidence, relationships, timeline,
        and adversarial signals.
    """
    if not findings:
        return IntelligenceProduct(
            confidence_scores={},
            relationships=[],
            timeline=[],
            adversarial_signals=[],
            entity_corroboration={},
        )

    logger.info("producing_intelligence: %d findings, target=%s",
                len(findings), target_type or "unknown")

    # 1. Score each finding
    confidence_scores: dict[str, EvidenceConfidence] = {}
    for f in findings:
        fid = getattr(f, "id", str(f))
        confidence_scores[fid] = score_finding_confidence(f)

    # 2. Apply corroboration boosts
    confidence_scores = apply_corroboration(confidence_scores, findings)

    # 3. Infer entity relationships
    relationships = infer_relationships(findings, confidence_scores)

    # 4. Extract timeline
    timeline = extract_timeline(findings)

    # 5. Detect adversarial signals
    adversarial_signals = detect_adversarial_signals(findings)

    # 6. Count entity corroboration
    entity_corroboration: dict[str, int] = defaultdict(int)
    for f in findings:
        ents = getattr(f, "entities", []) or []
        for e in ents:
            if isinstance(e, dict):
                name = (e.get("value") or e.get("name") or "").strip().lower()
                if name:
                    entity_corroboration[name] += 1

    product = IntelligenceProduct(
        confidence_scores=confidence_scores,
        relationships=relationships,
        timeline=timeline,
        adversarial_signals=adversarial_signals,
        entity_corroboration=dict(entity_corroboration),
    )

    logger.info("intelligence_produced: %d scored, %d relationships, %d timeline events, %d adversarial signals",
                len(confidence_scores), len(relationships), len(timeline), len(adversarial_signals))

    return product
