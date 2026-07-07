"""Entity resolution — deduplicate, merge aliases, propagate confidence."""

from __future__ import annotations
from dataclasses import dataclass, field
import re
import hashlib
import logging

logger = logging.getLogger("watson.resolution")

# ── Data model ────────────────────────────────────────────────

@dataclass
class ResolvedEntity:
    canonical: str                       # best display form
    etype: str                           # person | email | handle | domain | company | other
    core: str                            # identity fingerprint
    aliases: set[str] = field(default_factory=set)
    finding_ids: set[str] = field(default_factory=set)
    agents: set[str] = field(default_factory=set)
    confidence: float = 0.0              # resolved confidence after propagation
    link_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "canonical": self.canonical,
            "type": self.etype,
            "aliases": sorted(self.aliases),
            "source_count": len(self.agents),
            "finding_count": len(self.finding_ids),
            "agents": sorted(self.agents),
            "confidence": round(self.confidence, 3),
            "tier": _tier(self.confidence),
            "link_reasons": self.link_reasons,
        }


def _tier(c: float) -> str:
    if c >= 0.95: return "CONFIRMED"
    if c >= 0.70: return "PROBABLE"
    if c >= 0.40: return "POSSIBLE"
    if c >= 0.10: return "UNLIKELY"
    return "UNSUBSTANTIATED"


# ── Entity extraction ────────────────────────────────────────

_EXTRACT_EMAIL = re.compile(r"\b([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})\b", re.I)
_EXTRACT_PERSON = re.compile(r"\b([A-Z][a-z]+(?: [A-Z][a-z]+){1,2})\b")
_EXTRACT_DOMAIN = re.compile(r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:com|org|net|io|gov|ru|cn|de|uk|fr))\b", re.I)

# Organization indicators — suffixes that signal an organization, not a person
_ORG_INDICATORS = {
    "Inc", "LLC", "Ltd", "Corp", "Corporation", "GmbH", "SA", "AG", "PLC",
    "Group", "Holdings", "Limited", "Solutions", "Technologies", "Systems",
    "Partners", "Capital", "Ventures", "Enterprises", "Industries", "Associates",
    "International", "Global", "Bank", "Foundation", "Institute", "University",
    "College", "School", "Academy", "Hospital", "Media", "Network", "Agency",
    "Authority", "Department", "Ministry", "Bureau", "Office", "Commission",
    "Council", "Committee", "Organization", "Association", "Federation",
    "Union", "Alliance", "Coalition", "Party", "Movement",
}

# Common first names — if first token is a first name, entity is probably a person
_PERSON_FIRST_NAMES = {
    "Dmitry", "Dmitri", "Vladimir", "Sergey", "Alexei", "Mikhail", "Nikolai",
    "Ivan", "Andrei", "Alexander", "Boris", "Yuri", "Viktor", "Pavel", "Anton",
    "Roman", "Denis", "Oleg", "Igor", "Evgeny", "Konstantin", "Maxim", "Artem",
    "Donald", "Jeffrey", "Elon", "Bill", "Steve", "Mark", "John", "David",
    "Michael", "Robert", "James", "William", "Richard", "Joseph", "Thomas",
    "Charles", "Christopher", "Daniel", "Matthew", "Anthony", "George",
    "Lorenzo", "Giovanni", "Marco", "Andrea", "Francesco", "Alessandro",
}


def _is_organization_name(name: str) -> bool:
    """Heuristic: does this name look like an organization?"""
    tokens = name.split()
    # If last token is an org indicator, it's an org
    if tokens[-1] in _ORG_INDICATORS:
        return True
    # If it contains an org indicator anywhere
    if any(t in _ORG_INDICATORS for t in tokens):
        return True
    # If name has 1 token and it's not a first name
    if len(tokens) == 1 and tokens[0] not in _PERSON_FIRST_NAMES:
        return True
    return False


def _entity_has_digits(name: str) -> bool:
    """People don't have version numbers."""
    return bool(re.search(r"\d", name))


# Noise phrases — things that should never become entities
_NOISE_PHRASES = {
    # Web chrome / navigation
    "Public Affairs", "Key Takeaways", "Not Found", "Contact Us",
    "Terms of Service", "Privacy Policy", "All Rights Reserved",
    "Learn More", "Read More", "Click Here", "Subscribe",
    "Related Articles", "Recommended", "Trending", "Popular",
    "Breaking News", "Latest News", "Top Stories", "Featured",
    "Advertisement", "Sponsored", "Cookie Policy", "Accept Cookies",
    "Log In", "Sign Up", "Join Facebook", "Instagram Lite",
    "Update Substack", "Contact Uploading", "User Agreement",
    "About Us", "Contact Us", "Get Started", "Sign In",
    "Press Esc", "Mini Series", "Tesla Gallery", "Tesla Download",
    # YouTube/Google footer boilerplate
    "How Lisa Bowman", "Leveraged Major Press", "About Press Copyright",
    "Creators Advertise Developers", "Safety How", "Simplified Management",
    "Wikipedia Sports", "Frappe Press With", "Press Esc",
    # Scraped geography artifacts
    "United States Discovered", "United States Connection",
    "Canada Connection", "Canada Discovered",
    "Japan Connection", "Japan Discovered",
    "Germany Connection", "Germany Discovered",
    "Australia Connection", "Australia Discovered",
    "Brazil Connection", "Brazil Discovered",
    # Service/tech names that aren't people
    "Wayback Machine", "Confidence Assessment", "Service Identification",
    # Article/section headers
    "Executive Summary", "Key Findings", "Notable Entities",
    "Evidence Gaps", "Recommended Next", "Source Appendix",
    "Data Ethics", "Risk Themes", "Next Steps",
    # Generic capitalized noun phrases
    "New York", "Los Angeles", "San Francisco", "Hong Kong",
    "United States", "United Kingdom", "South Africa", "Shibuya City",
}

# Bad tokens — if any token in an entity matches these, it's NOT a person.
# Trade-off: rare surnames like "Hong" are lost to prevent "Hong Kong" as person.
_BAD_TOKENS = {
    # Geographic
    "hong", "kong", "holy", "land", "crusades",
    # Web/app chrome
    "app", "store", "chat", "developer", "timeline",
    # News/org suffixes
    "news", "emails", "email", "media", "network", "agency",
    # Tech companies
    "cloudflare", "microsoft", "bing", "google", "facebook",
    "instagram", "twitter", "reddit", "substack",
    # Political/geographic
    "russian", "state", "supporters", "empire", "flippers",
    # Tech terms
    "deepfake", "video", "makers", "big", "role", "manage",
    "preferences", "open", "mic", "crushai",
    # Articles
    "the", "this", "that", "these", "those",
    # Web chrome words
    "cookie", "policy", "uploading", "join", "lite", "update",
    "contact", "agreement", "sign", "log",
    # Footer boilerplate words (prevents "About Press Copyright", "Safety How", etc.)
    "copyright", "creators", "advertise", "developers", "safety",
    "leveraged", "simplified", "management", "frappe", "esc",
    "how", "about", "press", "wikipedia", "sports",
    "mini", "series", "gallery", "download",
    # Scraped geo artifacts
    "discovered", "connection",
    # LLM-generated garbage (observed from dark/gap phases)
    "arrested", "cartel", "super", "longman", "pronunciation",
    "dictionary", "pearson", "ransomware", "breach", "jail",
    "primary", "target", "final", "assessment", "sand", "dune",
    "padel", "financial", "investigation", "geospatial", "analysis",
    "language", "search", "results", "offshore", "company",
    "infrastructure", "identified", "cybercrime", "indicators",
    "digital", "footprint", "presence", "detected", "overall",
    "confidence", "forum", "discussions", "mentions",
    "marketplaces", "mixing", "services", "private", "channels",
    "leak", "pastebin", "extradited", "wanted", "sanctioned",
    "sanctions", "evasion", "relevance", "lieutenant", "active",
    # Verdict/sentencing terms that shouldn't be entities
    "charges", "conviction", "sentence", "sentencing", "remarks",
    "pleaded", "guilty", "court", "criminal", "legal",
    "victim", "murder", "organisation", "affiliation",
    # ── More LLM/title fragment garbage ──
    "schuste", "economist", "publisher", "benzinga", "motors",
    "directors", "what", "call", "follow", "story", "inside",
}

# Article prefixes that disqualify person names
_ARTICLE_PREFIXES = {"The", "A", "An"}


def _is_entity_noise(text: str) -> bool:
    """Filter out garbage that looks like entities but isn't."""
    t = text.strip()
    if len(t) < 3 or len(t) > 80:
        return True
    if t in _NOISE_PHRASES:
        return True
    if t.startswith(("http://", "https://", "www.")):
        return True
    # Python module paths
    if t.startswith(("watson.", "src.watson.", "watson/", "src/")):
        return True
    return False


def _has_bad_token(name: str) -> bool:
    """Check if any token in the name is in the bad tokens denylist."""
    tokens = name.lower().replace(".", " ").split()
    return any(tok in _BAD_TOKENS for tok in tokens)


def _has_article_prefix(name: str) -> bool:
    """Check if name starts with an article (The, A, An) — disqualifies as person."""
    tokens = name.split()
    if tokens and tokens[0] in _ARTICLE_PREFIXES and len(tokens) > 1:
        return True
    return False


def _extract_entities_from_text(text: str) -> list[tuple[str, str]]:
    """Pull (value, type) entity candidates from text using spaCy-validated NER.

    Delegates to the spaCy hybrid NER module for high-precision extraction.
    Falls back to regex if spaCy is unavailable.
    """
    try:
        from .ner import extract_entities_from_text as _ner_extract
        return _ner_extract(text)
    except ImportError:
        pass

    # ── Regex fallback (legacy) ──
    out: list[tuple[str, str]] = []
    if not text:
        return out

    for m in _EXTRACT_EMAIL.finditer(text):
        val = m.group(1)
        if not _is_entity_noise(val):
            out.append((val, "email"))

    for m in _EXTRACT_DOMAIN.finditer(text):
        val = m.group(1)
        if not _is_entity_noise(val):
            out.append((val, "domain"))

    for m in _EXTRACT_PERSON.finditer(text):
        val = m.group(1)
        if _is_entity_noise(val):
            continue
        if _has_article_prefix(val):
            continue
        if _has_bad_token(val):
            continue
        if _is_organization_name(val):
            continue
        # Require at least one token to be a known first name OR proper surname pattern.
        # This prevents "Book Review", "Board Members", "Fantastic Future" etc.
        # from being classified as person entities.
        tokens = val.split()
        has_known_name = any(t in _PERSON_FIRST_NAMES for t in tokens)
        # Also accept: tokens that look like surnames (capitalized, 3+ chars, not common words)
        _COMMON_NOUNS = {"Book", "Review", "Board", "Members", "Professional", "Profile",
                         "Future", "Biography", "Principal", "Shareholder", "Founder",
                         "Director", "Officer", "President", "Manager", "Analyst",
                         "Case", "Number", "Court", "District", "State", "County",
                         "Country", "City", "Government", "Department", "Ministry",
                         "Efficiency", "Technology", "Entrepreneur", "Chair", "Under",
                         "After", "Before", "View", "Call", "What", "Your", "Our",
                         "Alumni", "Note", "Lawsuit", "Compensation", "Fine", "Million",
                         "Bestselling", "Fantastic", "Medium", "Shortform", "Books",
                         # ── Title fragments misclassified as persons ──
                         "Official", "Publisher", "Page", "Users", "Call", "Follow",
                         "Story", "Schuste", "Inside", "Ultimate", "Ultimate",
                         "Economist", "Benzinga", "York", "Times", "What",
                         "Directors", "Motors", "Corp", "Inc", "LLC"}
        looks_like_surname = any(
            t[0].isupper() and len(t) >= 3 and t not in _COMMON_NOUNS
            for t in tokens
        )
        if not (has_known_name or looks_like_surname):
            continue
        out.append((val, "person"))

    return out


# ── Public API (test-compatible) ──────────────────────────────

def resolve_entities(findings: list) -> list[ResolvedEntity]:
    """Resolve and deduplicate entities from findings.
    
    Returns resolved entities (without cross-reference patterns).
    """
    entities, _ = build_intelligence_picture(findings)
    return entities


def propagate_confidence(findings: list, entities: list[ResolvedEntity]) -> list[ResolvedEntity]:
    """Propagate and adjust confidence based on corroboration.
    
    - Single-source entities are capped below CONFIRMED (0.85 max)
    - Multi-source entities get boosted by corroboration
    """
    for e in entities:
        n_sources = len(e.agents) if e.agents else len(e.finding_ids)
        if n_sources <= 1:
            # Single source — cap below CONFIRMED
            e.confidence = min(e.confidence, 0.85)
        else:
            # Multi-source — boost by corroboration
            boost = min(0.15, (n_sources - 1) * 0.05)
            e.confidence = min(0.99, e.confidence + boost)
    return entities


def cross_reference_advanced(
    findings: list,
    blocked: list | None = None,
) -> list[dict]:
    """Cross-reference findings and blocked vectors.
    
    Returns patterns list with typed dicts:
    - entity_corroboration: same entity across multiple agents
    - adversarial_posture: blocked tools indicating target countermeasures
    - confidence_summary: aggregate confidence stats
    """
    patterns = []
    
    # Build intelligence picture from findings
    if findings:
        entities, entity_patterns = build_intelligence_picture(findings)
        
        # Entity corroboration patterns
        for e in entities:
            if len(e.agents) >= 2 or len(e.finding_ids) >= 2:
                patterns.append({
                    "type": "entity_corroboration",
                    "entity": e.canonical,
                    "entity_type": e.etype,
                    "sources": sorted(e.agents) if e.agents else [],
                    "confidence": e.confidence,
                    "count": len(e.finding_ids),
                })
        
        # Add entity patterns from build_intelligence_picture
        for p in entity_patterns:
            if p.get("type") == "shared_source":
                patterns.append({
                    "type": "entity_corroboration",
                    "entity": f"{p['source']} ↔ {p['target']}",
                    "connection": p.get("connection", ""),
                    "strength": p.get("strength", 0),
                })
        
        # Confidence summary
        total = len(findings)
        high = sum(1 for f in findings if getattr(f, "confidence", 0) >= 0.70)
        mid = sum(1 for f in findings if 0.40 <= getattr(f, "confidence", 0) < 0.70)
        low = sum(1 for f in findings if getattr(f, "confidence", 0) < 0.40)
        patterns.append({
            "type": "confidence_summary",
            "total_findings": total,
            "high_confidence_count": high,
            "medium_confidence_count": mid,
            "low_confidence_count": low,
        })
    else:
        # Empty findings — still return empty confidence summary
        patterns.append({
            "type": "confidence_summary",
            "total_findings": 0,
            "high_confidence_count": 0,
            "medium_confidence_count": 0,
            "low_confidence_count": 0,
        })
    
    # Adversarial posture from blocked tools
    if blocked:
        for b in blocked:
            if b.get("is_intelligence"):
                patterns.append({
                    "type": "adversarial_posture",
                    "agent": b.get("agent", "unknown"),
                    "failure_reason": b.get("failure_reason", "unknown"),
                    "alternatives": b.get("alternatives", []),
                    "assessment": "Target may have active countermeasures",
                })
    
    return patterns


# ── Entity classification helpers (test-compatible) ──────────

def _classify_entity(text: str) -> str:
    """Classify an entity string by type."""
    import re
    text = text.strip()
    
    # Email
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', text):
        return "email"
    
    # Domain
    if re.match(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', text, re.I):
        return "domain"
    
    # Person (2+ capitalized words) — validate with spaCy
    if re.match(r'^[A-Z][a-z]+ [A-Z][a-z]+', text):
        try:
            from .ner import _spacy_validate_person, _is_garbage_person
            if _is_garbage_person(text):
                return "other"
            if _spacy_validate_person(text, strict_person_only=True):
                return "person"
            return "other"  # spaCy disagrees or says ORG — not a person
        except ImportError:
            return "person"
    
    # Handle (contains underscore, digits, or @)
    if '_' in text or '@' in text or any(c.isdigit() for c in text):
        return "handle"
    
    return "other"


def _normalize(text: str, etype: str) -> str:
    """Normalize an entity for deduplication."""
    text = text.strip().lower()
    
    if etype == "email":
        # Gmail: remove dots from local part
        if "@" in text:
            local, domain = text.split("@", 1)
            if domain == "gmail.com":
                local = local.replace(".", "")
            # For cross-type matching, normalize to just the local part
            # so email "baron.lorenzo99@gmail.com" → "baronlorenzo99"
            # This allows email+handle merging
            return local
        return text
    
    if etype == "handle":
        # Normalize separators (., _ → nothing)
        return text.replace(".", "").replace("_", "")
    
    return text


def _person_token_overlap(name: str, handle: str) -> bool:
    """Check if a person name and handle share enough tokens to be the same entity."""
    name_tokens = [t.lower() for t in name.replace(".", " ").split() if len(t) > 2]
    handle_lower = handle.lower()
    if not name_tokens:
        return False
    # Check if any name token appears as a substring in the handle
    for token in name_tokens:
        if token in handle_lower:
            return True
    return False

def _fingerprint(text: str) -> str:
    """Create a stable identity fingerprint."""
    return hashlib.sha256(text.lower().strip().encode()).hexdigest()[:16]


def build_intelligence_picture(
    findings: list,
) -> tuple[list[ResolvedEntity], list]:
    """Build resolved entity list from findings. Returns (entities, link_patterns)."""
    
    # Step 1: Extract raw entities from all findings
    # (name, type, finding_title, confidence, agent)
    raw_entities: list[tuple[str, str, str, float, str]] = []
    
    for f in findings:
        fid = getattr(f, "title", str(f))[:60]
        conf = getattr(f, "confidence", 0.5)
        agent = getattr(f, "agent", None)
        agent_name = agent.value if hasattr(agent, "value") else str(agent) if agent else ""
        
        # Use structured entities field if available
        ents = getattr(f, "entities", None)
        if ents and isinstance(ents, list):
            for e in ents:
                if isinstance(e, dict):
                    name = e.get("value", e.get("name", ""))
                    etype = e.get("type", "other")
                elif isinstance(e, (list, tuple)) and len(e) >= 2:
                    name, etype = e[0], e[1]
                else:
                    name, etype = str(e), "other"
                if name and not _is_entity_noise(name):
                    raw_entities.append((name, etype, fid, conf, agent_name))
        else:
            # Fallback: extract from text — but only for non-trash findings
            conf = getattr(f, "confidence", 0.5)
            tier = getattr(f, "tier", "")
            if conf >= 0.35 or tier in ("PRIMARY", "SECONDARY", "PROBABLE", "CONFIRMED"):
                text = f"{getattr(f, 'title', '')} {getattr(f, 'description', '')}"
                for name, etype in _extract_entities_from_text(text):
                    raw_entities.append((name, etype, fid, conf, agent_name))
    
    if not raw_entities:
        return [], []
    
    # Step 2: Classify and normalize each entity
    classified = []
    for name, etype, fid, conf, agent in raw_entities:
        # If type is not given or "other", classify
        if etype in ("other", ""):
            etype = _classify_entity(name)
        # ── spaCy quality gate: validate LLM person hints ──
        if etype == "person":
            try:
                from .ner import _spacy_validate_person, _is_garbage_person
                if _is_garbage_person(name) or not _spacy_validate_person(name, strict_person_only=True):
                    etype = "other"
            except ImportError:
                pass
        
        # Normalize for grouping
        normalized = _normalize(name, etype)
        
        # For handles, also check if they match any known person name
        classified.append((name, etype, normalized, fid, conf, agent))
    
    # Step 3: Group by normalized form
    groups: dict[str, list[tuple[str, str, str, str, float, str]]] = {}
    for name, etype, norm, fid, conf, agent in classified:
        if norm not in groups:
            groups[norm] = []
        groups[norm].append((name, etype, norm, fid, conf, agent))
    
    # Step 3b: Cross-type merging — persons linked to handles/emails
    # If a person name has token overlap with a handle, merge them
    merge_map: dict[str, str] = {}  # norm → target_norm
    person_norms = {n: entries for n, entries in groups.items()
                    if any(e[1] == "person" for e in entries)}
    handle_norms = {n: entries for n, entries in groups.items()
                    if any(e[1] in ("handle", "email") for e in entries)}
    
    for p_norm, p_entries in person_norms.items():
        for h_norm, h_entries in handle_norms.items():
            if p_norm == h_norm:
                continue
            # Check if any person name overlaps with any handle
            for pe in p_entries:
                p_name = pe[0]
                for he in h_entries:
                    h_name = he[0]
                    if _person_token_overlap(p_name, h_name):
                        # Merge handle into person (or vice versa)
                        merge_map[h_norm] = p_norm
                        break
    
    # Apply merges
    if merge_map:
        merged_groups: dict[str, list] = {}
        for norm, entries in groups.items():
            target = merge_map.get(norm, norm)
            # Follow chain
            while target in merge_map and target != merge_map[target]:
                target = merge_map[target]
            if target not in merged_groups:
                merged_groups[target] = []
            merged_groups[target].extend(entries)
        groups = merged_groups
    
    # Step 4: Resolve each group
    resolved = []
    for norm, entries in groups.items():
        # Pick canonical name (longest, non-empty)
        names = sorted(set(e[0] for e in entries), key=len, reverse=True)
        canonical = names[0] if names else entries[0][0]
        
        # Pick best type
        types = [e[1] for e in entries if e[1] not in ("other", "")]
        etype = types[0] if types else "other"
        
        # If entity has digits, it's NOT a person
        if etype == "person" and _entity_has_digits(canonical):
            etype = "other"
        # If it looks like an org, it's not a person
        if etype == "person" and _is_organization_name(canonical):
            etype = "company"
        
        # Compute confidence — weighted by source count
        n_sources = len(set(e[3] for e in entries))
        avg_conf = sum(e[4] for e in entries) / len(entries)
        # Boost: more sources = higher confidence
        confidence = min(0.99, avg_conf + (n_sources - 1) * 0.05)
        
        # Collect agents
        agents = set(e[5] for e in entries if e[5])
        
        resolved.append(ResolvedEntity(
            canonical=canonical,
            etype=etype,
            core=norm,
            aliases=set(n for n, _, _, _, _, _ in entries),
            finding_ids=set(e[3] for e in entries),
            agents=agents,
            confidence=confidence,
            link_reasons=[f"Resolved from {n_sources} sources"],
        ))
    
    # Sort by confidence
    resolved.sort(key=lambda e: e.confidence, reverse=True)
    
    # Step 5: Cross-reference patterns
    patterns = _build_cross_references(resolved, classified)
    
    # Add entity_resolution patterns
    for e in resolved:
        if e.aliases:
            patterns.append({
                "type": "entity_resolution",
                "entity": e.canonical,
                "aliases": sorted(e.aliases)[:5],
                "sources": len(e.finding_ids),
            })
    
    return resolved, patterns[:20]


def _build_cross_references(
    resolved: list[ResolvedEntity],
    raw: list[tuple[str, str, str, float]],
) -> list[dict]:
    """Find connections between resolved entities."""
    patterns = []
    
    for i, e1 in enumerate(resolved):
        for e2 in resolved[i + 1:]:
            # Entities that share finding_ids are connected
            shared = e1.finding_ids & e2.finding_ids
            if shared:
                patterns.append({
                    "source": e1.canonical,
                    "target": e2.canonical,
                    "connection": f"Shared {len(shared)} sources",
                    "type": "shared_source",
                    "strength": len(shared),
                })
    
    return patterns[:20]
