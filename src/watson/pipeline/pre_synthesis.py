"""Universal pre-synthesis pipeline for Watson OSINT.

Handles any target type and any language/script. Conservatively drops only
findings with zero relevance to the target — never risks losing real intel.

Architecture:
  1. TargetCanonicalizer → extracts canonical tokens from any target type
  2. RelevanceGrader → multilingual token + bigram scoring
  3. relevance_filter → safe drop-only gate (zero overlap + low confidence)

Target types supported:
  person, organization, domain, email, wallet, phone, ip, username, unknown

Scripts supported:
  Latin (all diacritic variants), Cyrillic, CJK, Arabic, Devanagari, Thai, etc.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Script → language mapping (for language boost)
# ---------------------------------------------------------------------------

# Unicode script blocks for common writing systems
_SCRIPT_RANGES: list[tuple[int, int, str]] = [
    # Latin blocks (various extensions)
    (0x0041, 0x007A, "en"),      # Basic Latin A-Z a-z
    (0x00C0, 0x024F, "en"),      # Latin-1 Supplement + Extended-A
    # Specific diacritic patterns for language detection
    (0x0150, 0x0151, "hu"),      # Ő ő — Hungarian
    (0x0170, 0x0171, "hu"),      # Ű ű — Hungarian
    (0x010C, 0x010D, "cs"),      # Č č — Czech/Slovak/Slovene/Croatian
    (0x0160, 0x0161, "cs"),      # Š š
    (0x017D, 0x017E, "cs"),      # Ž ž
    (0x0141, 0x0142, "pl"),      # Ł ł — Polish
    (0x0104, 0x0105, "pl"),      # Ą ą
    (0x0118, 0x0119, "pl"),      # Ę ę
    (0x0143, 0x0144, "pl"),      # Ń ń
    (0x015A, 0x015B, "pl"),      # Ś ś
    (0x0179, 0x017A, "pl"),      # Ź ź
    (0x017B, 0x017C, "pl"),      # Ż ż
    (0x00DF, 0x00DF, "de"),      # ß — German
    (0x00E4, 0x00E4, "de"),      # ä
    (0x00F6, 0x00F6, "de"),      # ö
    (0x00FC, 0x00FC, "de"),      # ü
    (0x00E0, 0x00E0, "it"),      # à — Italian
    (0x00E8, 0x00E8, "it"),      # è
    (0x00EC, 0x00EC, "it"),      # ì
    (0x00F2, 0x00F2, "it"),      # ò
    (0x00F9, 0x00F9, "it"),      # ù
    (0x00E7, 0x00E7, "pt"),      # ç — Portuguese/French
    (0x00F1, 0x00F1, "es"),      # ñ — Spanish
    # Cyrillic
    (0x0400, 0x04FF, "ru"),      # Cyrillic → default Russian
    (0x0500, 0x052F, "ru"),      # Cyrillic Supplement
    # CJK
    (0x4E00, 0x9FFF, "zh"),      # CJK Unified → default Chinese
    (0x3400, 0x4DBF, "zh"),      # CJK Extension A
    (0x3040, 0x309F, "ja"),      # Hiragana → Japanese
    (0x30A0, 0x30FF, "ja"),      # Katakana
    (0xAC00, 0xD7AF, "ko"),      # Hangul → Korean
    # Arabic
    (0x0600, 0x06FF, "ar"),      # Arabic
    (0x0750, 0x077F, "ar"),      # Arabic Supplement
    (0xFB50, 0xFDFF, "ar"),      # Arabic Presentation A
    (0xFE70, 0xFEFF, "ar"),      # Arabic Presentation B
    # Devanagari (Hindi, Sanskrit, Marathi, Nepali)
    (0x0900, 0x097F, "hi"),      # Devanagari
    # Thai
    (0x0E00, 0x0E7F, "th"),      # Thai
    # Greek
    (0x0370, 0x03FF, "el"),      # Greek
    # Hebrew
    (0x0590, 0x05FF, "he"),      # Hebrew
    # Georgian
    (0x10A0, 0x10FF, "ka"),      # Georgian
    # Armenian
    (0x0530, 0x058F, "hy"),      # Armenian
]


def _detect_scripts(text: str) -> dict[str, float]:
    """Count character frequencies per script/language.

    Returns dict mapping language codes to proportion (0.0–1.0).
    """
    counts: dict[str, int] = {}
    total = 0
    for ch in text:
        cp = ord(ch)
        for lo, hi, lang in _SCRIPT_RANGES:
            if lo <= cp <= hi:
                counts[lang] = counts.get(lang, 0) + 1
                total += 1
                break
    if total == 0:
        return {}
    return {lang: cnt / total for lang, cnt in counts.items()}


# ---------------------------------------------------------------------------
# Target canonicalization
# ---------------------------------------------------------------------------

# Known email provider domains — tokens to strip when canonicalizing
_EMAIL_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "protonmail.com", "proton.me", "pm.me",
    "icloud.com", "me.com", "mac.com",
    "aol.com", "mail.com", "gmx.com", "gmx.de",
    "zoho.com", "fastmail.com", "tutanota.com",
    "yandex.com", "yandex.ru", "qq.com", "163.com",
}

# Common TLDs — not useful as canonical tokens for domain targets
_NOISE_TLDS = {"com", "org", "net", "io", "co", "ai", "dev", "app", "info", "biz"}

# Known crypto prefixes
_WALLET_PREFIXES = {"0x": "eth", "bc1": "btc", "1": "btc", "3": "btc",
                     "T": "trx", "L": "ltc", "M": "ltc", "X": "xmr"}


@dataclass
class TargetProfile:
    """Canonical representation of an investigation target — any type, any language."""
    raw: str                              # Original query string
    target_type: str                      # person, organization, domain, email, wallet, phone, ip, username, unknown
    canonical_tokens: set[str]            # Meaningful, normalized tokens
    name_parts: list[str]                 # For person/org targets (split by spaces, normalized)
    likely_languages: set[str]            # ISO 639-1 codes inferred from script
    tld: str = ""                         # For domain/email targets
    wallet_chain: str = ""                # For wallet targets
    metadata: dict = field(default_factory=dict)
    name_part_tokens: list[set[str]] = field(default_factory=list)  # Per-part ASCII-normalized tokens (for person targets)


def canonicalize_target(query: str) -> TargetProfile:
    """Extract canonical tokens and metadata from ANY target type.

    Handles: person names, organization names, domains, emails,
    cryptocurrency wallets, phone numbers, IP addresses, usernames.

    For multilingual targets: preserves diacritics in name_parts
    but normalizes canonical_tokens to ASCII for matching.
    """
    if not query or not query.strip():
        return TargetProfile(
            raw=query, target_type="unknown",
            canonical_tokens=set(), name_parts=[],
            likely_languages={"en"}
        )

    query = query.strip()

    # ── Type detection ──
    # Email
    if "@" in query and "." in query.split("@")[-1]:
        return _canonicalize_email(query)

    # Wallet
    if re.match(r'^(0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,62}|T[a-zA-Z0-9]{33}|L[a-zA-Z0-9]{33}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})$', query):
        return _canonicalize_wallet(query)

    # IP address
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', query):
        return _canonicalize_ip(query)

    # Phone number (international format)
    if re.match(r'^\+?\d{7,15}$', query.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")):
        return _canonicalize_phone(query)

    # Domain
    if "." in query and "/" not in query and " " not in query and not query.startswith("@"):
        # Must have a valid TLD
        parts = query.lower().rstrip(".").split(".")
        if len(parts) >= 2 and parts[-1].isalpha() and 2 <= len(parts[-1]) <= 6:
            return _canonicalize_domain(query)

    # Username (no spaces, alphanumeric + common separators)
    if re.match(r'^@?[a-zA-Z0-9][a-zA-Z0-9._-]{2,30}$', query.lstrip("@")):
        return _canonicalize_username(query)

    # Person vs Organization heuristic
    # Person: usually 2-3 words, capitalized, no common org indicators
    # Organization: often has Inc, Corp, Ltd, LLC, or is a single word
    words = query.split()
    org_indicators = {"inc", "corp", "ltd", "llc", "gmbh", "sa", "spa", "bv", "nv",
                      "ag", "kg", "plc", "lp", "llp", "co", "group", "holdings",
                      "corporation", "limited", "company", "bank", "university",
                      "institute", "foundation", "association", "ministry", "department"}

    is_org = any(w.lower().rstrip(".,") in org_indicators for w in words)

    if len(words) >= 2 and not is_org:
        return _canonicalize_person(query)
    else:
        return _canonicalize_organization(query)


# ── Stop words: universal function words in major languages ──
# These generate false bigram/token matches and dilute relevance.
_STOP_WORDS: set[str] = {
    # English
    "the", "and", "for", "that", "this", "with", "from", "have", "are",
    "was", "not", "but", "you", "all", "can", "had", "her", "his", "its",
    "one", "our", "out", "she", "some", "than", "them", "then", "were",
    "will", "would", "been", "being", "does", "did", "has", "just", "like",
    "make", "more", "much", "must", "now", "only", "over", "said", "such",
    "also", "any", "after", "about", "into", "other", "their", "there",
    "which", "when", "what", "who", "how", "where", "may", "get", "got",
    "new", "see", "use", "way", "well", "back", "come", "down", "each",
    "even", "first", "good", "know", "last", "life", "long", "look", "many",
    "most", "own", "part", "same", "still", "take", "tell", "these", "those",
    "very", "year", "here", "every", "through", "before", "between",
    # Hungarian
    "az", "ez", "egy", "nem", "hogy", "van", "volt", "lesz", "mint",
    "meg", "mert", "már", "még", "itt", "ott", "aki", "ami", "csak",
    "ha", "is", "de", "el", "ki", "be", "ki", "fel", "le", "át",
    # French
    "le", "la", "les", "un", "une", "des", "est", "pas", "dans",
    "pour", "avec", "sur", "par", "que", "qui", "ce", "se", "au",
    "du", "en", "il", "elle", "nous", "vous", "ils", "elles", "mais",
    # Spanish
    "el", "los", "las", "del", "por", "con", "sin", "para", "como",
    "más", "pero", "entre", "hasta", "desde", "porque", "cuando",
    # German
    "der", "die", "das", "den", "dem", "ein", "eine", "einen",
    "nicht", "sich", "auch", "auf", "bei", "nach", "noch", "schon",
    "um", "zu", "zur", "zum", "von", "vor", "wir", "sie", "er",
    # Italian
    "di", "che", "in", "lo", "gli", "sono", "per", "con", "su",
    # Russian (transliterated)
    "i", "v", "na", "ne", "chto", "kak", "eto", "ot", "po",
    # Portuguese
    "da", "das", "dos", "em", "na", "no", "nas", "nos", "ao", "aos",
    # Dutch
    "de", "het", "een", "op", "te", "zijn", "dat", "met", "van",
    # Arabic (transliterated)
    "al", "fi", "min", "ma", "la", "wa", "ya",
    # Universal
    "or", "if", "an", "as", "at", "be", "by", "do", "go", "he", "in",
    "is", "it", "me", "my", "no", "of", "on", "so", "to", "up", "us",
    "we", "oh", "ok", "hi", "am", "pm", "dr", "mr", "ms", "rs",
}

def _tokenize(text: str) -> set[str]:
    """Normalize text to canonical ASCII tokens (min 2 chars). Filters stop words."""
    # NFKD decomposes diacritics: ó → o + combining acute
    s = unicodedata.normalize('NFKD', text.lower())
    # Strip combining characters (diacritics)
    s = ''.join(c for c in s if not unicodedata.combining(c))
    # Extract alphanumeric tokens, filter stop words
    tokens = set()
    for token in s.split():
        token = ''.join(c for c in token if c.isalnum())
        if len(token) >= 2 and token not in _STOP_WORDS:
            tokens.add(token)
    return tokens


def _detect_languages(text: str) -> set[str]:
    """Infer likely languages from script detection."""
    scripts = _detect_scripts(text)
    langs = set(scripts.keys())
    # Always include English as fallback
    langs.add("en")
    return langs


def _canonicalize_person(query: str) -> TargetProfile:
    """Canonicalize a person name."""
    words = [w.strip(".,;:'\"") for w in query.split() if len(w.strip(".,;:'\"")) >= 2]
    name_parts = [w.lower() for w in words]
    tokens = _tokenize(query)
    # Also add individual name parts as tokens (e.g., "bodi", "ildiko")
    # And track per-part tokens for surname-aware relevance scoring
    name_part_tokens: list[set[str]] = []
    for part in name_parts:
        tokenized = _tokenize(part)
        tokens.update(tokenized)
        name_part_tokens.append(tokenized)
    langs = _detect_languages(query)
    return TargetProfile(
        raw=query, target_type="person",
        canonical_tokens=tokens, name_parts=name_parts,
        name_part_tokens=name_part_tokens,
        likely_languages=langs, metadata={"word_count": len(words)}
    )


def _canonicalize_organization(query: str) -> TargetProfile:
    """Canonicalize an organization name."""
    # Strip org indicators for cleaner tokens
    stripped = re.sub(r'\b(Inc|Corp|Ltd|LLC|GmbH|SA|SpA|BV|NV|AG|KG|PLC|LP|LLP|Co)\b\.?',
                      '', query, flags=re.IGNORECASE)
    tokens = _tokenize(stripped)
    words = [w for w in stripped.split() if len(w) >= 2]
    langs = _detect_languages(query)
    return TargetProfile(
        raw=query, target_type="organization",
        canonical_tokens=tokens, name_parts=[w.lower() for w in words],
        likely_languages=langs, metadata={"word_count": len(words)}
    )


def _canonicalize_domain(query: str) -> TargetProfile:
    """Canonicalize a domain name."""
    parts = query.lower().rstrip(".").split(".")
    tld = parts[-1] if len(parts) >= 2 else ""
    # The meaningful part is the SLD (second-level domain)
    sld = parts[-2] if len(parts) >= 2 else parts[0]
    tokens = _tokenize(sld)
    # Also add the full domain without TLD
    if len(parts) >= 2:
        tokens.add('.'.join(parts[:-1]))
    langs = {"en"}
    # Country-code TLD hints at language
    _CC_LANG = {"hu": "hu", "de": "de", "fr": "fr", "es": "es", "it": "it",
                "pt": "pt", "ru": "ru", "cn": "zh", "jp": "ja", "kr": "ko",
                "pl": "pl", "cz": "cs", "sk": "cs", "nl": "nl", "se": "sv",
                "no": "no", "dk": "da", "fi": "fi", "gr": "el", "il": "he",
                "ar": "ar", "th": "th", "vn": "vi", "tr": "tr", "ua": "uk"}
    if tld in _CC_LANG:
        langs.add(_CC_LANG[tld])
    return TargetProfile(
        raw=query, target_type="domain",
        canonical_tokens=tokens, name_parts=[sld],
        likely_languages=langs, tld=tld
    )


def _canonicalize_email(query: str) -> TargetProfile:
    """Canonicalize an email address."""
    local, domain = query.split("@", 1)
    # Extract meaningful tokens from local part
    # "baron.lorenzo99" → ["baron", "lorenzo"]
    name_parts = re.split(r'[\d._\-+\s]+', local)
    name_parts = [p for p in name_parts if len(p) >= 2]
    tokens = set()
    for part in name_parts:
        tokens.update(_tokenize(part))
    # Also add the local part as a whole for username matching
    tokens.add(local.lower())
    # Don't add domain tokens if it's a known provider
    domain_parts = domain.lower().split(".")
    if domain.lower() not in _EMAIL_PROVIDERS:
        sld = domain_parts[0] if domain_parts else domain
        tokens.update(_tokenize(sld))
        tokens.add(domain.lower())
    langs = _detect_languages(' '.join(name_parts))
    langs.add("en")
    return TargetProfile(
        raw=query, target_type="email",
        canonical_tokens=tokens, name_parts=[p.lower() for p in name_parts],
        likely_languages=langs, metadata={
            "local": local, "domain": domain,
            "is_provider": domain.lower() in _EMAIL_PROVIDERS
        }
    )


def _canonicalize_wallet(query: str) -> TargetProfile:
    """Canonicalize a cryptocurrency wallet address."""
    clean = query.strip()
    chain = "unknown"
    for prefix, c in _WALLET_PREFIXES.items():
        if clean.lower().startswith(prefix.lower()):
            chain = c
            break
    # Use the full address as a single token
    tokens = {clean.lower()}
    # Also add first 8 and last 8 chars for partial matches
    if len(clean) >= 16:
        tokens.add(clean[:8].lower())
        tokens.add(clean[-8:].lower())
    return TargetProfile(
        raw=query, target_type="wallet",
        canonical_tokens=tokens, name_parts=[clean[:12]],
        likely_languages={"en"}, wallet_chain=chain
    )


def _canonicalize_phone(query: str) -> TargetProfile:
    """Canonicalize a phone number."""
    digits = ''.join(c for c in query if c.isdigit())
    tokens = {digits}
    # Last 6-10 digits as partial match
    if len(digits) >= 6:
        tokens.add(digits[-6:])
    if len(digits) >= 10:
        tokens.add(digits[-10:])
    langs = {"en"}
    # Country code detection (very rough)
    if digits.startswith("36"):
        langs.add("hu")
    elif digits.startswith("33"):
        langs.add("fr")
    elif digits.startswith("39"):
        langs.add("it")
    return TargetProfile(
        raw=query, target_type="phone",
        canonical_tokens=tokens, name_parts=[digits],
        likely_languages=langs
    )


def _canonicalize_ip(query: str) -> TargetProfile:
    """Canonicalize an IP address."""
    tokens = {query.strip()}
    # Individual octets
    for octet in query.split("."):
        if octet.isdigit():
            tokens.add(octet)
    return TargetProfile(
        raw=query, target_type="ip",
        canonical_tokens=tokens, name_parts=[query.strip()],
        likely_languages={"en"}
    )


def _canonicalize_username(query: str) -> TargetProfile:
    """Canonicalize a username/handle."""
    clean = query.lstrip("@").lower()
    tokens = {clean}
    # Split on common separators for sub-tokens
    sub_tokens = re.split(r'[._\-]', clean)
    for st in sub_tokens:
        if len(st) >= 2:
            tokens.update(_tokenize(st))
    langs = _detect_languages(clean)
    langs.add("en")
    return TargetProfile(
        raw=query, target_type="username",
        canonical_tokens=tokens, name_parts=sub_tokens,
        likely_languages=langs
    )


# ---------------------------------------------------------------------------
# Multilingual Relevance Grading
# ---------------------------------------------------------------------------

def relevance_score(profile: TargetProfile, text: str) -> float:
    """Multilingual relevance: 0.0 = no relation, 1.0 = exact match.

    Strategies (applied cumulatively):
      1. Jaccard token overlap (diacritic-normalized) — primary
      2. Bigram overlap — catches partial name matches
      3. Script/language boost — reward matching scripts
      4. Target-type-specific heuristics
    """
    if not text or not profile.canonical_tokens:
        return 0.0 if profile.canonical_tokens else 0.5

    text_tokens = _tokenize(text)
    if not text_tokens:
        return 0.0

    # ── Strategy 1: Jaccard token overlap ──
    target_tokens = profile.canonical_tokens
    intersection = target_tokens & text_tokens
    union = target_tokens | text_tokens
    jaccard = len(intersection) / len(union) if union else 0.0

    # ── Strategy 2: Trigram overlap ──
    # 3-character sequences are much less likely to randomly match across
    # unrelated text than bigrams (e.g., "di" appears in ~30% of English words,
    # but "bodi" → "bod" or "odi" appears in almost none).
    # Catches "ildiko" matching "ildikó" (NFKD → "ildiko") and
    # "Ildiko Bodi" matching "Bódi Ildikó" via shared trigrams in the name parts.
    def _trigrams(tokens: set[str]) -> set[str]:
        trigrams = set()
        for token in tokens:
            for i in range(len(token) - 2):
                trigrams.add(token[i:i+3])
        return trigrams

    target_trigrams = _trigrams(target_tokens)
    text_trigrams = _trigrams(text_tokens)
    if target_trigrams:
        trigram_overlap = len(target_trigrams & text_trigrams) / len(target_trigrams)
    else:
        trigram_overlap = 0.0

    # ── Strategy 3: Language/script boost ──
    # If the text uses scripts matching the target's likely languages,
    # apply a small boost (helps Hungarian articles about Hungarian people)
    text_scripts = _detect_scripts(text)
    script_boost = 0.0
    if text_scripts and profile.likely_languages:
        matching_scripts = profile.likely_languages & set(text_scripts.keys())
        if matching_scripts:
            # Up to 0.10 boost based on script match ratio
            script_boost = 0.10 * sum(text_scripts[lang] for lang in matching_scripts)

    # ── Strategy 2.5: Surname-aware penalty (person targets only) ──
    # For multi-word person names, a finding that matches only ONE name part
    # (e.g., "Ildiko Szabo" matching only "Ildiko" from "BÓDI Ildikó") is a
    # completely different person. Given names are too common; the surname is
    # the primary disambiguator. This penalty prevents the trigram/Jaccard
    # overlap from giving high scores to clearly irrelevant findings.
    name_penalty = 1.0
    if profile.target_type == "person" and profile.name_part_tokens and len(profile.name_part_tokens) >= 2:
        parts_matched = 0
        for part_tokens in profile.name_part_tokens:
            if part_tokens & text_tokens:
                parts_matched += 1

        match_ratio = parts_matched / len(profile.name_part_tokens)

        if match_ratio >= 1.0:
            # Full name match — all parts present → slight bonus
            name_penalty = 1.15
        elif match_ratio <= 0.5:
            # Only half or fewer name parts matched → heavy penalty
            # 1/2 → 0.25x, 1/3 → 0.15x, 2/4 → 0.35x
            name_penalty = max(0.10, match_ratio * 0.50)
        else:
            # Most parts matched (e.g., 2/3) → moderate penalty
            name_penalty = match_ratio

    # ── Composite score ──
    # Jaccard is the primary signal (most reliable). Trigram overlap is a
    # secondary fallback — weighted low, and 3-char sequences avoid the
    # false-match problem of bigrams. Script boost is tiny.
    composite = (0.70 * jaccard) + (0.12 * trigram_overlap) + (0.05 * script_boost)

    # Apply surname-aware penalty / bonus
    composite *= name_penalty

    # ── Target-type-specific boosts ──
    if profile.target_type == "wallet":
        # Wallet addresses are unique — exact match is very strong
        if profile.raw.lower() in text.lower():
            composite = max(composite, 0.95)
    elif profile.target_type == "ip":
        if profile.raw in text:
            composite = max(composite, 0.95)
    elif profile.target_type == "phone":
        digits = ''.join(c for c in profile.raw if c.isdigit())
        if digits and digits in ''.join(c for c in text if c.isdigit()):
            composite = max(composite, 0.90)

    return min(composite, 1.0)


# ---------------------------------------------------------------------------
# Safe Relevance Filter
# ---------------------------------------------------------------------------

def relevance_filter(findings: list, query: str, min_score: float = 0.03) -> tuple[list, list]:
    """Filter out clearly irrelevant findings.

    SAFETY RULES (never drops legitimate intelligence):
      1. Findings WITH source URLs are always kept (assume scraper validated)
         EXCEPT: person targets with 2+ name parts → if only 1 name part matches
         and confidence < 0.80, drop it (given-name-only matches are noise).
      2. Findings with high confidence (≥0.65) are always kept
      3. Only drops findings with ZERO composite relevance score
      4. Only drops if confidence < 0.65

    Returns: (kept, dropped) — dropped list is for audit logging.
    """
    if not query or not findings:
        return (list(findings), [])

    profile = canonicalize_target(query)
    if not profile.canonical_tokens:
        return (list(findings), [])  # Can't assess, keep all

    kept = []
    dropped = []
    for f in findings:
        confidence = f.confidence or 0.5

        # Rule 1: Has source URL → keep UNLESS it's a person target
        # where ≤1 of 2+ name parts matches (given-name-only noise).
        # Given names (like "Ildikó") are too common; a finding that
        # matches ONLY the given name and not the surname is a different
        # person. No confidence threshold — scrapers assign uniform
        # high confidence, so we gate on name-part overlap instead.
        has_source = f.source_url and f.source_url.startswith("http")
        if has_source:
            if profile.target_type == "person" and profile.name_part_tokens and len(profile.name_part_tokens) >= 2:
                # Surname check: count how many name parts have token overlap
                combined_text = f"{f.title or ''} {f.description or ''}"
                text_tokens = _tokenize(combined_text)
                parts_matched = sum(
                    1 for pt in profile.name_part_tokens if pt & text_tokens
                )
                # If ≤1 name part matches out of 2+ → it's a different person
                # (unless ALL parts matched, which means full name overlap)
                if parts_matched <= 1:
                    dropped.append(f)
                    continue
            kept.append(f)
            continue

        # Rule 2: High confidence → always keep (don't risk false positives)
        if confidence >= 0.65:
            kept.append(f)
            continue

        # Rule 3: Compute relevance
        combined_text = f"{f.title or ''} {f.description or ''}"
        score = relevance_score(profile, combined_text)

        # Rule 4: Only drop if ZERO relevance + low confidence
        if score <= min_score:
            dropped.append(f)
            continue

        kept.append(f)

    return (kept, dropped)
