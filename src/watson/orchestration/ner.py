"""
spaCy-powered entity extraction for Watson OSINT.

Replaces the old regex-only _extract_entities_from_text() with a hybrid:
  1. Regex extracts email, domain, and person CANDIDATES (high recall)
  2. spaCy NER validates person candidates (high precision)
  3. Only entities that pass BOTH filters are kept

This eliminates garbage like "Calls It", "So Cringe", "Elon Musk Gets" while
keeping real entities like "Elon Musk", "Vivian Wilson", "Errol Musk".
"""

from __future__ import annotations

import logging
import re
from typing import Optional

logger = logging.getLogger("watson.ner")

# ── Lazy-loaded spaCy model ──────────────────────────────────────

_nlp: Optional[object] = None
_MODEL_NAME = "en_core_web_md"


def _get_nlp():
    """Lazy-load spaCy model — only on first use."""
    global _nlp
    if _nlp is None:
        try:
            import spacy
            _nlp = spacy.load(_MODEL_NAME)
            logger.info("spaCy NER loaded: %s", _MODEL_NAME)
        except Exception as e:
            logger.warning("spaCy NER unavailable: %s — falling back to regex-only", e)
            _nlp = False  # Sentinel: tried and failed
    return _nlp if _nlp is not False else None


# ── Regex extractors (unchanged from resolution.py) ──────────────

_EXTRACT_EMAIL = re.compile(r"\b([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})\b", re.I)
_EXTRACT_PERSON = re.compile(r"\b([A-Z][a-z]+(?: [A-Z][a-z]+){1,2})\b")
_EXTRACT_DOMAIN = re.compile(
    r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:com|org|net|io|gov|ru|cn|de|uk|fr))\b",
    re.I,
)

# ── Known first names (heuristic fallback) ───────────────────────

_PERSON_FIRST_NAMES = {
    "Dmitry", "Dmitri", "Vladimir", "Sergey", "Alexei", "Mikhail", "Nikolai",
    "Ivan", "Andrei", "Alexander", "Boris", "Yuri", "Viktor", "Pavel", "Anton",
    "Roman", "Denis", "Oleg", "Igor", "Evgeny", "Konstantin", "Maxim", "Artem",
    "Donald", "Jeffrey", "Elon", "Bill", "Steve", "Mark", "John", "David",
    "Michael", "Robert", "James", "William", "Richard", "Joseph", "Thomas",
    "Charles", "Christopher", "Daniel", "Matthew", "Anthony", "George",
    "Lorenzo", "Giovanni", "Marco", "Andrea", "Francesco", "Alessandro",
    "Errol", "Maye", "Vivian", "Walter", "Ashlee", "Linda", "Kanye",
    "Patrick", "Adam", "Tom", "Vincent", "Dave", "Don", "Shashank",
}


def _spacy_validate_person(name: str, strict_person_only: bool = False) -> bool:
    """Check if spaCy recognizes this as a real person name.

    Returns True if spaCy classifies the name as PERSON or ORG
    (indicating it's a real named entity, not a random phrase).
    
    When strict_person_only=True, only PERSON label is accepted
    (used for employee pivot where ORGs like "Federal Trade Commission" are noise).
    """
    nlp = _get_nlp()
    if nlp is None:
        tokens = name.split()
        return any(t in _PERSON_FIRST_NAMES for t in tokens)

    doc = nlp(name)
    for ent in doc.ents:
        if ent.text.strip() == name.strip():
            if strict_person_only:
                return ent.label_ == "PERSON"
            if ent.label_ in ("PERSON", "ORG"):
                return True
            return False

    # spaCy didn't recognize it as any entity — could be rare name
    # Fall back to heuristic: contains known first name
    tokens = name.split()
    return any(t in _PERSON_FIRST_NAMES for t in tokens)


def _is_garbage_person(name: str) -> bool:
    """Heuristic checks on candidate person names that regex catches but aren't people.

    These are patterns spaCy can't always catch on short fragments.
    """
    tokens = name.split()
    if len(tokens) < 2:
        return True  # Single word isn't a full person name

    # Known non-person entities (countries, cities, organizations)
    _KNOWN_NON_PERSONS = {
        "South Africa", "North Korea", "South Korea", "United States",
        "United Kingdom", "New York", "Los Angeles", "San Francisco",
        "Hong Kong", "Saudi Arabia", "United Arab", "European Union",
        "New Zealand", "Sri Lanka", "Costa Rica", "Puerto Rico",
        "El Salvador", "San Jose", "San Diego", "Santa Clara",
        "West Bank", "East Timor", "Sierra Leone", "Burkina Faso",
        "Ivory Coast", "Papua New", "Middle East", "Latin America",
        "North America", "South America", "Central America",
    }
    if name in _KNOWN_NON_PERSONS:
        return True

    lower_tokens = [t.lower() for t in tokens]

    # Verb-like endings: "Elon Musk Criticises", "Elon Musk Gets"
    verbish = {
        "gets", "calls", "says", "criticises", "criticizes", "supports",
        "attacks", "slams", "blasts", "responds", "speaks", "talks",
        "writes", "posts", "tweets", "announces", "reveals", "claims",
        "launches", "unveils", "discusses", "explains", "defends",
        "promises", "warns", "urges", "asks", "tells", "shares",
    }
    if any(t in verbish for t in lower_tokens):
        return True

    # Headline fragments: 4+ words is almost certainly a sentence fragment
    if len(tokens) > 3:
        return True

    # Names ending with common non-name words
    non_name_ends = {
        "it", "is", "be", "am", "are", "was", "were", "has", "had",
        "does", "did", "will", "would", "could", "should", "can",
        "with", "for", "from", "about", "after", "before", "under",
        "over", "your", "our", "their", "this", "that", "what",
        "and", "but", "not", "just", "only", "also", "still",
    }
    if lower_tokens[-1] in non_name_ends:
        return True

    return False


def extract_entities_from_text(text: str) -> list[tuple[str, str]]:
    """Pull (value, type) entity candidates from text using spaCy-validated NER.

    Returns list of (entity_value, entity_type) tuples.
    Types: 'email', 'domain', 'person'
    """
    out: list[tuple[str, str]] = []
    if not text:
        return out

    # ── Pre-process: strip parenthetical content to avoid concatenation ──
    # "Errol Musk (father) Maye Musk (mother)" → "Errol Musk  Maye Musk"
    text = re.sub(r'\([^)]*\)', ' ', text)
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text).strip()

    # ── Emails and domains: regex is perfect, no NLP needed ──
    for m in _EXTRACT_EMAIL.finditer(text):
        val = m.group(1)
        if len(val) >= 5:
            out.append((val, "email"))

    for m in _EXTRACT_DOMAIN.finditer(text):
        val = m.group(1)
        if 4 <= len(val) <= 80:
            out.append((val, "domain"))

    # ── Persons: regex finds candidates, spaCy validates ──
    seen = set()
    for m in _EXTRACT_PERSON.finditer(text):
        val = m.group(1).strip()
        if val in seen:
            continue
        seen.add(val)

        # Quick length/reject checks
        if len(val) < 5 or len(val) > 60:
            continue
        if val.startswith(("http://", "https://", "www.")):
            continue

        # Garbage heuristic check
        if _is_garbage_person(val):
            continue

        # spaCy validation (or known-name fallback)
        if _spacy_validate_person(val):
            out.append((val, "person"))

    return out
