"""Intent classification — understand what the user is investigating."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

# ── Data model ────────────────────────────────────────────────

@dataclass
class Intent:
    """What Watson understood about the investigation target."""
    focus: str                          # natural-language focus area
    target_type: str                    # person | company | domain | topic | wallet
    confidence: float                   # classification confidence 0-1
    entities: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    raw_query: str = ""

# ── LLM prompt for classification ─────────────────────────────

_INTENT_PROMPT = """You are an OSINT target classifier. Given a search query, determine what is being investigated.

Return STRICT JSON with these fields:
{
  "target_type": "person|company|domain|topic|wallet|ip|email",
  "focus": "short description of what aspect to investigate (1 sentence)",
  "confidence": 0.0-1.0,
  "categories": ["list of tool categories to use: social, corporate, dark, crypto, geo, media, recon, vision"],
  "entities": ["list of named entities found in the query"]
}

ENTITY TYPE RULES:
- Classify each entity independently based on context
- People have names, DOBs, nationalities, aliases, professions
- Companies have suffixes (Inc, LLC, Ltd, Corp, GmbH, SA, AG, Group, Holdings) or are known orgs
- Entities with version numbers (e.g., "LockBit 3.0") are NEVER typed as person
- Email addresses, crypto wallets, IPs, domains have their own types
- If ambiguous, prefer the more specific type

Query: {query}

JSON:"""

# ── Deterministic fallback — no LLM needed for obvious cases ──

def _deterministic_classify(query: str) -> Optional[Intent]:
    """Quick classification without LLM for obvious cases."""
    q = query.strip().lower()
    
    # Email
    if "@" in q and "." in q.split("@")[-1]:
        return Intent(focus=f"Email investigation of {q}", target_type="email",
                      confidence=0.95, entities=[query.strip()],
                      categories=["social", "recon"], raw_query=query)
    
    # Crypto wallet
    if q.startswith("0x") and len(q) >= 40:
        return Intent(focus=f"Cryptocurrency wallet {q[:10]}...", target_type="wallet",
                      confidence=0.95, entities=[q], categories=["crypto", "dark"],
                      raw_query=query)
    
    # IP address
    parts = q.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return Intent(focus=f"IP address investigation of {q}", target_type="ip",
                      confidence=0.95, entities=[q], categories=["geo", "dark"],
                      raw_query=query)
    
    # Domain
    if "." in q and not " " in q and not q.startswith("http"):
        if any(q.endswith(t) for t in [".com", ".org", ".net", ".io", ".gov", ".ru", ".cn", ".de"]):
            return Intent(focus=f"Domain investigation of {q}", target_type="domain",
                          confidence=0.85, entities=[q],
                          categories=["recon", "dark", "corporate"],
                          raw_query=query)
    
    return None

# ── LLM fallback classifier ──────────────────────────────────

async def _llm_classify(query: str, call_llm) -> Intent:
    """Use LLM to classify the query intent."""
    prompt = _INTENT_PROMPT.format(query=query[:500])
    
    try:
        raw = await call_llm(prompt, timeout=30)
    except Exception:
        raw = None
    
    if not raw:
        return Intent(focus=query, target_type="topic", confidence=0.3,
                      entities=[], categories=["recon", "social"],
                      raw_query=query)
    
    import json, re
    # Strip markdown fences
    raw = raw.strip()
    if raw.startswith("```"):
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
    if target_type not in ("person", "company", "domain", "topic", "wallet", "ip", "email"):
        target_type = "topic"
    
    return Intent(
        focus=str(parsed.get("focus", query)),
        target_type=target_type,
        confidence=float(parsed.get("confidence", 0.5)),
        entities=[str(e) for e in parsed.get("entities", []) if str(e).strip()],
        categories=[str(c) for c in parsed.get("categories", ["recon", "social"])],
        raw_query=query,
    )

# ── Main entry point ─────────────────────────────────────────

async def classify_intent(query: str, call_llm=None) -> Intent:
    """Classify investigation intent. Uses deterministic rules first, LLM as fallback."""
    det = _deterministic_classify(query)
    if det:
        return det
    
    if call_llm:
        return await _llm_classify(query, call_llm)
    
    return Intent(focus=query, target_type="topic", confidence=0.4,
                  entities=[], categories=["recon", "social"], raw_query=query)
