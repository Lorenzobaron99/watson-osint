"""
Unified API key store for Watson tools.

Loads keys from ~/.watson/api_keys.json, falling back to environment variables.
Provides save/load/list for the dashboard settings UI.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

STORE_PATH = Path.home() / ".watson" / "api_keys.json"

# ── Tool registry — all tools that accept API keys ─────────────

TOOLS_NEEDING_KEYS = {
    "opencorporates": {
        "label": "OpenCorporates",
        "env_var": "OPENCORPORATES_API_KEY",
        "get_key_url": "https://opencorporates.com/api_accounts/new",
        "description": "Company registry — verifies corporate structures, directors, filings.",
        "tier": "free",  # free tier available, key unlocks higher rate limits
    },
    "opensanctions": {
        "label": "OpenSanctions",
        "env_var": "OPENSANCTIONS_API_KEY",
        "get_key_url": "https://www.opensanctions.org/api/",
        "description": "Sanctions & PEP database — checks individuals and entities against global sanctions lists.",
        "tier": "free",
    },
    "hibp": {
        "label": "Have I Been Pwned",
        "env_var": "HIBP_API_KEY",
        "get_key_url": "https://haveibeenpwned.com/API/Key",
        "description": "Breach database — checks emails against known data breaches.",
        "tier": "paid",
    },
    "shodan": {
        "label": "Shodan",
        "env_var": "SHODAN_API_KEY",
        "get_key_url": "https://account.shodan.io/",
        "description": "Internet scanner — discovers exposed services, industrial control systems, vulnerable infrastructure.",
        "tier": "paid",
    },
    "marinetraffic": {
        "label": "MarineTraffic AIS",
        "env_var": "MARINETRAFFIC_API_KEY",
        "get_key_url": "https://www.marinetraffic.com/en/ais-api-services",
        "description": "Ship tracking — monitors vessel movements for sanctions evasion, smuggling, illegal fishing.",
        "tier": "paid",
    },
    "chainalysis": {
        "label": "Chainalysis / Crypto",
        "env_var": "CHAINALYSIS_API_KEY",
        "get_key_url": "https://www.chainalysis.com/",
        "description": "Blockchain intelligence — traces crypto transactions, identifies wallets, sanctions screening.",
        "tier": "paid",
    },
    "pacer": {
        "label": "PACER (US Courts)",
        "env_var": "PACER_API_KEY",
        "get_key_url": "https://pacer.uscourts.gov/",
        "description": "US federal court records — dockets, filings, judgments, bankruptcy records.",
        "tier": "paid",
    },
}


# ── Load / Save ───────────────────────────────────────────────

def _load_store() -> dict:
    """Read the JSON key store. Returns empty dict if missing or corrupt."""
    if not STORE_PATH.exists():
        return {}
    try:
        return json.loads(STORE_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_store(data: dict) -> None:
    """Write the JSON key store atomically."""
    STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STORE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(STORE_PATH)


def get_key(slug: str) -> str:
    """Get an API key by tool slug.

    Priority: JSON store > environment variable.
    """
    store = _load_store()
    if slug in store and store[slug]:
        return store[slug]
    tool = TOOLS_NEEDING_KEYS.get(slug, {})
    env_var = tool.get("env_var", "")
    return os.environ.get(env_var, "")


def set_key(slug: str, value: str) -> None:
    """Save an API key to the JSON store."""
    store = _load_store()
    store[slug] = value.strip()
    _save_store(store)


def delete_key(slug: str) -> None:
    """Remove an API key from the JSON store."""
    store = _load_store()
    store.pop(slug, None)
    _save_store(store)


def list_keys() -> list[dict]:
    """Return all configured tools with their key status (masked)."""
    store = _load_store()
    result = []
    for slug, tool in TOOLS_NEEDING_KEYS.items():
        key = store.get(slug, "") or os.environ.get(tool["env_var"], "")
        result.append({
            "slug": slug,
            "label": tool["label"],
            "description": tool["description"],
            "get_key_url": tool["get_key_url"],
            "env_var": tool["env_var"],
            "tier": tool.get("tier", "free"),
            "configured": bool(key),
            "preview": _mask(key) if key else "",
        })
    return result


def _mask(key: str) -> str:
    """Show first 4 + last 4 chars, mask the rest."""
    if len(key) <= 8:
        return "*" * len(key)
    return key[:4] + "*" * (len(key) - 8) + key[-4:]
