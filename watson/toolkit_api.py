"""Bellingcat direct API integration — real data from real sources.

Stripped-down version that hits the actual APIs without the full
OSINTTool/registry framework. Imported directly by the engine.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import ssl as _ssl
from urllib.parse import quote
from typing import Optional

try:
    import certifi as _certifi
    _SSL_CTX = _ssl.create_default_context(cafile=_certifi.where())
except ImportError:
    _SSL_CTX = False

import aiohttp


# ── API key loading ───────────────────────────────────────────

def _load_api_keys() -> dict[str, str]:
    """Load API keys from the unified key store (JSON + env fallback)."""
    try:
        from watson.api_keys import get_key
        return {
            "opencorporates": get_key("opencorporates"),
            "opensanctions": get_key("opensanctions"),
        }
    except ImportError:
        keys = {}
        for env_var, slug in [
            ("OPENCORPORATES_API_KEY", "opencorporates"),
            ("OPENSANCTIONS_API_KEY", "opensanctions"),
        ]:
            val = os.environ.get(env_var, "")
            if val:
                keys[slug] = val
        return keys


# ── API definitions ────────────────────────────────────────────

DIRECT_APIS: dict[str, dict] = {
    "crt.sh": {
        "search_url": "https://crt.sh/?q=%25.{query}&output=json",
        "extract": "root",
        "auth": False,
    },
    "Wayback CDX": {
        "search_url": "https://web.archive.org/cdx/search/cdx?url=*.{query}/*&output=json&fl=timestamp,original,statuscode&limit=50",
        "extract": "root",
        "auth": False,
    },
    "OpenCorporates": {
        "search_url": "https://api.opencorporates.com/v0.4/companies/search?q={query}",
        "extract": "companies",
        "auth": True,
        "auth_env": "OPENCORPORATES_API_KEY",
        "get_key_url": "https://opencorporates.com/api_accounts/new",
    },
    "OpenSanctions": {
        "search_url": "https://api.opensanctions.org/search/default?q={query}",
        "extract": "results",
        "auth": True,
        "auth_env": "OPENSANCTIONS_API_KEY",
        "get_key_url": "https://www.opensanctions.org/api/",
    },
    "Wikidata": {
        "search_url": "https://www.wikidata.org/w/api.php?action=wbsearchentities&search={query}&language=en&format=json&limit=10&origin=*",
        "extract": "search",
        "auth": False,
    },
    "Wikipedia": {
        "search_url": "https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch={query}&format=json&srlimit=10&origin=*",
        "extract": "query.search",
        "auth": False,
    },
    "urlscan.io": {
        "search_url": "https://urlscan.io/api/v1/search/?q={query}",
        "extract": "results",
        "auth": False,
        # urlscan expects domain:prefix for domain searches, plain text otherwise
        "query_formatter": lambda q: f"domain:{q}" if "." in q and not q.startswith("domain:") else q,
    },
}

# ── API selection per target type ──────────────────────────────

API_SELECTION: dict[str, list[str]] = {
    "domain": ["crt.sh", "urlscan.io", "Wayback CDX", "Wikidata"],
    "company": ["OpenCorporates", "Wikidata", "Wikipedia"],  # OpenSanctions via corporate agent (retry wrapper)
    "person": ["Wikidata", "Wikipedia"],  # OpenSanctions via corporate agent (retry wrapper)
    "email": ["Wikidata"],
    "topic": ["Wikipedia", "Wikidata"],
}


class BellingcatAPI:
    """Direct API integration for Bellingcat OSINT tools.

    Hits crt.sh, Wayback CDX, OpenCorporates, Wikidata, Wikipedia,
    OpenSanctions, and more — in parallel with rate limiting.
    """

    def __init__(self, max_concurrent: int = 5, timeout: int = 20):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self._api_keys = _load_api_keys()

    async def investigate(
        self, query: str, target_type: str = "topic"
    ) -> list[dict]:
        """Run relevant API calls for a target and return findings.

        Auth failures return error findings (not None) so the user
        knows exactly what's missing — never swallow API errors.
        """
        api_names = API_SELECTION.get(target_type, API_SELECTION["topic"])
        sem = asyncio.Semaphore(self.max_concurrent)

        async def _call_one(name: str) -> dict | None:
            api_def = DIRECT_APIS.get(name)
            if not api_def:
                return {
                    "title": f"⚠️ {name}: API not configured",
                    "description": f"API '{name}' is not in the registry.",
                    "source_type": "error",
                    "confidence": 0.0,
                    "tool": name,
                }
            async with sem:
                return await self._call_api(name, api_def, query)

        tasks = [_call_one(name) for name in api_names]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings = []
        for i, r in enumerate(results):
            if isinstance(r, dict) and r.get("title"):
                findings.append(r)
            elif isinstance(r, Exception):
                api_name = api_names[i] if i < len(api_names) else "unknown"
                findings.append({
                    "title": f"⚠️ {api_name}: Internal error",
                    "description": f"Unexpected error: {type(r).__name__}: {str(r)[:200]}",
                    "source_type": "error",
                    "confidence": 0.0,
                    "tool": api_name,
                })

        return findings

    async def _call_api(
        self, name: str, api_def: dict, query: str
    ) -> dict | None:
        """Call a single API and return a finding dict.

        Never returns None — returns error findings so failures are
        visible to the user instead of silently dropped.
        """
        # ── Auth check ──────────────────────────────────────────
        api_key = None
        if api_def.get("auth"):
            auth_env = api_def["auth_env"]
            # Normalize: strip "API_KEY" suffix and trailing underscore
            slug = auth_env.lower().replace("_api_key", "").strip("_")
            api_key = self._api_keys.get(
                slug,
                self._api_keys.get(auth_env.lower(), ""),
            )
            if not api_key:
                api_key = os.environ.get(auth_env, "")
            if not api_key:
                return {
                    "title": f"⚠️ {name}: API key required",
                    "description": (
                        f"{name} requires an API key. Set {auth_env} "
                        f"in your environment or .env file. "
                        f"Get a key at: {api_def.get('get_key_url', 'N/A')}"
                    ),
                    "source_type": "error",
                    "confidence": 0.0,
                    "tool": name,
                }

        try:
            url = api_def["search_url"]
            # Apply query formatter if defined (e.g. urlscan.io needs domain: prefix)
            formatted_query = query
            if "query_formatter" in api_def:
                formatted_query = api_def["query_formatter"](query)
            url = url.replace("{query}", quote(formatted_query, safe=""))
            url = url.replace("%25.{query}", "%25." + quote(formatted_query, safe=""))

            headers = {
                "User-Agent": "Mozilla/5.0 (compatible; Watson-OSINT/1.0)",
            }

            # Inject API key for auth-required APIs
            if api_def.get("auth") and api_key:
                if name == "OpenCorporates":
                    # OpenCorporates uses query param for API token
                    url += f"&api_token={quote(api_key, safe='')}"
                elif name == "OpenSanctions":
                    headers["Authorization"] = f"ApiKey {api_key}"

            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers=headers,
            ) as session:
                async with session.get(url, ssl=_SSL_CTX) as resp:
                    # ── Error responses — surface, don't swallow ──
                    if resp.status == 401 or resp.status == 403:
                        return {
                            "title": f"⚠️ {name}: Authentication failed",
                            "description": (
                                f"{name} returned {resp.status}. "
                                f"Check your API key ({api_def.get('auth_env', 'N/A')}). "
                                f"Get a key: {api_def.get('get_key_url', 'N/A')}"
                            ),
                            "source_type": "error",
                            "confidence": 0.0,
                            "tool": name,
                        }
                    if resp.status == 202 and "x-amzn-waf-action" in str(resp.headers):
                        return {
                            "title": f"⚠️ {name}: Bot detection triggered",
                            "description": (
                                f"{name} is behind CloudFront WAF and blocked the request. "
                                f"This API is not currently usable for automated queries."
                            ),
                            "source_type": "error",
                            "confidence": 0.0,
                            "tool": name,
                        }
                    if resp.status == 429:
                        return {
                            "title": f"⚠️ {name}: Rate limited",
                            "description": f"{name} returned 429 — too many requests. Retry later.",
                            "source_type": "error",
                            "confidence": 0.0,
                            "tool": name,
                        }
                    if resp.status not in (200, 202):
                        body = await resp.text()
                        return {
                            "title": f"⚠️ {name}: HTTP {resp.status}",
                            "description": f"{name} returned {resp.status}: {body[:200]}",
                            "source_type": "error",
                            "confidence": 0.0,
                            "tool": name,
                        }

                    if "json" in resp.content_type or name in ("crt.sh", "Wayback CDX", "urlscan.io"):
                        try:
                            data = await resp.json()
                        except Exception:
                            text = await resp.text()
                            return {
                                "title": f"⚠️ {name}: JSON parse failed",
                                "description": f"Expected JSON but got: {text[:200]}",
                                "source_type": "error",
                                "confidence": 0.0,
                                "tool": name,
                            }
                    else:
                        text = await resp.text()
                        try:
                            data = json.loads(text)
                        except json.JSONDecodeError:
                            data = {"raw": text[:1000]}

            # Extract meaningful data
            extractor = api_def.get("extract", "")
            result = data
            if extractor and extractor != "root":
                for key in extractor.split("."):
                    if isinstance(result, dict):
                        result = result.get(key, [])
                    elif isinstance(result, list):
                        break

            count = len(result) if isinstance(result, list) else (1 if result else 0)

            # Build description from samples
            samples = []
            if isinstance(result, list) and result:
                for item in result[:5]:
                    samples.append(self._summarize(name, item))

            description = f"Found {count} result(s)."
            if samples:
                description += " " + "; ".join(samples[:3])

            return {
                "title": f"✓ {name}: {count} Results",
                "description": description[:2000],
                "source_type": "bellingcat",
                "source_url": url.split("?")[0],
                "confidence": min(0.85, 0.3 + count * 0.05) if count > 0 else 0.0,
                "evidence": [url],
                "tool": name,
            }

        except asyncio.TimeoutError:
            return {
                "title": f"⚠️ {name}: Timeout",
                "description": f"{name} timed out after {self.timeout}s. The API may be slow or unreachable.",
                "source_type": "error",
                "confidence": 0.0,
                "tool": name,
            }
        except Exception as e:
            return {
                "title": f"⚠️ {name}: Error",
                "description": f"{type(e).__name__}: {str(e)[:200]}",
                "source_type": "error",
                "confidence": 0.0,
                "tool": name,
            }

    @staticmethod
    def _summarize(api_name: str, item) -> str:
        """Create a one-line summary of an API result."""
        if not isinstance(item, dict):
            return str(item)[:120]

        summarizers = {
            "crt.sh": lambda i: f"{i.get('common_name', '?')} ({str(i.get('not_before', ''))[:10]})",
            "Wayback CDX": lambda i: f"{i[2] if isinstance(i, list) and len(i) > 2 else '?'} @ {i[1] if isinstance(i, list) and len(i) > 1 else '?'}",
            "OpenCorporates": lambda i: f"{i.get('company', {}).get('name', '?')} ({i.get('company', {}).get('jurisdiction_code', '?')})",
            "Wikidata": lambda i: f"{i.get('label', '?')} ({i.get('id', '?')}) — {i.get('description', '')[:60]}",
            "Wikipedia": lambda i: f"{i.get('title', '?')}",
            "urlscan.io": lambda i: f"{i.get('page', {}).get('url', '?')[:80]}",
        }
        fn = summarizers.get(api_name, lambda i: json.dumps(i, default=str)[:120])
        try:
            return fn(item)
        except Exception:
            return json.dumps(item, default=str)[:120]
