"""
Bellingcat Automation — bridge module for tools_bellingcat.py.

Thin wrapper around bellingcat_api.BellingcatAPI that provides
the interface expected by the BellingcatToolkit._run_automation() method.

Previously this module didn't exist, causing "No module named
'watson.bellingcat_automation'" errors in every investigation.
"""

from __future__ import annotations

from watson.bellingcat_api import BellingcatAPI, API_SELECTION, DIRECT_APIS

# ── Target-type → API tool mapping ─────────────────────────────

TARGET_API_MAP: dict[str, list[str]] = {
    "person": API_SELECTION.get("person", ["Wikidata", "Wikipedia", "OpenSanctions"]),
    "company": API_SELECTION.get("company", ["OpenCorporates", "Wikidata", "Wikipedia", "OpenSanctions"]),
    "domain": API_SELECTION.get("domain", ["crt.sh", "urlscan.io", "Wayback CDX", "Wikidata"]),
    "email": API_SELECTION.get("email", ["Wikidata"]),
    "topic": API_SELECTION.get("topic", ["Wikipedia", "Wikidata"]),
}

# ── Automation class ────────────────────────────────────────────

class BellingcatAutomation:
    """Run automated Bellingcat API calls for a target type.

    Wraps BellingcatAPI with the interface expected by tools_bellingcat.py:
    - run_category(target_type, query, tool_names) → dict[str, list[dict]]
    - results_to_findings(tool_name, results, query, target_type) → list[dict]
    """

    def __init__(self, api_keys: dict | None = None):
        self._api = BellingcatAPI()
        if api_keys:
            self._api._api_keys.update(api_keys)

    async def run_category(
        self, target_type: str, query: str, tool_names: list[str]
    ) -> dict[str, list[dict]]:
        """Run automated tools for a target type. Returns {tool_name: [results]}."""
        import asyncio

        results: dict[str, list[dict]] = {}

        async def _run_one(name: str):
            api_def = DIRECT_APIS.get(name)
            if not api_def:
                return name, [{
                    "title": f"{name}: not configured",
                    "description": f"Tool '{name}' is not in DIRECT_APIS registry.",
                    "source_type": "error",
                    "confidence": 0.0,
                }]
            result = await self._api._call_api(name, api_def, query)
            return name, [result] if result else []

        # Run all tools concurrently
        tasks = [_run_one(name) for name in tool_names]
        gathered = await asyncio.gather(*tasks, return_exceptions=True)

        for item in gathered:
            if isinstance(item, BaseException):
                continue
            name, findings = item
            if findings:
                results[name] = findings

        return results

    def results_to_findings(
        self, tool_name: str, results: list[dict], query: str, target_type: str
    ) -> list[dict]:
        """Convert raw API results to Watson finding dicts."""
        findings = []
        for r in results:
            if not isinstance(r, dict):
                continue
            # Already in finding format from bellingcat_api
            if "title" in r:
                findings.append(r)
            else:
                # Raw result — wrap it
                findings.append({
                    "title": f"{tool_name}: {query}",
                    "description": str(r)[:500],
                    "evidence": [],
                    "confidence": 0.5,
                    "severity": "info",
                    "tool": tool_name,
                    "source_type": "api",
                })
        return findings
