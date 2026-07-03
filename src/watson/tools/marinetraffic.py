"""MarineTraffic AIS tool — ship tracking for sanctions evasion OSINT.

Monitors vessel movements, ownership, and port calls. Critical for
sanctions evasion, illegal fishing, and smuggling investigations.
Paid API required (free tier: 500 req/day).
"""

from __future__ import annotations

import logging

from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSource

logger = logging.getLogger("watson.marinetraffic")


class MarineTrafficTool(OSINTTool):
    """Ship tracking via AIS — vessel movements, ownership, port calls."""

    category = FindingSource.OSINT
    name = "marinetraffic"
    description = "MarineTraffic AIS — vessel tracking, ship ownership, port calls for sanctions evasion detection"
    free_tier_available = False
    rate_limit_rps = 1.0

    VESSEL_SEARCH = "https://services.marinetraffic.com/api/exportvessels/v:8/"

    async def investigate(self, query: str, context: str = "") -> list[Finding]:
        """Search vessel movements related to a target."""
        findings: list[Finding] = []

        from watson.api_keys import get_key

        api_key = get_key("marinetraffic")
        if not api_key:
            findings.append(self._make_finding(
                title="🔒 MarineTraffic AIS API key not configured",
                description=(
                    "MarineTraffic provides real-time ship tracking via AIS — vessel "
                    "movements, ownership, port calls. Critical for sanctions evasion "
                    "and smuggling investigations.\n\n"
                    "Install your API key in Settings → API Vault to enable.\n"
                    "Get a key: https://www.marinetraffic.com/en/ais-api-services"
                ),
                confidence=0.0,
                source_url="https://www.marinetraffic.com/en/ais-api-services",
            ))
            return findings

        # Extract searchable terms
        vessel_name = self._extract_vessel_name(query)
        if not vessel_name:
            return findings

        try:
            import httpx

            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(
                    f"{self.VESSEL_SEARCH}{api_key}/v:2/name:{vessel_name}/protocol:jsono",
                )
                resp.raise_for_status()

                # MarineTraffic returns JSONP-style — strip prefix
                raw = resp.text
                if raw.startswith("jsono("):
                    import json as _json
                    raw = raw[6:-1]  # strip jsono( ... )
                    data = _json.loads(raw)
                else:
                    data = resp.json()

                vessels = data if isinstance(data, list) else data.get("data", {}).get("rows", [])

                if vessels:
                    entries = []
                    for v in vessels[:5]:
                        name = v.get("SHIPNAME", v.get("NAME", "Unknown"))
                        imo = v.get("IMO", "?")
                        mmsi = v.get("MMSI", "?")
                        flag = v.get("FLAG", v.get("COUNTRY", "?"))
                        ship_type = v.get("SHIPTYPE", v.get("TYPE", "?"))
                        lat = v.get("LAT", "")
                        lon = v.get("LON", "")

                        entries.append(
                            f"- **{name}** (IMO: {imo}) — {flag} flag\n"
                            f"  Type: {ship_type} | MMSI: {mmsi}"
                            + (f" | Position: {lat}, {lon}" if lat and lon else "")
                        )

                    findings.append(self._make_finding(
                        title=f"🚢 MarineTraffic: {len(vessels)} vessels matching '{vessel_name}'",
                        description="\n".join(entries[:5]),
                        confidence=0.85,
                        evidence=[f"https://www.marinetraffic.com/en/ais/details/ships/name:{vessel_name}"],
                    ))
                else:
                    findings.append(self._make_finding(
                        title=f"🚢 MarineTraffic: No vessels found for '{vessel_name}'",
                        description="No vessels matching the query in the AIS database.",
                        confidence=0.6,
                    ))

        except Exception as e:
            logger.warning("marinetraffic_search_failed: %s", e)
            findings.append(self._make_finding(
                title=f"⚠ MarineTraffic search failed: {str(e)[:100]}",
                description="API call failed. Check your key or try again later.",
                confidence=0.0,
            ))

        return findings

    @staticmethod
    def _extract_vessel_name(query: str) -> str | None:
        """Extract vessel name or IMO number from query."""
        import re

        # IMO number: 7 digits
        imo = re.search(r'\b(\d{7})\b', query)
        if imo:
            return imo.group(1)

        # Vessel name in quotes
        quoted = re.search(r'"([^"]+)"', query)
        if quoted:
            return quoted.group(1)

        # Vessel name keyword
        vessel = re.search(r'(?:ship|vessel|tanker|vessel_name)\s*[:=]?\s*([A-Za-z0-9\s]{2,30})', query, re.IGNORECASE)
        if vessel:
            return vessel.group(1).strip()

        return None


# Register
marinetraffic_tool = MarineTrafficTool()
registry.register(marinetraffic_tool)
