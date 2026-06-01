"""Conflict monitoring tool — incident data, live conflict maps, event aggregation."""

from __future__ import annotations

from datetime import datetime, timedelta

from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSource
from ..utils.http import get_client


class ConflictTool(OSINTTool):
    """Monitor conflicts — live incident maps, event data, conflict timelines."""

    category = FindingSource.CONFLICT
    name = "conflict-monitor"
    description = "Live conflict maps, incident data (ACLED), event timelines, situation reports"
    free_tier_available = True
    rate_limit_rps = 0.5

    LIVEUAMAP_API = "https://liveuamap.com/"
    ACLED_DASHBOARD = "https://acleddata.com/dashboard/"

    async def investigate(self, query: str, context: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # Extract location from query
        location = self._extract_location(query)
        if not location:
            location = query[:60]

        # 1. Live Universal Awareness Map
        findings.append(
            self._make_finding(
                title=f"🗺 Live conflict map: {location}",
                description=(
                    f"[LiveUAMap](https://liveuamap.com/) provides real-time conflict monitoring "
                    f"with geolocated events. Search for '{location}' on the map to see recent "
                    f"incidents, frontlines, and event timelines."
                ),
                evidence=[
                    f"https://liveuamap.com/?q={location}",
                    "https://liveuamap.com/",
                ],
                confidence=0.8,
                location=location,
            )
        )

        # 2. ACLED data reference
        findings.append(
            self._make_finding(
                title=f"📊 ACLED conflict data: {location}",
                description=(
                    f"The Armed Conflict Location & Event Data Project (ACLED) tracks "
                    f"political violence and protest events worldwide. "
                    f"Use their dashboard to filter by location, date, and event type."
                ),
                evidence=[
                    f"https://acleddata.com/dashboard/#/dashboard",
                    "https://acleddata.com/data-export-tool/",
                ],
                confidence=0.85,
                location=location,
            )
        )

        # 3. Additional resources
        findings.append(
            self._make_finding(
                title=f"📡 OSINT conflict resources for {location}",
                description=(
                    "Recommended monitoring resources:\n"
                    f"- [LiveUAMap](https://liveuamap.com/?q={location}) — real-time mapped events\n"
                    f"- [ACLED Dashboard](https://acleddata.com/dashboard/) — structured event data\n"
                    f"- [NASA FIRMS](https://firms.modaps.eosdis.nasa.gov/map/) — satellite fire/thermal detection\n"
                    f"- [Flightradar24](https://www.flightradar24.com/) — aircraft tracking near conflict zones\n"
                    f"- [MarineTraffic](https://www.marinetraffic.com/) — vessel movements"
                ),
                confidence=0.7,
                location=location,
            )
        )

        return findings

    def _extract_location(self, text: str) -> str | None:
        """Extract a location from conflict-related query."""
        import re

        patterns = [
            r"(?:in|at|near|around)\s+([A-Z][a-zA-Z\s,]+?)(?:\s+(?:and|or|\.|$))",
            r"(?:conflict|war|fighting|clashes|attacks?|incidents?)\s+(?:in|at)\s+([A-Z][a-zA-Z\s,]+?)(?:\s+(?:and|or|\.|$))",
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip().rstrip(".,")

        return None


# Register
conflict_tool = ConflictTool()
registry.register(conflict_tool)
