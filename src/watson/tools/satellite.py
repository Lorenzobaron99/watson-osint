"""Satellite & Maps tool — satellite imagery, terrain, coordinates."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSource
from ..utils.http import get_client
from ..utils.helpers import extract_domain


class SatelliteTool(OSINTTool):
    """Investigate locations via satellite imagery, maps, and geospatial data."""

    category = FindingSource.SATELLITE
    name = "satellite-maps"
    description = "Satellite imagery, terrain data, coordinate lookup, and geospatial analysis"
    free_tier_available = True
    rate_limit_rps = 0.5

    GOOGLE_EARTH_HISTORICAL = "https://earth.google.com/web/search/{location}"
    OPENSTREETMAP_NOMINATIM = "https://nominatim.openstreetmap.org/search"
    OPENSTREETMAP_REVERSE = "https://nominatim.openstreetmap.org/reverse"

    async def investigate(self, query: str, context: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # Try to extract a location from the query
        location = await self._extract_location(query)
        if not location:
            return findings

        client = get_client(rate_limit=self.rate_limit_rps)

        # 1. Geocode the location
        try:
            params = {"q": location, "format": "json", "limit": 3}
            data = await client.get_json(self.OPENSTREETMAP_NOMINATIM, params=params)

            if data and isinstance(data, list) and len(data) > 0:
                first = data[0]
                lat = first.get("lat")
                lon = first.get("lon")
                display_name = first.get("display_name", location)

                findings.append(
                    self._make_finding(
                        title=f"📍 Location: {display_name[:80]}",
                        description=(
                            f"Coordinates: {lat}, {lon}. "
                            f"Type: {first.get('type', 'unknown')}. "
                            f"Category: {first.get('category', 'unknown')}."
                        ),
                        evidence=[
                            f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=14",
                            self.GOOGLE_EARTH_HISTORICAL.format(location=location),
                        ],
                        confidence=0.9,
                    )
                )

                # 2. Find nearby features from additional results
                if len(data) > 1:
                    nearby = ", ".join(
                        d.get("display_name", "").split(",")[0].strip()
                        for d in data[1:3]
                    )
                    findings.append(
                        self._make_finding(
                            title=f"Nearby: {nearby}",
                            description=f"Related locations found near {display_name.split(',')[0]}.",
                            confidence=0.7,
                            lat=lat,
                            lon=lon,
                        )
                    )

        except Exception as e:
            findings.append(
                self._make_finding(
                    title="Satellite lookup limited",
                    description=f"Could not retrieve full satellite data: {str(e)}. Try the Google Earth link.",
                    evidence=[self.GOOGLE_EARTH_HISTORICAL.format(location=location)],
                    confidence=0.3,
                )
            )

        return findings

    async def _extract_location(self, text: str) -> str | None:
        """Extract a location string from the query text."""
        # Simple heuristic: look for location patterns
        import re

        # Match "in X" or "near X" or "at X" patterns
        patterns = [
            r"(?:in|near|at|around|over)\s+([A-Z][a-zA-Z\s,]+?)(?:\s+(?:and|or|\.|$|,))",
            r"location[s]?\s+(?:is|are|:)?\s+([A-Z][a-zA-Z\s,]+?)(?:\s+(?:and|or|\.|$))",
        ]

        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1).strip().rstrip(".,")

        # If no pattern matched, check if the whole thing might be a location
        if len(text) < 80 and any(c.isupper() for c in text):
            return text.strip()

        return None


# Register
satellite_tool = SatelliteTool()
registry.register(satellite_tool)
