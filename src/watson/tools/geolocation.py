"""Geolocation tool — pinpoint locations from visual clues and coordinates."""

from __future__ import annotations

from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSource
from ..utils.http import get_client


class GeolocationTool(OSINTTool):
    """Investigate and verify locations — geocoding, reverse geocoding, and POI search."""

    category = FindingSource.GEOLOCATION
    name = "geolocation"
    description = "Forward/reverse geocoding, POI search, address verification"
    free_tier_available = True
    rate_limit_rps = 1.0

    NOMINATIM_SEARCH = "https://nominatim.openstreetmap.org/search"
    NOMINATIM_REVERSE = "https://nominatim.openstreetmap.org/reverse"
    OVERPASS_API = "https://overpass-api.de/api/interpreter"

    async def investigate(self, query: str, context: str = "") -> list[Finding]:
        findings: list[Finding] = []
        client = get_client(rate_limit=self.rate_limit_rps)

        # Check for coordinates in the query
        coords = self._parse_coordinates(query)

        if coords:
            lat, lon = coords
            try:
                params = {"lat": lat, "lon": lon, "format": "json", "zoom": 18}
                data = await client.get_json(self.NOMINATIM_REVERSE, params=params)

                if isinstance(data, dict):
                    display = data.get("display_name", f"{lat}, {lon}")
                    address = data.get("address", {})

                    findings.append(
                        self._make_finding(
                            title=f"📍 Reverse geocode: {display[:80]}",
                            description=(
                                f"Coordinates {lat}, {lon} resolve to: "
                                f"{address.get('road', '')} {address.get('city', '')}, "
                                f"{address.get('country', '')}"
                            ),
                            evidence=[f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=18"],
                            confidence=0.95,
                            lat=lat,
                            lon=lon,
                            address=address,
                        )
                    )

                    # Find nearby POIs via Overpass
                    pois = await self._nearby_pois(lat, lon, client)
                    findings.extend(pois)

            except Exception as e:
                findings.append(
                    self._make_finding(
                        title="Geolocation lookup failed",
                        description=f"Error reverse-geocoding {lat}, {lon}: {str(e)}",
                        confidence=0.0,
                    )
                )

        else:
            # Try forward geocoding — search for a place name
            location = self._extract_place(query)
            if location:
                try:
                    params = {"q": location, "format": "json", "limit": 3}
                    data = await client.get_json(self.NOMINATIM_SEARCH, params=params)

                    if isinstance(data, list) and data:
                        places = []
                        for d in data[:3]:
                            places.append(f"{d.get('display_name', '')[:60]} ({d.get('lat')}, {d.get('lon')})")

                        findings.append(
                            self._make_finding(
                                title=f"📍 Places matching '{location}'",
                                description="\n".join(f"- {p}" for p in places),
                                confidence=0.85,
                            )
                        )
                except Exception:
                    pass

        return findings

    def _parse_coordinates(self, text: str) -> tuple[float, float] | None:
        """Extract lat/lon from text."""
        import re

        # Decimal degrees: 48.8566, 2.3522
        match = re.search(r"(-?\d+\.\d+)\s*[,;\s]\s*(-?\d+\.\d+)", text)
        if match:
            return float(match.group(1)), float(match.group(2))

        # DMS format: 48°51'24"N, 2°21'08"E — simplified
        match = re.search(
            r"(\d+)°\s*(\d+)'?\s*(\d+(?:\.\d+)?)\"?\s*([NS])[\s,;]+\s*(\d+)°\s*(\d+)'?\s*(\d+(?:\.\d+)?)\"?\s*([EW])",
            text,
        )
        if match:
            lat = int(match.group(1)) + int(match.group(2)) / 60 + float(match.group(3)) / 3600
            if match.group(4) == "S":
                lat = -lat
            lon = int(match.group(5)) + int(match.group(6)) / 60 + float(match.group(7)) / 3600
            if match.group(8) == "W":
                lon = -lon
            return lat, lon

        return None

    async def _nearby_pois(self, lat: float, lon: float, client) -> list[Finding]:
        """Find points of interest near a location using Overpass API."""
        findings: list[Finding] = []
        radius = 500  # meters

        query = f"""
        [out:json];
        (
          node(around:{radius},{lat},{lon})["amenity"];
          node(around:{radius},{lat},{lon})["tourism"];
          node(around:{radius},{lat},{lon})["historic"];
          node(around:{radius},{lat},{lon})["building"]["name"];
        );
        out 5;
        """

        try:
            data = await client.get_json(self.OVERPASS_API, params={"data": query})

            if isinstance(data, dict) and "elements" in data:
                elements = data["elements"][:5]
                if elements:
                    pois = []
                    for el in elements:
                        tags = el.get("tags", {})
                        name = tags.get("name", "Unnamed")
                        amenity = tags.get("amenity", tags.get("tourism", tags.get("historic", "")))
                        pois.append(f"{name} ({amenity})" if amenity else name)

                    findings.append(
                        self._make_finding(
                            title=f"🏛 Nearby landmarks ({len(elements)} found)",
                            description="\n".join(f"- {p}" for p in pois),
                            confidence=0.8,
                            lat=lat,
                            lon=lon,
                            radius=radius,
                        )
                    )
        except Exception:
            pass

        return findings

    def _extract_place(self, text: str) -> str | None:
        """Extract a place name from query text."""
        import re

        patterns = [
            r"(?:find|locate|search|show|look up|geolocate)\s+(.+?)(?:\s+(?:and|or|for|$|\.))",
            r"(?:where is|what is at)\s+(.+?)(?:\?|$)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip().rstrip(".,?")
        return None


# Register
geolocation_tool = GeolocationTool()
registry.register(geolocation_tool)
