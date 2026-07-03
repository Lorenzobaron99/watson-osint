"""Geolocation tool — pinpoint locations from visual clues and coordinates."""

from __future__ import annotations

from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSource
from ..utils.http import get_client

import logging

logger = logging.getLogger("watson.geolocation")


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

    async def _overpass_query(self, query: str) -> dict | None:
        """Run an Overpass QL query via POST (required for larger queries)."""
        import httpx
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                self.OVERPASS_API,
                data={"data": query},
                headers={"Accept": "application/json", "User-Agent": "WatsonOSINT/0.3"},
            )
            r.raise_for_status()
            return r.json()

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
            data = await self._overpass_query(query)

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

    async def investigate_infrastructure(self, place_name: str) -> list[Finding]:
        """Geocode a place then find nearby strategic infrastructure.

        Queries ports, mines, refineries, military facilities — relevant for
        sanctions evasion, conflict mineral smuggling, and commodity fraud investigations.
        """
        findings: list[Finding] = []
        client = get_client(rate_limit=self.rate_limit_rps)

        # Step 1: Geocode the place
        try:
            params = {"q": place_name, "format": "json", "limit": 1}
            data = await client.get_json(self.NOMINATIM_SEARCH, params=params)
            if not isinstance(data, list) or not data:
                return findings

            lat = float(data[0]["lat"])
            lon = float(data[0]["lon"])
            display = data[0].get("display_name", place_name)[:80]

            findings.append(self._make_finding(
                title=f"📍 Geocoded: {display}",
                description=f"Coordinates: {lat}, {lon}\n[OpenStreetMap](https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=12)",
                evidence=[f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=12"],
                confidence=0.95,
                lat=lat, lon=lon,
            ))

            # Step 2: Find infrastructure within 50km
            infra = await self._nearby_infrastructure(lat, lon, client)
            findings.extend(infra)

        except Exception:
            pass

        return findings

    async def _nearby_infrastructure(self, lat: float, lon: float, client) -> list[Finding]:
        """Query Overpass for strategic infrastructure near a point.

        Queries nodes, ways, AND relations for industrial/mining/military/port
        features. Nornickel-type targets need ways (mine boundaries) and relations.
        """
        findings: list[Finding] = []
        radius = 50000  # 50km radius

        # ── Single combined query: nodes + ways + relations for all categories ──
        # This avoids 4 sequential API calls (4×1.5s = 6s saved) and catches
        # ways/relations that were invisible to node-only queries.
        query = f"""[out:json][timeout:25];
(
  // Mines & quarries — nodes, ways, relations
  node(around:{radius},{lat},{lon})["landuse"="quarry"];
  way(around:{radius},{lat},{lon})["landuse"="quarry"];
  rel(around:{radius},{lat},{lon})["landuse"="quarry"];
  node(around:{radius},{lat},{lon})["landuse"="mining"];
  way(around:{radius},{lat},{lon})["landuse"="mining"];
  rel(around:{radius},{lat},{lon})["landuse"="mining"];

  // Industrial facilities — factories, refineries, smelters
  node(around:{radius},{lat},{lon})["landuse"="industrial"];
  way(around:{radius},{lat},{lon})["landuse"="industrial"];
  rel(around:{radius},{lat},{lon})["landuse"="industrial"];
  node(around:{radius},{lat},{lon})["man_made"="works"];
  way(around:{radius},{lat},{lon})["man_made"="works"];
  node(around:{radius},{lat},{lon})["industrial"];
  way(around:{radius},{lat},{lon})["industrial"];

  // Ports & harbours
  node(around:{radius},{lat},{lon})["amenity"="ferry_terminal"];
  node(around:{radius},{lat},{lon})["harbour"];
  way(around:{radius},{lat},{lon})["harbour"];

  // Military
  node(around:{radius},{lat},{lon})["landuse"="military"];
  way(around:{radius},{lat},{lon})["landuse"="military"];
  node(around:{radius},{lat},{lon})["aeroway"="aerodrome"]["name"];
);
out center 20;
"""

        loc_label = display_name(lat, lon)

        try:
            data = await self._overpass_query(query)

            if isinstance(data, dict) and "elements" in data:
                elements = data["elements"]
                # Group by category
                mines: list[str] = []
                industrial: list[str] = []
                ports: list[str] = []
                military: list[str] = []

                for el in elements[:20]:
                    tags = el.get("tags", {})
                    name = tags.get("name", "")
                    # Get center for ways/relations
                    center = el.get("center", {})
                    el_lat = center.get("lat", el.get("lat", 0))
                    el_lon = center.get("lon", el.get("lon", 0))
                    elem_type = el.get("type", "node")

                    label = f"- **{name}**" if name else f"- Unnamed {elem_type}"
                    if el_lat and el_lon:
                        label += f" ({el_lat:.4f}, {el_lon:.4f})"

                    # Classify into category
                    landuse = tags.get("landuse", "")
                    man_made = tags.get("man_made", "")
                    industrial_tag = tags.get("industrial", "")
                    amenity = tags.get("amenity", "")
                    aeroway = tags.get("aeroway", "")
                    harbour_tag = tags.get("harbour", "")
                    has_name = tags.get("name", "")

                    if landuse in ("quarry", "mining"):
                        mines.append(label)
                    elif landuse == "industrial" or man_made == "works" or industrial_tag:
                        industrial.append(label)
                    elif amenity == "ferry_terminal" or harbour_tag:
                        ports.append(label)
                    elif landuse == "military" or (aeroway == "aerodrome" and has_name):
                        military.append(label)

                titles = {
                    "mines": "⛏ Mines & quarries",
                    "industrial": "🏭 Industrial facilities",
                    "ports": "🚢 Ports & harbours",
                    "military": "🪖 Military installations",
                }
                for cat, entries in [("mines", mines), ("industrial", industrial),
                                      ("ports", ports), ("military", military)]:
                    if entries:
                        findings.append(self._make_finding(
                            title=f"{titles[cat]} near {loc_label}",
                            description="\n".join(entries[:6]),
                            confidence=0.85,
                            infrastructure_type=cat,
                        ))

        except Exception as e:
            logger.warning("overpass_infra_failed: %s", e)

        return findings


def display_name(lat: float, lon: float) -> str:
    return f"({lat:.3f}, {lon:.3f})"


# Register
geolocation_tool = GeolocationTool()
registry.register(geolocation_tool)
