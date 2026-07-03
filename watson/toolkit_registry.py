"""
Bellingcat OSINT Toolkit Registry — 338 tools × 24 categories.

Loads the official Bellingcat toolkit CSV and provides:
- Search by category, keyword, target type
- Auto-classification: given a target, determines which tools apply
- URL templates for parameterized tool access
- Direct API integrations for tools with public endpoints
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

# ── CSV path (downloaded from bellingcat/toolkit releases) ──────────
_CSV_PATH = Path(__file__).resolve().parent.parent / "data" / "bellingcat_toolkit.csv"


@dataclass
class BellingcatTool:
    """Single tool from the Bellingcat toolkit."""
    category: str
    name: str
    url: str
    description: str
    cost: str  # Free, Paid, Partially Free
    details: str = ""  # GitBook link

    @property
    def is_free(self) -> bool:
        return "free" in self.cost.lower() and "paid" not in self.cost.lower()

    @property
    def is_api_accessible(self) -> bool:
        """Heuristic: tools that likely have programmatic API access."""
        api_indicators = ["api.", "/api/", "api-", "api_", "graphql", "rest."]
        return any(ind in self.url.lower() for ind in api_indicators)

    @property
    def is_url_templateable(self) -> bool:
        """Heuristic: tools whose URL can be parameterized with a query."""
        return bool(self.url) and self.url.startswith("http") and not self.is_api_accessible


# ── Target-type → relevant Bellingcat categories ────────────────────
TARGET_CATEGORY_MAP: dict[str, list[str]] = {
    "person": [
        "People", "Facebook", "Instagram", "Twitter/X", "Tiktok",
        "Other Platforms", "Multiple Platforms", "Facial Recognition",
        "Reverse Image Search", "Metadata", "Archiving",
        "Telegram", "Youtube",  # added — key social platforms
    ],
    "company": [
        "Companies & Finance", "Websites", "Archiving", "Data Organization & Analysis",
        "Maps", "Transport", "Geolocation", "Metadata",  # added — supply chain tracking
    ],
    "domain": [
        "Websites", "Archiving", "Data Organization & Analysis",
        "Companies & Finance", "Metadata", "Maps",  # added — WHOIS, DNS, IP geolocation
    ],
    "email": [
        "People", "Websites", "Other Platforms", "Data Organization & Analysis",
        "Metadata", "Archiving",  # added — breach tracking, archive search
    ],
    "username": [
        "People", "Multiple Platforms", "Other Platforms", "Facebook",
        "Instagram", "Twitter/X", "Tiktok", "Youtube", "Telegram",
    ],
    "phone": [
        "People", "Other Platforms", "Telegram", "Metadata",  # added metadata
    ],
    "image": [
        "Reverse Image Search", "Facial Recognition", "Metadata",
        "Misc", "Geolocation", "Maps", "Satellite Imagery", "Street View",
    ],
    "location": [
        "Geolocation", "Maps", "Satellite Imagery", "Street View",
        "Environment & Wildlife", "Conflict", "Transport",
    ],
    "social_media": [
        "Facebook", "Instagram", "Twitter/X", "Tiktok", "Youtube",
        "Telegram", "Multiple Platforms", "Other Platforms", "Archiving",
    ],
    "vehicle": [
        "Transport", "Maps", "Satellite Imagery", "Geolocation", "Street View",
    ],
    "ship": [
        "Transport", "Maps", "Satellite Imagery",
    ],
    "aircraft": [
        "Transport", "Maps", "Satellite Imagery",
    ],
    "organization": [
        "Companies & Finance", "Websites", "Archiving", "Conflict",
        "Environment & Wildlife", "People", "Metadata",  # added metadata
    ],
}


# ── URL templates for parameterized tools ───────────────────────────
URL_TEMPLATES: dict[str, str] = {
    # People
    "Google": "https://www.google.com/search?q={query}",
    "DuckDuckGo": "https://duckduckgo.com/?q={query}",
    "Bing": "https://www.bing.com/search?q={query}",
    "Yandex": "https://yandex.com/search/?text={query}",
    "Baidu": "https://www.baidu.com/s?wd={query}",
    # Social
    "Twitter Advanced Search": "https://twitter.com/search?q={query}&f=live",
    "TweetDeck": "https://tweetdeck.twitter.com/",
    "Social Blade": "https://socialblade.com/youtube/search/{query}",
    "WhatsMyName Web": "https://whatsmyname.app/?q={query}",
    "Namechk": "https://namechk.com/",
    "Namecheckr": "https://www.namecheckr.com/search/{query}",
    "Instant Username Search": "https://instantusername.com/?q={query}",
    "CheckUsernames": "https://checkusernames.com/",
    # Websites
    "urlscan.io": "https://urlscan.io/search/#{query}",
    "Shodan": "https://www.shodan.io/search?query={query}",
    "Censys": "https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q={query}",
    "ZoomEye": "https://www.zoomeye.org/searchResult?q={query}",
    "VirusTotal": "https://www.virustotal.com/gui/search/{query}",
    "crt.sh": "https://crt.sh/?q={query}",
    "DNSDumpster": "https://dnsdumpster.com/",
    "SecurityTrails": "https://securitytrails.com/domain/{query}",
    "BuiltWith": "https://builtwith.com/{query}",
    "Wappalyzer": "https://www.wappalyzer.com/lookup/{query}",
    # Companies
    "OpenCorporates": "https://opencorporates.com/companies?q={query}",
    "OpenSanctions": "https://opensanctions.org/search/?q={query}",
    "ICIJ Offshore Leaks": "https://offshoreleaks.icij.org/search?q={query}",
    "Companies House (UK)": "https://find-and-update.company-information.service.gov.uk/search?q={query}",
    "SEC EDGAR": "https://www.sec.gov/cgi-bin/browse-edgar?company={query}&action=getcompany",
    "EU Sanctions Map": "https://sanctionsmap.eu/#/main?search=%7B%22value%22:%22{query}%22%7D",
    # Maps / Satellite
    "Google Maps": "https://www.google.com/maps/search/{query}",
    "Google Earth": "https://earth.google.com/web/search/{query}",
    "OpenStreetMap": "https://www.openstreetmap.org/search?query={query}",
    "Bing Maps": "https://www.bing.com/maps?q={query}",
    "Yandex Maps": "https://yandex.com/maps/?text={query}",
    "Wikimapia": "https://wikimapia.org/#lang=en&lat=0&lon=0&z=1&search={query}",
    "Sentinel Hub EO Browser": "https://apps.sentinel-hub.com/eo-browser/?zoom=12&lat=0&lng=0&query={query}",
    "Zoom Earth": "https://zoom.earth/#view={query}",
    "SunCalc": "https://www.suncalc.org/#/{query}",
    # Transport
    "MarineTraffic": "https://www.marinetraffic.com/en/ais/home/centerx:0/centery:0/zoom:2",
    "VesselFinder": "https://www.vesselfinder.com/?imo={query}",
    "FlightRadar24": "https://www.flightradar24.com/data/search?q={query}",
    "FlightAware": "https://flightaware.com/live/flight/{query}",
    "ADS-B Exchange": "https://globe.adsbexchange.com/?icao={query}",
    "OpenSky Network": "https://opensky-network.org/aircraft-profile?icao24={query}",
    "ShipSpotting": "https://www.shipspotting.com/photos/search?query={query}",
    # Archiving
    "Wayback Machine": "https://web.archive.org/web/*/https://{query}",
    "archive.today": "https://archive.today/?run=1&url=https://{query}",
    "CachedView": "https://cachedview.com/?q={query}",
    # Data / Leaks
    "Have I Been Pwned": "https://haveibeenpwned.com/account/{query}",
    "DeHashed": "https://dehashed.com/search?query={query}",
    "Intelligence X": "https://intelx.io/?s={query}",
    "GhostProject": "https://ghostproject.fr/",
    "LeakCheck": "https://leakcheck.io/search?query={query}",
    # Telegram
    "Telemetrio": "https://telemetr.io/en/channels?query={query}",
    "Tgstat": "https://tgstat.com/search?q={query}",
    "TelegramDB": "https://telegramdb.org/search?q={query}",
    # Conflict
    "ACLED": "https://acleddata.com/data-export-tool/",
    "LiveUAMap": "https://liveuamap.com/",
    # Image / Video
    "Google Images": "https://www.google.com/search?tbm=isch&q={query}",
    "Google Lens": "https://lens.google.com/uploadbyurl?url={query}",
    "Yandex Images": "https://yandex.com/images/search?rpt=imageview&url={query}",
    "Bing Images": "https://www.bing.com/images/search?q={query}",
    "TinEye": "https://tineye.com/search?url={query}",
    "PimEyes": "https://pimeyes.com/en/search/{query}",
    "FaceCheck.id": "https://facecheck.id/",
    "InVID Verification": "https://citizenevidence.org/2024/03/05/invid-weverify-verification-plugin/",
    # Added — high-value tools missing templates
    "SpiderFoot HX": "https://www.spiderfoot.net/hx/?q={query}",
    "Maigret": "https://github.com/soxoj/maigret",
    "GHunt": "https://github.com/mxrch/GHunt",
    "Holehe": "https://github.com/megadose/holehe",
    "Blackbird": "https://github.com/p1ngul1n0/blackbird",
    "Sherlock": "https://github.com/sherlock-project/sherlock",
    "WhatsApp Group Links": "https://whatsgrouplink.com/?s={query}",
    "Epieos": "https://epieos.com/?q={query}",
    "That's Them": "https://thatsthem.com/people/{query}",
    "FamilyTreeNow": "https://www.familytreenow.com/search/genealogy/results?first=&last={query}",
    "TruePeopleSearch": "https://www.truepeoplesearch.com/results?name={query}",
    "FastPeopleSearch": "https://www.fastpeoplesearch.com/name/{query}",
    "PeekYou": "https://www.peekyou.com/{query}",
    "Spokeo": "https://www.spokeo.com/{query}",
    "Whitepages": "https://www.whitepages.com/name/{query}",
    "BeenVerified": "https://www.beenverified.com/search?q={query}",
    "USPhoneBook": "https://www.usphonebook.com/{query}",
    "SearchSystems": "https://publicrecords.searchsystems.net/search.php?q={query}",
    "OCCRP Aleph": "https://aleph.occrp.org/search?q={query}",
    "Sanctions List Search": "https://sanctionssearch.ofac.treas.gov/Details.aspx?id={query}",
    "Interpol Red Notices": "https://www.interpol.int/How-we-work/Notices/Red-Notices/View-Red-Notices",
    "WikiLeaks": "https://search.wikileaks.org/?q={query}",
    "Panama Papers": "https://offshoreleaks.icij.org/search?q={query}",
    "GeoSpy": "https://geospy.ai/",
    "Overpass Turbo": "https://overpass-turbo.eu/?Q={query}",
    "Picarta": "https://picarta.ai/",
    "YouTube Geofind": "https://mattw.io/youtube-geofind/location",
    "GeoGuessr": "https://www.geoguessr.com/",
    "PeakVisor": "https://peakvisor.com/search?q={query}",
    "Wikimapia": "https://wikimapia.org/#lang=en&lat=0&lon=0&z=1&search={query}",
}


class BellingcatRegistry:
    """Loads, indexes, and queries the Bellingcat OSINT Toolkit."""

    def __init__(self, csv_path: Path | None = None):
        self._tools: list[BellingcatTool] = []
        self._by_category: dict[str, list[BellingcatTool]] = {}
        self._by_name: dict[str, BellingcatTool] = {}
        self._by_keyword: dict[str, list[BellingcatTool]] = {}
        self._path = csv_path or _CSV_PATH
        self._loaded = False

    def load(self) -> None:
        """Load and index the CSV."""
        if self._loaded:
            return
        if not self._path.exists():
            raise FileNotFoundError(f"Bellingcat CSV not found at {self._path}. Run download first.")

        with open(self._path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                tool = BellingcatTool(
                    category=row.get("Category", "").strip(),
                    name=row.get("Name", "").strip(),
                    url=row.get("URL", "").strip(),
                    description=row.get("Description", "").strip(),
                    cost=row.get("Cost", "").strip(),
                    details=row.get("Details", "").strip(),
                )
                self._tools.append(tool)
                self._by_category.setdefault(tool.category, []).append(tool)
                self._by_name[tool.name.lower()] = tool

                # Build keyword index from name + description
                text = f"{tool.name} {tool.description}".lower()
                words = set(re.findall(r"[a-z0-9]+", text))
                for w in words:
                    if len(w) > 2:  # Skip very short words
                        self._by_keyword.setdefault(w, []).append(tool)

        self._loaded = True

    @property
    def tools(self) -> list[BellingcatTool]:
        self.load()
        return self._tools

    @property
    def categories(self) -> list[str]:
        self.load()
        return sorted(self._by_category.keys())

    def get_category(self, category: str) -> list[BellingcatTool]:
        self.load()
        return self._by_category.get(category, [])

    def get(self, name: str) -> BellingcatTool | None:
        self.load()
        return self._by_name.get(name.lower())

    def search(self, query: str, limit: int = 20) -> list[BellingcatTool]:
        """Free-text search across tool names and descriptions."""
        self.load()
        tokens = set(re.findall(r"[a-z0-9]+", query.lower()))
        scores: dict[str, tuple[int, BellingcatTool]] = {}
        for token in tokens:
            if len(token) <= 2:
                continue
            for tool in self._by_keyword.get(token, []):
                key = tool.name.lower()
                if key in scores:
                    scores[key] = (scores[key][0] + 1, tool)
                else:
                    scores[key] = (1, tool)
        ranked = sorted(scores.values(), key=lambda x: -x[0])
        return [t for _, t in ranked[:limit]]

    def classify(self, target_type: str) -> list[str]:
        """Return the Bellingcat categories relevant to a target type."""
        return TARGET_CATEGORY_MAP.get(target_type.lower(), ["People", "Websites", "Companies & Finance"])

    def tools_for_target(self, target_type: str) -> list[BellingcatTool]:
        """Return all Bellingcat tools relevant to a target type."""
        self.load()
        categories = self.classify(target_type)
        tools: list[BellingcatTool] = []
        seen: set[str] = set()
        for cat in categories:
            for tool in self._by_category.get(cat, []):
                if tool.name.lower() not in seen:
                    tools.append(tool)
                    seen.add(tool.name.lower())
        return tools

    def build_url(self, tool_name: str, query: str) -> str | None:
        """Build a parameterized URL for a tool if a template exists."""
        if tool_name in URL_TEMPLATES:
            return URL_TEMPLATES[tool_name].format(query=quote(query, safe=""))
        # Try case-insensitive match
        for name, template in URL_TEMPLATES.items():
            if name.lower() == tool_name.lower():
                return template.format(query=quote(query, safe=""))
        return None

    def get_url_templates(self) -> dict[str, str]:
        """Return all URL templates."""
        return dict(URL_TEMPLATES)

    def summary(self) -> dict[str, Any]:
        """Return a summary of the registry for the frontend."""
        self.load()
        return {
            "total_tools": len(self._tools),
            "categories": {
                cat: len(tools)
                for cat, tools in sorted(self._by_category.items())
            },
            "target_types": list(TARGET_CATEGORY_MAP.keys()),
            "free_tools": sum(1 for t in self._tools if t.is_free),
            "paid_tools": sum(1 for t in self._tools if t.cost == "Paid"),
            "partial_tools": sum(1 for t in self._tools if "Partially" in t.cost),
            "url_templates": len(URL_TEMPLATES),
        }


# ── Singleton ───────────────────────────────────────────────────────
registry = BellingcatRegistry()
