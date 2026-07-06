"""OSINT Framework integration — maps 1,417 OSINT tools to Watson entity types.

The OSINT Framework (https://osintframework.com) is a curated tree of OSINT
tools organized by investigation target (username, email, domain, IP, etc.).
Maltego's competitive advantage is its Transform Hub — a marketplace of paid
data connectors. OSINT Framework is the open-source equivalent.

This module:
  1. Loads the framework tree from cache (downloads on first use)
  2. Maps framework categories to Watson entity types
  3. Provides tool lookup by entity type (e.g., "what tools investigate domains?")
  4. Generates search URLs for discovered entities (enrichment transforms)

Integration: when the graph engine discovers a new entity (e.g., a domain),
it queries OSINT Framework for relevant investigation tools, then enriches
findings with direct links to those tools — compensating for Watson's lack
of direct database access.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from .entities import EntityType

logger = logging.getLogger("watson.graph.osint_framework")

# Cache location
_CACHE_DIR = Path.home() / ".watson" / "cache"
_CACHE_FILE = _CACHE_DIR / "osint_framework.json"
_FRAMEWORK_URL = (
    "https://raw.githubusercontent.com/lockfale/osint-framework/"
    "master/public/arf.json"
)

# ── Category → EntityType mapping ─────────────────────────────────
# Maps OSINT Framework top-level categories to Watson entity types.
# When Watson discovers a Domain, it looks up the Domain category
# in the framework and gets all subcategory tools.

CATEGORY_ENTITY_MAP: dict[str, EntityType] = {
    "Username": EntityType.PERSON,
    "Email Address": EntityType.EMAIL,
    "Domain Name": EntityType.DOMAIN,
    "IP & MAC Address": EntityType.IP_ADDRESS,
    "Images / Videos / Docs": EntityType.DOCUMENT,
    "Social Networks": EntityType.PERSON,
    "People Search Engines": EntityType.PERSON,
    "Public Records": EntityType.PERSON,
    "Business Records": EntityType.ORGANIZATION,
    "Telephone Numbers": EntityType.PERSON,
    "Geolocation Tools / Maps": EntityType.LOCATION,
    "Cloud Infrastructure": EntityType.DOMAIN,
    "Blockchain & Cryptocurrency": EntityType.ORGANIZATION,
    "Dark Web": EntityType.DOCUMENT,
    "Archives": EntityType.WEBSITE,
    "Search Engines": EntityType.WEBSITE,
    "Online Communities": EntityType.WEBSITE,
}


class OSINTFramework:
    """Query interface to the OSINT Framework tree."""

    def __init__(self):
        self._tree: dict = {}
        self._loaded = False
        self._by_entity_type: dict[EntityType, list[dict]] = {}

    # ── Loading ──────────────────────────────────────────────────

    def _ensure_loaded(self) -> None:
        """Load the framework tree from cache or download it."""
        if self._loaded:
            return

        if _CACHE_FILE.exists():
            try:
                self._tree = json.loads(_CACHE_FILE.read_text())
                self._loaded = True
                self._build_index()
                logger.info(
                    "osint_framework_loaded_from_cache: %s",
                    _CACHE_FILE,
                )
                return
            except (json.JSONDecodeError, OSError):
                logger.warning("osint_framework_cache_corrupt, re-downloading")

        self._download()
        self._loaded = True
        self._build_index()

    def _download(self) -> None:
        """Download the framework data from GitHub."""
        import urllib.request

        logger.info("osint_framework_downloading: %s", _FRAMEWORK_URL)
        try:
            _CACHE_DIR.mkdir(parents=True, exist_ok=True)
            urllib.request.urlretrieve(_FRAMEWORK_URL, str(_CACHE_FILE))
            self._tree = json.loads(_CACHE_FILE.read_text())
            logger.info(
                "osint_framework_downloaded: %d top-level nodes",
                len(self._tree.get("children", [])),
            )
        except Exception as e:
            logger.error("osint_framework_download_failed: %s", e)
            self._tree = {"name": "OSINT Framework", "type": "folder", "children": []}

    def _build_index(self) -> None:
        """Build entity-type lookup index from the tree."""
        self._by_entity_type = {}

        root_children = self._tree.get("children", [])
        for category in root_children:
            cat_name = category.get("name", "")
            entity_type = CATEGORY_ENTITY_MAP.get(cat_name)
            if entity_type is None:
                continue

            tools = self._extract_tools(category)
            if tools:
                existing = self._by_entity_type.setdefault(entity_type, [])
                existing.extend(tools)

        # Log what we mapped
        for et, tools in self._by_entity_type.items():
            logger.info(
                "osint_framework_mapped: %s → %d tools",
                et.value,
                len(tools),
            )

    def _extract_tools(self, node: dict, parent_category: str = "") -> list[dict]:
        """Recursively extract tool entries from a framework node."""
        tools: list[dict] = []

        node_type = node.get("type", "")
        name = node.get("name", "")
        url = node.get("url", "")

        if node_type != "folder" and url:
            # This is a leaf tool entry
            tools.append({
                "name": name,
                "url": url,
                "category": parent_category or name,
            })

        for child in node.get("children", []):
            child_category = name if node_type == "folder" else parent_category
            tools.extend(self._extract_tools(child, child_category))

        return tools

    # ── Query API ────────────────────────────────────────────────

    def get_tools_for_entity(self, entity_type: EntityType) -> list[dict]:
        """Return all OSINT Framework tools relevant to an entity type.

        Example:
            >>> framework.get_tools_for_entity(EntityType.DOMAIN)
            [
                {"name": "Domain Dossier", "url": "https://centralops.net/...",
                 "category": "Whois Records"},
                {"name": "Shodan", "url": "https://www.shodan.io/",
                 "category": "Discovery"},
                ...
            ]
        """
        self._ensure_loaded()
        return self._by_entity_type.get(entity_type, [])

    def get_search_urls(
        self,
        entity_type: EntityType,
        value: str,
        max_results: int = 10,
    ) -> list[dict]:
        """Generate ready-to-use search URLs for an entity.

        Takes OSINT Framework tools and interpolates the entity value
        into their search URL templates (where the tool supports it).
        For tools that don't have search URL templates, returns the
        tool homepage as a reference link.

        Returns list of {"tool": str, "url": str, "category": str}.
        """
        self._ensure_loaded()
        tools = self.get_tools_for_entity(entity_type)
        results: list[dict] = []

        for tool in tools[:max_results]:
            url = tool["url"]
            name = tool["name"]

            # Interpolate search parameters where supported
            if "<%3C" in url or "%3C" in url:
                # Has a template parameter — interpolate the entity value
                url = url.replace("<%3Cusername%3E>", value)
                url = url.replace("<%3Cdomain%3E>", value)
                url = url.replace("<%3Cemail%3E>", value)
                url = url.replace("<%3Cip%3E>", value)

            results.append({
                "tool": name,
                "url": url,
                "category": tool.get("category", ""),
            })

        return results

    def get_categories(self) -> list[str]:
        """Return all top-level OSINT Framework categories."""
        self._ensure_loaded()
        return [
            c.get("name", "")
            for c in self._tree.get("children", [])
        ]

    def search_tools(self, keyword: str, limit: int = 20) -> list[dict]:
        """Search all tools by keyword (case-insensitive)."""
        self._ensure_loaded()
        keyword_lower = keyword.lower()
        results: list[dict] = []

        def _search(node):
            name = node.get("name", "")
            if keyword_lower in name.lower():
                url = node.get("url", "")
                if url:
                    results.append({"name": name, "url": url})
            for child in node.get("children", []):
                _search(child)

        _search(self._tree)
        return results[:limit]

    @property
    def total_tools(self) -> int:
        """Total number of tool entries in the framework."""
        self._ensure_loaded()

        def _count(node):
            if node.get("type") != "folder" and node.get("url"):
                return 1
            return sum(_count(c) for c in node.get("children", []))

        return _count(self._tree)


# ── Singleton ─────────────────────────────────────────────────────

_framework_instance: Optional[OSINTFramework] = None


def get_framework() -> OSINTFramework:
    """Get or create the singleton OSINT Framework instance."""
    global _framework_instance
    if _framework_instance is None:
        _framework_instance = OSINTFramework()
    return _framework_instance
