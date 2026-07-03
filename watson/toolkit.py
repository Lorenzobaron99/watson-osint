"""
Bellingcat Toolkit Tool — Integrates Bellingcat OSINT tools into Watson.

This tool orchestrates OSINT investigations using direct API calls,
browser scraping, and URL templating. Context-aware deduplication
via investigation_context parameter.
"""

from __future__ import annotations

import asyncio
import aiohttp
import json
import re
import uuid
from urllib.parse import quote

import ssl as _ssl
try:
    import certifi as _certifi
    _SSL_CTX = _ssl.create_default_context(cafile=_certifi.where())
except ImportError:
    _SSL_CTX = False

from src.watson.core.models import Finding, FindingSeverity, FindingSource
from .toolkit_registry import BellingcatRegistry
from src.watson.tools.base import OSINTTool
from src.watson.tools.registry import registry


DIRECT_APIS: dict[str, dict] = {
    "urlscan.io": {"search_url": "https://urlscan.io/api/v1/search/?q={query}", "headers": {"User-Agent": "Mozilla/5.0 (compatible; Watson-OSINT/1.0)"}, "extract": "results"},
    "crt.sh": {"search_url": "https://crt.sh/?q=%25.{query}&output=json", "headers": {"User-Agent": "Mozilla/5.0 (compatible; Watson-OSINT/1.0)"}, "extract": "root"},
    "Wayback CDX": {"search_url": "https://web.archive.org/cdx/search/cdx?url=*.{query}/*&output=json&fl=timestamp,original,statuscode&limit=50", "headers": {"User-Agent": "Mozilla/5.0 (compatible; Watson-OSINT/1.0)"}, "extract": "root"},
    "OpenCorporates": {"search_url": "https://api.opencorporates.com/v0.4/companies/search?q={query}", "headers": {"User-Agent": "Mozilla/5.0 (compatible; Watson-OSINT/1.0)", "Authorization": "ApiKey {api_key}"}, "extract": "companies", "requires_key": True},
    "OpenSanctions": {"search_url": "https://api.opensanctions.org/search/default?q={query}&limit=10", "headers": {"x-api-key": "{api_key}"}, "extract": "results", "requires_key": True},
    "Wikidata": {"search_url": "https://www.wikidata.org/w/api.php?action=wbsearchentities&search={query}&language=en&format=json&limit=10&origin=*", "headers": {"User-Agent": "Mozilla/5.0 (compatible; Watson-OSINT/1.0)"}, "extract": "search"},
    "Wikipedia": {"search_url": "https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch={query}&format=json&origin=*&srlimit=10", "headers": {"User-Agent": "Mozilla/5.0 (compatible; Watson-OSINT/1.0)"}, "extract": "search"},
    "WhatsMyName": {"search_url": "https://whatsmyname.app/api/v1/search?username={query}", "headers": {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"}, "extract": "sites"},
    "ICIJ Offshore Leaks": {"method": "POST", "search_url": "https://offshoreleaks.icij.org/api/v1/reconcile", "body": {"query": "{query}"}, "headers": {"Content-Type": "application/json"}, "extract": "result"},
    "OCCRP Aleph": {"search_url": "https://aleph.occrp.org/api/2/entities?q={query}&limit=10", "extract": "results"},
    "VirusTotal": {"search_url": "https://www.virustotal.com/api/v3/domains/{query}", "headers": {"x-apikey": "{api_key}"}, "extract": "data", "requires_key": True},
    "BuiltWith": {"search_url": "https://api.builtwith.com/free1/api.json?LOOKUP={query}", "extract": "Results"},
    "Instant Username Search": {"search_url": "https://instantusername.com/api/search?q={query}", "extract": "results"},
    "OpenSky Network": {"search_url": "https://opensky-network.org/api/metadata/aircraft/icao/{query}", "extract": "root"},
    "FlightAware": {"search_url": "https://flightaware.com/live/flight/{query}", "extract": "html"},
}


class BellingcatToolkit(OSINTTool):
    """Orchestrate Bellingcat OSINT tools against a target."""

    tool_id = "bellingcat_search"
    name = "Bellingcat Search"
    category = "osint"
    version = "2.0.0"
    description = "Orchestrates Bellingcat OSINT tools with direct API calls, scraping, and URL templating."
    SLOW_TOOLS = {"urlscan.io", "VirusTotal", "FlightAware", "OCCRP Aleph"}

    def __init__(self, api_keys: dict | None = None, fast_mode: bool = True):
        super().__init__()
        self._api_keys = api_keys or {}
        self._fast_mode = fast_mode
        self._registry = BellingcatRegistry()
        self._investigation_context: dict = {}
        self._called_apis: set[tuple[str, str]] = set()  # (api_name, query) — prevents re-running same API+target

    async def investigate(self, query: str, context: str = "", on_event=None, on_findings=None, investigation_context: dict | None = None) -> list[Finding]:
        """Run the full Bellingcat pipeline. Context-aware deduplication via investigation_context."""
        if investigation_context:
            self._investigation_context = investigation_context

        def _emit(phase, status, detail="", finding_count=0):
            if on_event:
                on_event("bellingcat_progress", {"phase": phase, "status": status, "detail": detail, "count": finding_count})

        findings: list[Finding] = []
        try:
            self._registry.load()
        except FileNotFoundError:
            return [self._make_finding(title="Toolkit CSV Not Found", description="Run: curl -sL 'https://github.com/bellingcat/toolkit/releases/download/csv/all-tools.csv' -o data/toolkit.csv", severity=FindingSeverity.LOW)]

        _emit("classify", "start", detail="Analyzing target")
        target_type = self._classify_target(query, context)
        tools = self._registry.tools_for_target(target_type)
        categories = self._registry.classify(target_type)
        _emit("classify", "complete", detail=f"Classified as {target_type}")
        # Internal plumbing — not an intelligence finding.  Don't emit as CONFIRMED.

        _emit("direct_apis", "start", detail="Running API queries")
        api_findings = await self._run_direct_apis(query, target_type)
        _emit("direct_apis", "complete", detail=f"{len(api_findings)} results")
        findings.extend(api_findings)

        _emit("automation", "start", detail="Running automated tools")
        auto_findings = await self._run_automation(query, target_type, tools)
        _emit("automation", "complete", detail=f"{len(auto_findings)} automated results")
        findings.extend(auto_findings)

        _emit("browser", "start", detail="Browser analysis")
        browser_findings = await self._run_browser_scraping(query, target_type, tools)
        _emit("browser", "complete", detail=f"{len(browser_findings)} browser findings")
        findings.extend(browser_findings)

        _emit("urls", "start", detail="Building URLs")
        url_findings = self._build_url_references(query, target_type, tools)
        _emit("urls", "complete", detail=f"{len(url_findings)} reference links")
        findings.extend(url_findings)

        findings.append(self._make_finding(title="Bellingcat Complete", description=f"Analyzed {query} across {len(categories)} categories", confidence=0.85))
        return findings

    def _classify_target(self, query: str, context: str) -> str:
        q = (query + " " + context).lower()
        if re.search(r"@[\w.-]+\.[a-z]{2,}", q): return "email"
        if re.search(r"@\w{2,}", q) or re.search(r"\busername[s]?\b", q): return "username"
        if re.search(r"\b\d{10,}\b", q): return "phone"
        if re.search(r"\.(com|org|net|io|gov|edu|uk|de|fr|ru|cn|jp)\b", q) or re.search(r"^[\w-]+\.[a-z]{2,}$", q.strip()): return "domain"
        if re.search(r"\b(lat|lon|latitude|longitude|coordinates|gps)\b", q): return "location"
        if re.search(r"\b(imo|mmsi|call.?sign|ship|vessel|maritime)\b", q): return "ship"
        if re.search(r"\b(icao|aircraft|flight|airport|airline)\b", q): return "aircraft"
        if re.search(r"\b(company|corp|inc|ltd|llc|business|enterprise|startup|firm|organization|ngo)\b", q): return "company"
        if re.search(r"\b(facebook|instagram|twitter|x\.com|tiktok|youtube|telegram|social)\b", q): return "social_media"
        if len(q.split()) <= 3 and re.search(r"[A-Z][a-z]+ [A-Z][a-z]+", query): return "person"
        return "person"

    async def _run_direct_apis(self, query: str, target_type: str) -> list[Finding]:
        findings: list[Finding] = []
        relevant_apis = self._select_apis_for_target(target_type, query)
        if not relevant_apis: return findings
        connector = aiohttp.TCPConnector(limit=5, ssl=_SSL_CTX)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self._call_api(session, name, api_def, query) for name, api_def in relevant_apis.items()]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if isinstance(result, Finding): findings.append(result)
                elif isinstance(result, Exception): findings.append(self._make_finding(title="API Error", description=str(result), severity=FindingSeverity.LOW))
        return findings

    def _select_apis_for_target(self, target_type: str, query: str = "") -> dict:
        api_map = {
            "person": ["Wikidata", "Wikipedia", "ICIJ Offshore Leaks", "OpenSanctions"],
            "company": ["OpenCorporates", "Wikidata", "Wikipedia", "ICIJ Offshore Leaks", "OCCRP Aleph", "Wayback CDX", "crt.sh"],
            "domain": ["crt.sh", "urlscan.io", "Wayback CDX", "VirusTotal", "BuiltWith", "Wikipedia", "Wikidata"],
            "email": ["ICIJ Offshore Leaks", "OCCRP Aleph"],
            "organization": ["OpenCorporates", "Wikidata", "ICIJ Offshore Leaks", "OCCRP Aleph"],
            "username": ["WhatsMyName", "Instant Username Search"],
            "location": ["Wikidata", "Wikipedia"],
            "ship": [], "aircraft": ["OpenSky Network", "FlightAware"], "vehicle": [],
        }
        names = api_map.get(target_type, [])
        # Dedup: skip (api_name, query) already called this session
        names = [n for n in names if (n.lower(), query.lower().strip()) not in self._called_apis]
        result = {}
        for n in names:
            if n not in DIRECT_APIS: continue
            if self._fast_mode and n in self.SLOW_TOOLS: continue
            api_def = DIRECT_APIS[n]
            if not api_def.get("requires_key") or self._api_keys.get(n.lower().replace(" ", "_")):
                result[n] = api_def
        return result

    async def _call_api(self, session, name: str, api_def: dict, query: str, max_retries: int = 2) -> Finding:
        url = api_def["search_url"].format(query=quote(query, safe=""))
        headers = dict(api_def.get("headers", {}))
        self._called_apis.add((name.lower(), query.lower().strip()))
        if api_def.get("requires_key"):
            key = self._api_keys.get(name.lower().replace(" ", "_"), "")
            if not key: return self._make_finding(title=f"{name} (API Key Required)", description=f"Set API key for {name}.", evidence=[url], confidence=0.1, severity=FindingSeverity.INFO)
            headers = {k: v.format(api_key=key) for k, v in headers.items()}
        for attempt in range(max_retries + 1):
            try:
                method = api_def.get("method", "GET")
                if method == "POST":
                    body_template = api_def.get("body", {})
                    body = json.loads(json.dumps(body_template).replace("{query}", query)) if body_template else None
                    async with session.post(url, headers=headers, json=body, ssl=_SSL_CTX) as resp:
                        if resp.status in (200, 201):
                            data = await resp.json()
                            raw_items = self._extract_items(data, api_def.get("extract", "root"))
                            items = [json.dumps(i) if isinstance(i, dict) else str(i) for i in raw_items]
                            return self._make_finding(title=f"{name} Results", description=f"Found {len(items)} items", evidence=items[:5], confidence=0.7, source_tool=name)
                        elif resp.status == 429: await asyncio.sleep(2 ** attempt)
                        else: return self._make_finding(title=f"{name} Error", description=f"HTTP {resp.status}", evidence=[url], confidence=0.1, severity=FindingSeverity.LOW, source_tool=name)
                else:
                    async with session.get(url, headers=headers, ssl=_SSL_CTX) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            raw_items = self._extract_items(data, api_def.get("extract", "root"))
                            items = [json.dumps(i) if isinstance(i, dict) else str(i) for i in raw_items]
                            return self._make_finding(title=f"{name} Results", description=f"Found {len(items)} items", evidence=items[:5], confidence=0.7, source_tool=name)
                        elif resp.status == 429: await asyncio.sleep(2 ** attempt)
                        else: return self._make_finding(title=f"{name} Error", description=f"HTTP {resp.status}", evidence=[url], confidence=0.1, severity=FindingSeverity.LOW, source_tool=name)
            except Exception as e:
                if attempt == max_retries: return self._make_finding(title=f"{name} Failed", description=str(e)[:200], confidence=0.0, severity=FindingSeverity.LOW, source_tool=name)
                await asyncio.sleep(1)
        return self._make_finding(title=f"{name} Timeout", description="All retries exhausted", confidence=0.0, severity=FindingSeverity.LOW)

    @staticmethod
    def _extract_items(data, key: str) -> list:
        if isinstance(data, list): return data[:5]
        if isinstance(data, dict):
            if key == "root": return [data]
            parts = key.split(".")
            current = data
            for part in parts:
                if isinstance(current, dict): current = current.get(part, [])
                else: return []
            if isinstance(current, list): return current[:5]
            if isinstance(current, dict): return list(current.values())[:5]
        return []

    async def _run_automation(self, query: str, target_type: str, tools: list) -> list[Finding]:
        try:
            from watson.toolkit_automation import BellingcatAutomation, TARGET_API_MAP
        except ImportError as e:
            return [self._make_finding(title="Bellingcat unavailable", description=f"Automation module not found: {e}", confidence=0.0, severity=FindingSeverity.INFO, source_tool="bellingcat")]
        findings: list[Finding] = []
        auto_tool_names = TARGET_API_MAP.get(target_type, [])
        if not auto_tool_names: return findings
        automation = BellingcatAutomation(api_keys=self._api_keys)
        results = await automation.run_category(target_type, query, auto_tool_names)
        for tool_name, result_list in results.items():
            if not result_list: continue
            rich_findings = automation.results_to_findings(tool_name, result_list, query, target_type)
            for rf in rich_findings:
                metadata_kwargs = {k: v for k, v in rf.items() if k not in ("title", "description", "evidence", "confidence", "severity", "tool", "url")}
                findings.append(self._make_finding(title=rf.get("title", f"{tool_name}: Result")[:200], description=rf.get("description", "")[:500], evidence=rf.get("evidence", []) or [], confidence=float(rf.get("confidence", 0.5)), severity=FindingSeverity.INFO if rf.get("severity") not in [s.value for s in FindingSeverity] else FindingSeverity(rf.get("severity")), source_tool=tool_name, **metadata_kwargs))
        return findings

    async def _run_browser_scraping(self, query: str, target_type: str, tools: list) -> list[Finding]:
        return []

    def _build_url_references(self, query: str, target_type: str, tools: list) -> list[Finding]:
        return []

    def _make_finding(self, title: str = "", description: str = "", evidence: list = None,
                      confidence: float = 0.5, severity=None, source_tool: str = "", **kwargs) -> Finding:
        return Finding(
            id=f"bcat-{uuid.uuid4().hex[:12]}",
            title=title, description=(description or "")[:2000],
            evidence=evidence or [], confidence=confidence,
            severity=severity or FindingSeverity.INFO,
            source=FindingSource.BELLINGCAT if source_tool else FindingSource.OSINT,
            tool=source_tool,
            metadata={"bellingcat": True, **kwargs},
        )


# Register with the tool registry
bellingcat_tool = BellingcatToolkit()
registry.register(bellingcat_tool)
