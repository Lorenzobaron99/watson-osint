"""Wikidata SPARQL tool — corporate ownership, sanctions, key people via structured knowledge graph.

Wikidata is the structured-data backbone of Wikipedia. Every company, person,
and entity has a unique Q-ID with typed properties — we can query ownership
chains, sanctions designations, board members, and financial data without
ever hitting a paywall or Cloudflare block.

Free tier: always free. No API key needed. SPARQL endpoint is public.
Rate limit: ~5 req/s (generous — be respectful).
"""

from __future__ import annotations

import asyncio
from typing import Optional

import httpx

from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSeverity, FindingSource

# ── Shared httpx client (avoid BaseHTTPClient deadlock in parallel) ─

_client: Optional[httpx.AsyncClient] = None
_client_lock = asyncio.Lock()
_semaphore = asyncio.Semaphore(3)  # Max 3 concurrent SPARQL queries


async def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        async with _client_lock:
            if _client is None:
                _client = httpx.AsyncClient(
                    timeout=httpx.Timeout(30.0, connect=10.0),
                    headers={
                        "User-Agent": "WatsonOSINT/0.3 (https://github.com/nousresearch/watson-osint)",
                        "Accept": "application/json",
                    },
                )
    return _client


# ── SPARQL query templates ────────────────────────────────────────

COMPANY_SEARCH = """
SELECT ?company ?companyLabel ?countryLabel ?industryLabel ?website ?revenue ?employees
WHERE {{
  ?company (rdfs:label|skos:altLabel) "{name}"@en.
  ?company wdt:P31/wdt:P279* wd:Q4830453.
  OPTIONAL {{ ?company wdt:P17 ?country. }}
  OPTIONAL {{ ?company wdt:P452 ?industry. }}
  OPTIONAL {{ ?company wdt:P856 ?website. }}
  OPTIONAL {{ ?company wdt:P2139 ?revenue. }}
  OPTIONAL {{ ?company wdt:P1128 ?employees. }}
  SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
}}
LIMIT 5
"""

OWNERSHIP_QUERY = """
SELECT ?owner ?ownerLabel ?ownerTypeLabel ?ownershipPercent
WHERE {{
  ?company (rdfs:label|skos:altLabel) "{name}"@en.
  ?company wdt:P127 ?owner.
  OPTIONAL {{ ?owner wdt:P31 ?ownerType. }}
  OPTIONAL {{ ?company p:P127 [pq:P1103 ?ownershipPercent]. }}
  SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
}}
LIMIT 5
"""

SUBSIDIARIES_QUERY = """
SELECT ?sub ?subLabel ?subCountryLabel
WHERE {{
  ?company (rdfs:label|skos:altLabel) "{name}"@en.
  ?sub wdt:P749 ?company.
  OPTIONAL {{ ?sub wdt:P17 ?subCountry. }}
  SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
}}
LIMIT 20
"""

KEY_PEOPLE_QUERY = """
SELECT ?person ?personLabel ?roleLabel
WHERE {{
  ?company (rdfs:label|skos:altLabel) "{name}"@en.
  {{ ?company wdt:P169 ?person. BIND("CEO" AS ?roleLabel) }}
  UNION
  {{ ?company wdt:P112 ?person. BIND("Founder" AS ?roleLabel) }}
  UNION
  {{ ?company wdt:P3320 ?person. BIND("Board member" AS ?roleLabel) }}
  SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
}}
LIMIT 10
"""

SANCTIONS_QUERY = """
SELECT ?entity ?entityLabel ?sanctionType ?sanctionListLabel
WHERE {{
  VALUES ?entityName {{ "{name}" }}
  ?entity (rdfs:label|skos:altLabel) ?entityName.
  FILTER(LANG(?entityName) = "en")
  ?entity wdt:P31 ?sanctionType.
  FILTER(?sanctionType IN (wd:Q85891580, wd:Q110761879, wd:Q28135121))
  OPTIONAL {{ ?entity wdt:P793 ?sanctionList. }}
  SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
}}
LIMIT 5
"""

PERSON_SEARCH = """
SELECT ?person ?personLabel ?description ?birthDate ?countryLabel
WHERE {{
  ?person (rdfs:label|skos:altLabel) "{name}"@en.
  ?person wdt:P31 wd:Q5.
  OPTIONAL {{ ?person schema:description ?description. FILTER(LANG(?description) = "en") }}
  OPTIONAL {{ ?person wdt:P569 ?birthDate. }}
  OPTIONAL {{ ?person wdt:P27 ?country. }}
  SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
}}
LIMIT 5
"""


class WikidataTool(OSINTTool):
    """Query Wikidata for structured corporate intelligence, ownership, and sanctions."""

    category = FindingSource.CORPORATE
    name = "wikidata"
    description = "Wikidata SPARQL — corporate ownership, subsidiaries, key people, sanctions, structured entity data"
    free_tier_available = True
    rate_limit_rps = 3.0

    SPARQL_ENDPOINT = "https://query.wikidata.org/sparql"

    async def investigate(self, query: str, context: str = "") -> list[Finding]:
        findings: list[Finding] = []

        name = self._extract_entity(query)
        if not name:
            return findings

        # Run all SPARQL queries in parallel for speed
        import asyncio

        tasks = [
            self._run_query("company_search", COMPANY_SEARCH.format(name=self._escape_sparql(name)), name),
            self._run_query("ownership", OWNERSHIP_QUERY.format(name=self._escape_sparql(name)), name),
            self._run_query("subsidiaries", SUBSIDIARIES_QUERY.format(name=self._escape_sparql(name)), name),
            self._run_query("key_people", KEY_PEOPLE_QUERY.format(name=self._escape_sparql(name)), name),
            self._run_query("sanctions", SANCTIONS_QUERY.format(name=self._escape_sparql(name)), name),
        ]

        results = await asyncio.gather(*tasks)
        for f in results:
            if f:
                findings.append(f)

        return findings

    async def _run_query(self, label: str, sparql: str, target: str) -> Optional[Finding]:
        """Execute a SPARQL query and format results."""
        max_retries = 2
        for attempt in range(max_retries + 1):
            raw = None
            try:
                async with _semaphore:
                    client = await _get_client()
                    params = {"format": "json", "query": sparql}
                    r = await client.get(self.SPARQL_ENDPOINT, params=params)
                    if r.status_code == 429:
                        retry_after = int(r.headers.get("Retry-After", "5"))
                        if attempt < max_retries:
                            await asyncio.sleep(min(retry_after, 3))
                            continue
                        return None
                    r.raise_for_status()
                    raw = r.json()
            except Exception:
                if attempt < max_retries:
                    await asyncio.sleep(1.5)
                    continue
                return None

            if not isinstance(raw, dict):
                continue
            data: dict = raw

            bindings = data.get("results", {}).get("bindings", [])
            if not bindings:
                return None

            if label == "company_search":
                return self._format_company(bindings, target)
            elif label == "ownership":
                return self._format_ownership(bindings, target)
            elif label == "subsidiaries":
                return self._format_subsidiaries(bindings, target)
            elif label == "key_people":
                return self._format_key_people(bindings, target)
            elif label == "sanctions":
                return self._format_sanctions(bindings, target)

        return None

    # ── Formatters ────────────────────────────────────────────

    def _format_company(self, bindings: list[dict], target: str) -> Optional[Finding]:
        lines = []
        evidence_urls = []
        for b in bindings[:5]:
            label = self._val(b, "companyLabel") or self._uri_id(b, "company")
            country = self._val(b, "countryLabel")
            industry = self._val(b, "industryLabel")
            website = self._val(b, "website")
            revenue = self._val(b, "revenue")
            company_uri = b.get("company", {}).get("value", "")
            qid = company_uri.split("/")[-1] if company_uri else ""

            parts = [f"- **{label}**"]
            if country:
                parts.append(f" ({country})")
            if industry:
                parts.append(f" — {industry}")
            if revenue:
                parts.append(f" — Revenue: {revenue}")
            lines.append(" ".join(parts))

            if website:
                lines.append(f"  🌐 {website}")
                evidence_urls.append(website)
            if qid:
                lines.append(f"  📊 [Wikidata](https://www.wikidata.org/wiki/{qid})")
                evidence_urls.append(f"https://www.wikidata.org/wiki/{qid}")

        if not lines:
            return None

        return self._make_finding(
            title=f"📊 Wikidata: Company data for '{target}'",
            description="\n".join(lines),
            evidence=evidence_urls[:5],
            confidence=0.90,
            query=target,
            result_count=len(bindings),
        )

    def _format_ownership(self, bindings: list[dict], target: str) -> Optional[Finding]:
        lines = []
        evidence_urls = []
        for b in bindings[:5]:
            owner = self._val(b, "ownerLabel") or self._uri_id(b, "owner")
            owner_type = self._val(b, "ownerTypeLabel")
            pct = self._val(b, "ownershipPercent")
            owner_uri = b.get("owner", {}).get("value", "")
            owner_qid = owner_uri.split("/")[-1] if owner_uri else ""

            line = f"- **{owner}**"
            if owner_type:
                line += f" [{owner_type}]"
            if pct:
                line += f" — {pct}"
            lines.append(line)
            if owner_qid:
                evidence_urls.append(f"https://www.wikidata.org/wiki/{owner_qid}")

        if not lines:
            return None

        return self._make_finding(
            title=f"🏛️ Wikidata: Ownership of '{target}'",
            description="\n".join(lines),
            evidence=evidence_urls[:5],
            confidence=0.85,
            query=target,
            result_count=len(bindings),
        )

    def _format_subsidiaries(self, bindings: list[dict], target: str) -> Optional[Finding]:
        lines = []
        evidence_urls = []
        for b in bindings[:20]:
            sub = self._val(b, "subLabel") or self._uri_id(b, "sub")
            country = self._val(b, "subCountryLabel")
            sub_uri = b.get("sub", {}).get("value", "")
            sub_qid = sub_uri.split("/")[-1] if sub_uri else ""

            line = f"- **{sub}**"
            if country:
                line += f" ({country})"
            lines.append(line)
            if sub_qid:
                evidence_urls.append(f"https://www.wikidata.org/wiki/{sub_qid}")

        if not lines:
            return None

        return self._make_finding(
            title=f"🏢 Wikidata: {len(bindings)} subsidiaries of '{target}'",
            description="\n".join(lines[:20]),
            evidence=evidence_urls[:5],
            confidence=0.85,
            query=target,
            result_count=len(bindings),
        )

    def _format_key_people(self, bindings: list[dict], target: str) -> Optional[Finding]:
        lines = []
        evidence_urls = []
        for b in bindings[:10]:
            person = self._val(b, "personLabel") or self._uri_id(b, "person")
            role = self._val(b, "roleLabel") or "Affiliated"
            person_uri = b.get("person", {}).get("value", "")
            person_qid = person_uri.split("/")[-1] if person_uri else ""

            lines.append(f"- **{person}** — *{role}*")
            if person_qid:
                evidence_urls.append(f"https://www.wikidata.org/wiki/{person_qid}")

        if not lines:
            return None

        return self._make_finding(
            title=f"👥 Wikidata: Key people — {target}",
            description="\n".join(lines[:10]),
            evidence=evidence_urls[:5],
            confidence=0.90,
            query=target,
            result_count=len(bindings),
        )

    def _format_sanctions(self, bindings: list[dict], target: str) -> Optional[Finding]:
        lines = []
        evidence_urls = []
        for b in bindings[:5]:
            entity = self._val(b, "entityLabel") or self._uri_id(b, "entity")
            list_name = self._val(b, "sanctionListLabel")
            entity_uri = b.get("entity", {}).get("value", "")
            entity_qid = entity_uri.split("/")[-1] if entity_uri else ""

            line = f"- 🚨 **{entity}**"
            if list_name:
                line += f" — on: {list_name}"
            lines.append(line)
            if entity_qid:
                evidence_urls.append(f"https://www.wikidata.org/wiki/{entity_qid}")

        if not lines:
            return None

        return self._make_finding(
            title=f"🚨 Wikidata: Sanctions match — '{target}'",
            description="\n".join(lines),
            evidence=evidence_urls[:5],
            confidence=0.95,
            query=target,
            result_count=len(bindings),
            sanction_match=True,
        )

    # ── Helpers ───────────────────────────────────────────────

    def _escape_sparql(self, s: str) -> str:
        """Escape a string for SPARQL literal (basic — handles quotes)."""
        return s.replace("\\", "\\\\").replace('"', '\\"')

    def _val(self, binding: dict, key: str) -> Optional[str]:
        """Extract a string value from a SPARQL binding."""
        v = binding.get(key, {})
        if isinstance(v, dict):
            return v.get("value")
        return None

    def _uri_id(self, binding: dict, key: str) -> Optional[str]:
        """Extract the Q-ID or last path segment from a URI."""
        v = binding.get(key, {})
        if isinstance(v, dict):
            uri = v.get("value", "")
            return uri.rsplit("/", 1)[-1].rsplit("#", 1)[-1] if uri else None
        return None

    def _extract_entity(self, query: str) -> Optional[str]:
        """Extract a company or person name from the query."""
        import re
        # Grab the first capitalized phrase (company/person name)
        name = query.strip().split("\n")[0].strip()
        # Remove common prefixes
        name = re.sub(r'^(investigate|research|look into|check|find|who is|what is)\s+', '', name, flags=re.IGNORECASE).strip()
        if len(name) < 2:
            return None
        return name


# ── Register ──────────────────────────────────────────────────────

registry.register(WikidataTool())
