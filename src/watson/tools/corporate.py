"""Corporate & Finance tool — company records, sanctions lists, SEC filings."""

from __future__ import annotations

import urllib.parse

from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSource
from ..utils.http import get_client


class CorporateTool(OSINTTool):
    """Investigate companies — OpenCorporates, OpenSanctions, SEC EDGAR."""

    category = FindingSource.CORPORATE
    name = "corporate-finance"
    description = "Company registry lookup (OpenCorporates), sanctions check (OpenSanctions), SEC EDGAR"
    free_tier_available = True
    rate_limit_rps = 0.5

    OPENCORPORATES_API = "https://api.opencorporates.com/v0.4/companies/search"
    OPENSANCTIONS_API = "https://api.opensanctions.org/search/default"
    SEC_EDGAR_SEARCH = "https://efts.sec.gov/LATEST/search-index?q={query}&pageSize=5"

    async def investigate(self, query: str, context: str = "") -> list[Finding]:
        findings: list[Finding] = []

        company = self._extract_company_name(query)
        if not company:
            # Also check for person names (sanctions)
            person = self._extract_person_name(query)
            if person:
                findings.extend(await self._check_sanctions(person))
                return findings
            return findings

        client = get_client(rate_limit=self.rate_limit_rps)

        # 1. OpenCorporates search
        oc_result = await self._search_opencorporates(client, company)
        if oc_result:
            findings.append(oc_result)

        # 2. Sanctions check
        sanctions = await self._check_sanctions(company)
        findings.extend(sanctions)

        # 3. SEC EDGAR (for US companies)
        edgar = await self._search_edgar(company)
        if edgar:
            findings.append(edgar)

        return findings

    async def _search_opencorporates(self, client, company: str) -> Finding | None:
        """Search OpenCorporates for company records."""
        try:
            params = {"q": company, "per_page": 5}
            data = await client.get_json(self.OPENCORPORATES_API, params=params)

            if not isinstance(data, dict):
                return None
            results = data.get("results", {}).get("companies", [])
            if results:
                companies = []
                for r in results[:5]:
                    c = r.get("company", {})
                    name = c.get("name", "Unknown")
                    jurisdiction = c.get("jurisdiction_code", "??")
                    company_number = c.get("company_number", "")
                    companies.append(f"- **{name}** ({jurisdiction}, #{company_number})")

                return self._make_finding(
                    title=f"🏢 Company records: {len(results)} matches for '{company}'",
                    description="\n".join(companies),
                    evidence=[f"https://opencorporates.com/companies?q={urllib.parse.quote(company)}"],
                    confidence=0.85,
                    query=company,
                    result_count=len(results),
                )
        except Exception:
            pass
        return None

    async def _check_sanctions(self, name: str) -> list[Finding]:
        """Check OpenSanctions for sanctions/restrictions."""
        findings: list[Finding] = []
        client = get_client(rate_limit=self.rate_limit_rps)

        try:
            params = {"q": name, "limit": 5}
            data = await client.get_json(self.OPENSANCTIONS_API, params=params)

            results = data.get("results", [])
            if results:
                sanctioned = []
                for r in results[:5]:
                    r_name = r.get("caption", r.get("name", "Unknown"))
                    schema = r.get("schema", "")
                    countries = ", ".join(r.get("countries", []))
                    sanctioned.append(f"- **{r_name}** [{schema}] ({countries})")

                findings.append(
                    self._make_finding(
                        title=f"🚨 Sanctions check: {len(results)} matches for '{name}'",
                        description="\n".join(sanctioned),
                        evidence=[f"https://opensanctions.org/search/?q={urllib.parse.quote(name)}"],
                        confidence=0.9,
                        query=name,
                        result_count=len(results),
                    )
                )
            else:
                findings.append(
                    self._make_finding(
                        title=f"✅ No sanctions found: '{name}'",
                        description="No matches in OpenSanctions database.",
                        confidence=0.6,
                        query=name,
                    )
                )
        except Exception:
            pass

        return findings

    async def _search_edgar(self, company: str) -> Finding | None:
        """Search SEC EDGAR for US company filings."""
        try:
            return self._make_finding(
                title=f"📊 SEC EDGAR search ready: {company}",
                description="Click to search SEC filings for this company.",
                evidence=[
                    f"https://www.sec.gov/cgi-bin/browse-edgar?company={urllib.parse.quote(company)}"
                ],
                confidence=0.7,
                query=company,
            )
        except Exception:
            pass
        return None

    def _extract_company_name(self, text: str) -> str | None:
        """Extract a company name from query text."""
        import re

        patterns = [
            r"(?:company|corporation|business|firm|entity)\s+(?:named|called|is\s+)?['\"]?([A-Z][A-Za-z0-9\s&.,]+?)(?:\s+(?:and|or|\.|$|,))",
            r"(?:investigate|research|look\s+up|check|audit)\s+(?:the\s+)?(?:company\s+)?['\"]?([A-Z][A-Za-z0-9\s&.,]+?)(?:\s+(?:and|or|\.|$))",
            r"(?:who owns|who controls|ownership of)\s+['\"]?([A-Z][A-Za-z0-9\s&.,]+?)(?:\s+(?:and|or|\?|\.|$))",
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                name = match.group(1).strip().rstrip(".,")
                # Filter out common non-company words
                if len(name.split()) >= 1 and name.lower() not in (
                    "this", "that", "the", "a", "an"
                ):
                    return name

        return None

    def _extract_person_name(self, text: str) -> str | None:
        """Extract a person's name from query text."""
        import re

        patterns = [
            r"(?:person|individual|someone|called|named)\s+['\"]?([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})['\"]?",
            r"(?:who is|research|look\s+up|check|investigate)\s+['\"]?([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})['\"]?",
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()

        return None


# Register
corporate_tool = CorporateTool()
registry.register(corporate_tool)
