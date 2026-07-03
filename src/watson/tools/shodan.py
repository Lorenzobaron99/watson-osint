"""Shodan tool — internet-wide infrastructure scanning for OSINT.

Discovers exposed services, industrial control systems, vulnerable
infrastructure associated with a target. Paid API required.
"""

from __future__ import annotations

import logging

from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSource

logger = logging.getLogger("watson.shodan")


class ShodanTool(OSINTTool):
    """Internet scanner — discovers exposed services, ICS, vulnerable infra."""

    category = FindingSource.OSINT
    name = "shodan"
    description = "Shodan internet scanner — exposed services, industrial control systems, vulnerable infrastructure"
    free_tier_available = False
    rate_limit_rps = 1.0

    SHODAN_HOST_SEARCH = "https://api.shodan.io/shodan/host/search"

    async def investigate(self, query: str, context: str = "") -> list[Finding]:
        """Search Shodan for exposed infrastructure related to the target."""
        findings: list[Finding] = []

        from watson.api_keys import get_key

        api_key = get_key("shodan")
        if not api_key:
            findings.append(self._make_finding(
                title="🔒 Shodan API key not configured",
                description=(
                    "Shodan provides internet-wide infrastructure scanning — exposed "
                    "services, industrial control systems, vulnerable ports. "
                    "Install your API key in Settings → API Vault to enable.\n\n"
                    "Get a key: https://account.shodan.io/"
                ),
                confidence=0.0,
                source_url="https://account.shodan.io/",
            ))
            return findings

        # Extract searchable terms
        search_term = self._extract_search_term(query)
        if not search_term:
            return findings

        try:
            import httpx

            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(
                    f"{self.SHODAN_HOST_SEARCH}?key={api_key}&query={search_term}&facets=org,os,port",
                )
                resp.raise_for_status()
                data = resp.json()

                matches = data.get("matches", [])
                total = data.get("total", 0)

                if matches:
                    entries = []
                    for m in matches[:8]:
                        ip = m.get("ip_str", "?")
                        port = m.get("port", "?")
                        org = m.get("org", "?")
                        os_name = m.get("os", "?") or "?"
                        hostnames = ", ".join(m.get("hostnames", [])[:2]) or "none"
                        product = m.get("product", m.get("_shodan", {}).get("module", "unknown"))

                        entries.append(
                            f"- **{ip}:{port}** — {product} ({org})\n"
                            f"  OS: {os_name} | Hostnames: {hostnames}"
                        )

                    findings.append(self._make_finding(
                        title=f"🌐 Shodan: {len(matches)} exposed services for '{search_term}' ({total} total)",
                        description="\n".join(entries[:6]),
                        confidence=0.85,
                        evidence=[f"https://www.shodan.io/search?query={search_term}"],
                        total_results=total,
                    ))
                else:
                    findings.append(self._make_finding(
                        title=f"🌐 Shodan: No exposed services found for '{search_term}'",
                        description="No internet-facing infrastructure matching the query was discovered.",
                        confidence=0.6,
                    ))

        except Exception as e:
            logger.warning("shodan_search_failed: %s", e)
            findings.append(self._make_finding(
                title=f"⚠ Shodan search failed: {str(e)[:100]}",
                description="API call failed. Check your key or try again later.",
                confidence=0.0,
            ))

        return findings

    @staticmethod
    def _extract_search_term(query: str) -> str:
        """Extract domain, IP, or org name for Shodan search."""
        import re

        # IP address
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', query)
        if ip_match:
            return ip_match.group(0)

        # Domain
        domain_match = re.search(r'(?:org|domain|hostname)\s*[:=]?\s*([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})', query, re.IGNORECASE)
        if domain_match:
            return domain_match.group(1)

        # Use first 3 words as org search
        words = query.split()[:3]
        return f'org:"{" ".join(words)}"'


# Register
shodan_tool = ShodanTool()
registry.register(shodan_tool)
