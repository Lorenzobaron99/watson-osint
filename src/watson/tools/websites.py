"""Websites & Domains tool — WHOIS, Wayback Machine, DNS, SSL certificates."""

from __future__ import annotations

import asyncio
from datetime import datetime

from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSource
from ..utils.http import get_client
from ..utils.helpers import extract_domain


class WebsitesTool(OSINTTool):
    """Investigate domains — WHOIS, Internet Archive, SSL certificates, DNS records."""

    category = FindingSource.WEBSITES
    name = "websites-domains"
    description = "WHOIS lookup, Wayback Machine history, SSL certificates (crt.sh), subdomain discovery"
    free_tier_available = True
    rate_limit_rps = 3.0

    WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"
    CRTSH_API = "https://crt.sh/"
    DNS_OVER_HTTPS = "https://dns.google/resolve"

    async def investigate(self, query: str, context: str = "") -> list[Finding]:
        findings: list[Finding] = []
        client = get_client(rate_limit=self.rate_limit_rps)

        domains = self._extract_domains(query)
        if not domains:
            return findings

        for domain in domains[:3]:  # Max 3 domains
            clean = extract_domain(domain)

            # Run all three checks in parallel (with short timeouts for slow APIs)
            wayback, crt, dns = await asyncio.gather(
                self._check_wayback(client, clean),
                self._check_crtsh(client, clean),
                self._check_dns(client, clean),
                return_exceptions=True,
            )

            if isinstance(wayback, Finding):
                findings.append(wayback)
            if isinstance(crt, Finding):
                findings.append(crt)
            if isinstance(dns, Finding):
                findings.append(dns)

        return findings

    async def _check_wayback(self, client, domain: str) -> Finding | None:
        """Check Internet Archive Wayback Machine for domain history."""
        try:
            params = {
                "url": f"*.{domain}/*",
                "output": "json",
                "limit": 5,
                "fl": "timestamp,original,statuscode",
                "collapse": "digest",
            }
            data = await client.get_json(self.WAYBACK_CDX, params=params)

            if isinstance(data, list) and data:
                # Get first and most recent snapshots
                first = data[-1] if len(data) > 0 else data[0]
                latest = data[0]

                first_date = datetime.strptime(first[0][:8], "%Y%m%d").strftime("%b %d, %Y")
                latest_date = datetime.strptime(latest[0][:8], "%Y%m%d").strftime("%b %d, %Y")

                return self._make_finding(
                    title=f"📚 Wayback Machine: {domain}",
                    description=(
                        f"First archived: {first_date}. "
                        f"Latest snapshot: {latest_date}. "
                        f"Total unique snapshots in recent window: {len(data)}."
                    ),
                    evidence=[
                        f"https://web.archive.org/web/*/{domain}",
                        f"https://web.archive.org/web/{latest[0]}/{latest[1]}",
                    ],
                    confidence=0.95,
                    domain=domain,
                    first_snapshot=first[0],
                    latest_snapshot=latest[0],
                )
        except Exception:
            pass
        return None

    async def _check_crtsh(self, client, domain: str) -> Finding | None:
        """Check SSL certificate transparency logs via crt.sh."""
        try:
            url = f"{self.CRTSH_API}?q=%.{domain}&output=json"
            data = await client.get_json(url)

            if isinstance(data, list) and data:
                # Extract unique subdomains
                subdomains: set[str] = set()
                for entry in data[:50]:
                    names = entry.get("name_value", "").split("\n")
                    for name in names:
                        name = name.strip().lstrip("*.")
                        if name and domain in name:
                            subdomains.add(name)

                subdomain_list = sorted(subdomains)[:10]

                return self._make_finding(
                    title=f"🔒 SSL certs: {len(subdomains)} subdomains found for {domain}",
                    description=(
                        f"Discovered {len(subdomains)} unique names via certificate transparency. "
                        f"First 10:\n" + "\n".join(f"- `{s}`" for s in subdomain_list)
                    ),
                    evidence=[f"https://crt.sh/?q=%.{domain}"],
                    confidence=0.9,
                    domain=domain,
                    subdomain_count=len(subdomains),
                )
        except Exception:
            pass
        return None

    async def _check_dns(self, client, domain: str) -> Finding | None:
        """Check DNS records via Google DNS-over-HTTPS."""
        try:
            async def _query(rt: str) -> str | None:
                try:
                    data = await client.get_json(
                        self.DNS_OVER_HTTPS, params={"name": domain, "type": rt}
                    )
                    answers = data.get("Answer", [])
                    if answers:
                        values = [a["data"] for a in answers[:3]]
                        return f"{rt}: {', '.join(values)}"
                except Exception:
                    pass
                return None

            results = await asyncio.gather(
                *[_query(rt) for rt in ["A", "AAAA", "MX", "NS", "TXT"]]
            )
            records_found = [r for r in results if r]

            if records_found:
                return self._make_finding(
                    title=f"🌐 DNS records for {domain}",
                    description="\n".join(f"- {r}" for r in records_found),
                    confidence=0.9,
                    domain=domain,
                )
        except Exception:
            pass
        return None

    def _extract_domains(self, text: str) -> list[str]:
        """Extract domain names from text."""
        import re

        pattern = r"(?:https?://)?(?:www\.)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)"
        matches = re.findall(pattern, text)
        return list(dict.fromkeys(matches))


# Register
websites_tool = WebsitesTool()
registry.register(websites_tool)
