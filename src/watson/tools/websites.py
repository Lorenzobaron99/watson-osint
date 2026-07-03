"""Websites & Domains tool — WHOIS, Wayback Machine, DNS, SSL certificates."""

from __future__ import annotations

import asyncio
from datetime import datetime

from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSeverity, FindingSource
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

        domains = self._extract_domains(query)
        if not domains:
            return findings

        import httpx
        for domain in domains[:3]:
            clean = extract_domain(domain)

            async def _wayback():
                try:
                    params = {"url": f"*.{clean}/*", "output": "json", "limit": 5, "fl": "timestamp,original"}
                    async with httpx.AsyncClient(timeout=10) as c:
                        resp = await c.get(self.WAYBACK_CDX, params=params)
                        if resp.status_code == 200:
                            snapshots = resp.json()
                            if isinstance(snapshots, list) and snapshots:
                                first = snapshots[0][0] if snapshots[0] else "unknown"
                                last = snapshots[-1][0] if snapshots[-1] else "unknown"
                                return self._make_finding(
                                    title=f"📚 Wayback Machine: {clean}",
                                    description=f"First archived: {first[:4]}-{first[4:6]}-{first[6:8]}. "
                                    f"Latest snapshot: {last[:4]}-{last[4:6]}-{last[6:8]}. "
                                    f"Total unique snapshots in recent window: {len(snapshots)}.",
                                    evidence=[f"https://web.archive.org/web/*/{clean}"],
                                    confidence=0.95,
                                    domain=clean,
                                )
                except Exception:
                    pass
                return None

            async def _crtsh():
                try:
                    url = f"{self.CRTSH_API}?q=%25.{clean}&output=json"
                    async with httpx.AsyncClient(timeout=15) as c:
                        resp = await c.get(url, headers={"User-Agent": "WatsonOSINT/0.3"})
                        if resp.status_code == 200:
                            certs = resp.json()
                            if isinstance(certs, list) and certs:
                                subdomains = set()
                                for cert in certs[:50]:
                                    names = cert.get("name_value", "")
                                    for n in names.split("\\n"):
                                        n = n.strip()
                                        if n and n != clean and not n.startswith("*."):
                                            subdomains.add(n)
                                return self._make_finding(
                                    title=f"🔐 SSL certificates: {clean}",
                                    description=f"{len(certs)} certificates found. "
                                    f"{len(subdomains)} unique subdomains: {', '.join(sorted(list(subdomains))[:10])}",
                                    evidence=[f"https://crt.sh/?q=%.{clean}"],
                                    confidence=0.85,
                                    domain=clean,
                                )
                        elif resp.status_code >= 400:
                            return self._make_finding(
                                title=f"⚠️ crt.sh lookup failed for {clean}",
                                description=f"SSL certificate lookup error: HTTP {resp.status_code}. "
                                f"Try manually: https://crt.sh/?q=%.{clean}",
                                evidence=[f"https://crt.sh/?q=%.{clean}"],
                                confidence=0.1,
                                domain=clean,
                            )
                except Exception:
                    pass
                return None

            async def _dns():
                try:
                    async with httpx.AsyncClient(timeout=10) as c:
                        a_resp = await c.get(f"{self.DNS_OVER_HTTPS}?name={clean}&type=A")
                        mx_resp = await c.get(f"{self.DNS_OVER_HTTPS}?name={clean}&type=MX")
                        ns_resp = await c.get(f"{self.DNS_OVER_HTTPS}?name={clean}&type=NS")
                        txt_resp = await c.get(f"{self.DNS_OVER_HTTPS}?name={clean}&type=TXT")
                        a_data = a_resp.json() if a_resp.status_code == 200 else {}
                        mx_data = mx_resp.json() if mx_resp.status_code == 200 else {}
                        ns_data = ns_resp.json() if ns_resp.status_code == 200 else {}
                        txt_data = txt_resp.json() if txt_resp.status_code == 200 else {}
                        a_records = [a.get("data", "") for a in a_data.get("Answer", [])]
                        mx_records = [m.get("data", "") for m in mx_data.get("Answer", [])]
                        ns_records = [n.get("data", "") for n in ns_data.get("Answer", [])]
                        txt_records = [t.get("data", "") for t in txt_data.get("Answer", [])]
                        if a_records or mx_records:
                            return self._make_finding(
                                title=f"🌐 DNS records for {clean}",
                                description=f"- A: {', '.join(a_records[:3])} "
                                f"- MX: {', '.join(mx_records[:3])} "
                                f"- NS: {', '.join(ns_records[:3])} "
                                f"- TXT: {', '.join(txt_records[:3])}",
                                evidence=[f"https://dns.google/resolve?name={clean}"],
                                confidence=0.9,
                                domain=clean,
                            )
                except Exception:
                    pass
                return None

            wayback, crt, dns = await asyncio.gather(
                _wayback(), _crtsh(), _dns(),
            )
            if wayback: findings.append(wayback)
            if crt: findings.append(crt)
            if dns: findings.append(dns)

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

            if isinstance(data, list) and len(data) > 1:
                # Skip header row (first element is column names)
                rows = data[1:] if isinstance(data[0], list) and data[0][0] == "timestamp" else data
                if not rows:
                    return None
                first = rows[-1]
                latest = rows[0]

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
        except Exception as e:
            return self._make_finding(
                title=f"⚠️ Wayback Machine unavailable for {domain}",
                description=f"Could not retrieve archive data: {str(e)[:200]}",
                confidence=0.0,
                severity=FindingSeverity.LOW,
            )
        return None

    async def _check_crtsh(self, client, domain: str) -> Finding | None:
        """Check SSL certificate transparency logs via crt.sh."""
        try:
            url = f"{self.CRTSH_API}?q=%25.{domain}&output=json"
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
        except Exception as e:
            return self._make_finding(
                title=f"⚠️ crt.sh lookup failed for {domain}",
                description=f"SSL certificate lookup error: {str(e)[:200]}. Try manually: https://crt.sh/?q=%.{domain}",
                evidence=[f"https://crt.sh/?q=%.{domain}"],
                confidence=0.1,
                severity=FindingSeverity.LOW,
            )
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
            else:
                return self._make_finding(
                    title=f"⚠️ No DNS records found for {domain}",
                    description="DNS-over-HTTPS returned no records. Domain may not resolve or is parked.",
                    confidence=0.3,
                    severity=FindingSeverity.LOW,
                )
        except Exception as e:
            return self._make_finding(
                title=f"⚠️ DNS lookup failed for {domain}",
                description=f"DNS-over-HTTPS error: {str(e)[:200]}",
                confidence=0.0,
                severity=FindingSeverity.LOW,
            )

    def _extract_domains(self, text: str) -> list[str]:
        """Extract domain names from text. Falls back to deriving domain from single-word queries."""
        import re

        pattern = r"(?:https?://)?(?:www\.)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)"
        matches = re.findall(pattern, text)
        domains = list(dict.fromkeys(matches))

        # If no domain found and query looks like a company/product name, derive it
        if not domains:
            # Check for single capitalized word or CamelCase (e.g. "OpenAI", "DeepSeek")
            word_match = re.search(r'\b([A-Za-z][A-Za-z0-9]{2,}(?:\.[a-z]{2,})?)\b', text)
            if word_match:
                word = word_match.group(1).lower()
                if '.' not in word:
                    domains = [f"{word}.com", f"{word}.org", f"{word}.io"]
                else:
                    domains = [word]

        return domains


# Register
websites_tool = WebsitesTool()
registry.register(websites_tool)
