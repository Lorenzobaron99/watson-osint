"""Scraper engine — extracts real data from Wikipedia, OpenSanctions, and OSINT sources.

When APIs fail (rate-limited, blocked), this falls back to HTML scraping with
browser-grade headers. Uses plain http.client for maximum reliability.
"""

from __future__ import annotations

import http.client
import json
import re
import ssl
import urllib.parse
from html.parser import HTMLParser
from typing import Optional

from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSource


class TextExtractor(HTMLParser):
    """Extracts clean text from HTML, stripping tags and scripts."""

    def __init__(self):
        super().__init__()
        self.text_parts: list[str] = []
        self.skip = False
        self._skip_tags = {"script", "style", "noscript", "svg", "math"}

    def handle_starttag(self, tag, attrs):
        if tag in self._skip_tags:
            self.skip = True

    def handle_endtag(self, tag):
        if tag in self._skip_tags:
            self.skip = False
        if tag in ("p", "br", "li", "tr", "h1", "h2", "h3", "h4", "td", "th", "div"):
            self.text_parts.append("\n")

    def handle_data(self, data):
        if not self.skip:
            text = data.strip()
            if text:
                self.text_parts.append(text + " ")

    def get_text(self) -> str:
        return "".join(self.text_parts)


def _http_get(url: str, timeout: int = 8) -> Optional[str]:
    """Fetch a URL with browser-grade headers. Returns HTML text or None."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    path = parsed.path + ("?" + parsed.query if parsed.query else "")

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
    }

    try:
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, timeout=timeout, context=ctx)
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()

        if resp.status in (301, 302):
            location = resp.getheader("Location", "")
            conn.close()
            if location:
                return _http_get(location, timeout)

        if resp.status != 200:
            conn.close()
            return None

        # Handle gzip
        body = resp.read()
        conn.close()

        if resp.getheader("Content-Encoding") == "gzip":
            import gzip

            body = gzip.decompress(body)

        return body.decode("utf-8", errors="replace")
    except Exception:
        return None


class ScraperTool(OSINTTool):
    """Autonomous web scraper — extracts structured data from OSINT sources."""

    category = FindingSource.PEOPLE
    name = "scraper"
    description = "Autonomous web scraper — extracts real data from Wikipedia, OpenSanctions, and OSINT sources"
    free_tier_available = True
    rate_limit_rps = 1.0

    async def investigate(self, query: str, context: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # Extract entity name
        name = self._extract_entity_name(query)
        if not name:
            return findings

        # 1. Wikipedia
        wiki_findings = await self._scrape_wikipedia(name)
        findings.extend(wiki_findings)

        # 2. OpenSanctions
        sanctions_findings = await self._scrape_opensanctions(name)
        findings.extend(sanctions_findings)

        return findings

    async def _scrape_wikipedia(self, name: str) -> list[Finding]:
        """Scrape Wikipedia for person/entity data."""
        findings: list[Finding] = []

        # Try exact name first, then just first+last name
        names_to_try = [name]
        parts = name.split()
        if len(parts) >= 2:
            # Try first+last name
            names_to_try.append(f"{parts[0]}_{parts[-1]}")
            # Also try just the last name (common for criminals, celebrities)
            names_to_try.append(parts[-1])

        html = None
        scraped_url = ""
        for try_name in names_to_try:
            encoded = urllib.parse.quote(try_name.replace(" ", "_"))
            scraped_url = f"https://en.wikipedia.org/wiki/{encoded}"
            html = _http_get(scraped_url)

            if html and "Wikipedia does not have an article" not in html:
                break
            html = None

        if not html:
            # Search fallback
            search_url = f"https://en.wikipedia.org/wiki/Special:Search?search={urllib.parse.quote(name)}"
            html = _http_get(search_url)

        if not html:
            return findings

        # Extract infobox data
        infobox = self._parse_infobox(html)
        lead = self._extract_lead_paragraph(html)

        if infobox or lead:
            desc_parts = []

            if lead:
                desc_parts.append(lead[:300])

            if infobox:
                desc_parts.append("")
                for key, value in list(infobox.items())[:10]:
                    desc_parts.append(f"**{key}:** {value[:120]}")

            evidence = [scraped_url]
            confidence = 0.9 if infobox else 0.6

            findings.append(
                self._make_finding(
                    title=f"📖 Wikipedia: {name}",
                    description="\n".join(desc_parts),
                    evidence=evidence,
                    confidence=confidence,
                    source_url=scraped_url,
                    infobox=infobox,
                )
            )

        return findings

    def _parse_infobox(self, html: str) -> dict[str, str]:
        """Parse Wikipedia infobox into key-value pairs."""
        result: dict[str, str] = {}

        # Find infobox table
        infobox_match = re.search(
            r'<table[^>]*class="[^"]*infobox[^"]*"[^>]*>(.*?)</table>',
            html, re.DOTALL | re.IGNORECASE
        )
        if not infobox_match:
            return result

        infobox_html = infobox_match.group(1)

        # Extract rows
        rows = re.findall(r'<tr[^>]*>(.*?)</tr>', infobox_html, re.DOTALL | re.IGNORECASE)

        for row in rows:
            # th = key, td = value
            th_match = re.search(r'<th[^>]*>(.*?)</th>', row, re.DOTALL | re.IGNORECASE)
            td_match = re.search(r'<td[^>]*>(.*?)</td>', row, re.DOTALL | re.IGNORECASE)

            if th_match and td_match:
                key = self._strip_html(th_match.group(1)).strip()
                value = self._strip_html(td_match.group(1)).strip()
                if key and value and len(key) < 50:
                    result[key] = value

        return result

    def _extract_lead_paragraph(self, html: str) -> str:
        """Extract the first substantive paragraph from Wikipedia."""
        # Find all paragraph tags
        for p_match in re.finditer(r'<p[^>]*>(.*?)</p>', html, re.DOTALL | re.IGNORECASE):
            text = self._strip_html(p_match.group(1)).strip()
            # Skip empty, navigation boilerplate, or coordinate paragraphs
            if len(text) < 80:
                continue
            if "From Wikipedia" in text or "may refer to:" in text:
                continue
            return text[:500]

        return ""

    async def _scrape_opensanctions(self, name: str) -> list[Finding]:
        """Scrape OpenSanctions search results."""
        findings: list[Finding] = []

        encoded = urllib.parse.quote(name)
        url = f"https://www.opensanctions.org/search/?q={encoded}"
        html = _http_get(url)

        if not html:
            return findings

        # Look for entity names in the search results list (not footer)
        # Entity results are in a list with links to /entities/ paths
        entity_matches = re.findall(
            r'<a[^>]*href="[^"]*"[^>]*>([^<]{5,100})</a>',
            html,
            re.IGNORECASE
        )

        # Filter: must be capitalized, not nav/footer, not navigation
        nav_terms = {
            "Search", "Documentation", "About", "Privacy", "Research",
            "Datasets", "Showcase", "Commercial use", "Global sanctions",
            "Specialized datasets", "EveryPolitician", "Newsletter",
            "Subscribe", "LinkedIn", "Github code", "Get support",
            "Talk to sales", "Forum", "System status", "Changelog",
            "Trust Center", "Security", "For LLMs", "Impressum",
            "API console", "License in bulk", "Use the API",
            "Equivalent request", "Search guide", "Using the API",
            "Advanced",
        }
        entities = [
            e.strip() for e in entity_matches
            if e.strip() and e.strip()[0].isupper()
            and len(e.strip()) > 8
            and e.strip() not in nav_terms
            and not any(nav in e.strip() for nav in nav_terms if len(nav) > 5)
        ][:5]

        # Check for sanctions indicators
        has_sanctions = bool(re.search(
            r'(?:sanction|debarred|wanted|OFAC|SDN|Interpol)',
            html, re.IGNORECASE
        ))

        if entities:
            status = "🚨 SANCTIONED" if has_sanctions else "📋 Listed"
            findings.append(
                self._make_finding(
                    title=f"{status}: {name} — OpenSanctions",
                    description=(
                        f"Found {len(entities)} entries in OpenSanctions:\n"
                        + "\n".join(f"- {e}" for e in entities)
                    ),
                    evidence=[url],
                    confidence=0.9 if has_sanctions else 0.7,
                    sanction_status="sanctioned" if has_sanctions else "listed",
                    entity_count=len(entities),
                )
            )

        return findings

    def _strip_html(self, text: str) -> str:
        """Remove HTML tags and decode entities from text."""
        # Remove tags
        text = re.sub(r'<[^>]+>', ' ', text)
        # Decode named entities
        text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        text = text.replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")
        text = text.replace("&#160;", " ").replace("&ndash;", "–").replace("&mdash;", "—")
        # Decode numeric entities like &#91; → [ or &#93; → ]
        text = re.sub(r'&#(\d+);', lambda m: chr(int(m.group(1))), text)
        text = re.sub(r'&#[xX]([0-9a-fA-F]+);', lambda m: chr(int(m.group(1), 16)), text)
        # Clean up whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        # Remove citation brackets [1][2] etc
        text = re.sub(r'\[\d+\]', '', text)
        text = re.sub(r'\[[a-z]\]', '', text)
        return text

    def _extract_entity_name(self, text: str) -> Optional[str]:
        """Extract entity name from query text."""
        # Strip quotes and common keywords
        clean = re.sub(r'["\']', '', text)
        clean = re.sub(
            r'\b(?:investigate|research|search|find|check|look\s+up|company|sanctions?)\b',
            '', clean, flags=re.IGNORECASE
        ).strip()

        # Find capitalized name sequence (1-4 words)
        match = re.search(r'\b([A-Z][a-z]+(?:\s+(?:"[^"]*"\s+)?[A-Z][a-z]+){0,3})\b', clean)
        if match:
            return match.group(1)

        # Fallback: any CamelCase or single capitalized word (e.g. "OpenAI", "DeepSeek")
        match = re.search(r'\b([A-Za-z][A-Za-z0-9]{2,}(?:\s+[A-Za-z][A-Za-z0-9]{1,}){0,2})\b', clean)
        if match:
            name = match.group(1)
            if name.lower() not in ("who", "what", "where", "when", "why", "how",
                "the", "and", "for", "with", "this", "that"):
                return name

        return None


# Register
scraper_tool = ScraperTool()
registry.register(scraper_tool)
