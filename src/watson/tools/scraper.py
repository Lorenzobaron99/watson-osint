"""Scraper engine — extracts real data from Wikipedia, OpenSanctions, and OSINT sources.

When APIs fail (rate-limited, blocked), this falls back to HTML scraping with
browser-grade headers. Uses plain http.client for maximum reliability.
"""

from __future__ import annotations

import http.client
import json
import logging
import re
import ssl
import urllib.parse
from html.parser import HTMLParser
from typing import Optional

from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSource

logger = logging.getLogger("watson.scraper")


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
                # ── Guard against Wikipedia "did you mean?" redirects ──
                # Wikipedia redirects /wiki/Gačanin → /wiki/Edin (name etymology).
                # Check the page title contains the LAST name part (most distinctive).
                # "Edin Gačanin" → page title must contain "gačanin", not just "edin".
                title_match = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
                page_title = self._strip_html(title_match.group(1)) if title_match else ""
                page_title = re.sub(r'\s*[-–—]\s*Wikipedia\s*$', '', page_title, flags=re.IGNORECASE).strip()
                title_lower = page_title.lower()
                try_parts = [p.lower() for p in try_name.split() if len(p) >= 3]
                if try_parts:
                    # Must match the LAST name part (most distinctive).
                    # ASCII-fold both sides — "gačanin" ↔ "gacanin" diacritic mismatch
                    import unicodedata as _ucd
                    _fold = lambda s: _ucd.normalize("NFKD", s).encode("ascii", "ignore").decode()
                    last_folded = _fold(try_parts[-1])
                    title_folded = _fold(title_lower)
                    if last_folded not in title_folded:
                        html = None
                        continue
                    # Secondary: reject Wikipedia search result pages
                    is_search = (
                        "mw-search-results" in html or
                        "searchdidyoumean" in html.lower() or
                        'id="mw-search-top-table"' in html or
                        "may refer to:" in html[:2000].lower()
                    )
                    if is_search:
                        html = None
                        continue
                break
            html = None

        if not html:
            # Search fallback — use Wikipedia API for intelligent disambiguation.
            # Avoids Wikipedia "did you mean?" redirects (e.g. /wiki/Gačanin → /wiki/Edin).
            best_article = await self._wiki_api_search(name, parts)
            if best_article:
                scraped_url = f"https://en.wikipedia.org/wiki/{urllib.parse.quote(best_article.replace(' ', '_'))}"
                html = _http_get(scraped_url)
            
            if not html:
                # Last resort: raw search page HTML (keeps existing fallback)
                search_url = f"https://en.wikipedia.org/wiki/Special:Search?search={urllib.parse.quote(name)}"
                html = _http_get(search_url)

        if not html:
            return findings

        # ── Detect redirect: page title doesn't match search target ──
        title_match = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
        page_title = self._strip_html(title_match.group(1)) if title_match else ""
        # Clean " - Wikipedia" suffix
        page_title = re.sub(r'\s*[-–—]\s*Wikipedia\s*$', '', page_title, flags=re.IGNORECASE).strip()
        # Check if we were redirected — page title doesn't contain our target name
        name_parts = [p.lower() for p in name.split() if len(p) > 2]
        title_lower = page_title.lower()
        is_redirect = len(name_parts) >= 2 and not any(
            part in title_lower for part in name_parts[-2:]
        )

        if is_redirect:
            # ── Redirect case: page is about something else ──
            # Skip infobox (belongs to redirect target, not our subject)
            # Extract lead paragraph for context + paragraphs mentioning our target
            lead = self._extract_lead_paragraph(html)
            target_paras = self._extract_target_paragraphs(html, name)

            if target_paras or lead:
                desc_parts = []
                if lead:
                    desc_parts.append(f"[Article: {page_title}] {lead[:300]}")
                if target_paras:
                    desc_parts.append("")
                    desc_parts.append(f"--- Mentions of {name} ---")
                    for i, para in enumerate(target_paras[:5], 1):
                        desc_parts.append(f"{i}. {para[:600]}")

                findings.append(
                    self._make_finding(
                        title=f"📖 Wikipedia: {name}",
                        description="\n".join(desc_parts),
                        evidence=[scraped_url],
                        confidence=0.75 if target_paras else 0.50,
                        source_url=scraped_url,
                        infobox={"page_title": page_title, "redirected": True},
                    )
                )
        else:
            # ── Direct page: extract infobox normally ──
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

                findings.append(
                    self._make_finding(
                        title=f"📖 Wikipedia: {name}",
                        description="\n".join(desc_parts),
                        evidence=[scraped_url],
                        confidence=0.9 if infobox else 0.6,
                        source_url=scraped_url,
                        infobox=infobox,
                    )
                )

        return findings

    # ── Wikipedia API search with disambiguation ──────────────────

    # Pages that are about words/names, not people — skip these.
    _SKIP_TITLE_PATTERNS = [
        r" \(name\)$", r" \(surname\)$", r" \(given name\)$",
        r" \(disambiguation\)$", r" \(word\)$", r" \(term\)$",
    ]
    # Keywords that suggest the article is about crime/investigations —
    # prefer these when ambiguous.
    _CRIME_KEYWORDS = [
        "organised crime", "organized crime", "cartel", "drug traffick",
        "cocaine", "mafia", "gang", "sanction", "indict", "arrest",
        "convict", "criminal", "crime", "trafficking", "smuggl",
    ]

    async def _wiki_api_search(self, name: str, parts: list[str]) -> str | None:
        """Search Wikipedia API for the best article about this subject.

        Tries both original and ASCII-folded versions of the name.
        Skips disambiguation pages and name-etymology articles.
        Prefers articles with crime/investigation keywords.
        """
        import unicodedata
        import httpx

        # Build search queries — original + ASCII-folded (no diacritics)
        ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
        queries = [name]
        if ascii_name != name and len(ascii_name) >= 3:
            queries.append(ascii_name)

        for query in queries:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.get(
                        "https://en.wikipedia.org/w/api.php",
                        params={
                            "action": "query",
                            "list": "search",
                            "srsearch": query,
                            "srlimit": 10,
                            "format": "json",
                        },
                        headers={"User-Agent": "WatsonOSINT/1.0"},
                    )
                    if resp.status_code != 200:
                        continue
                    data = resp.json()
            except Exception:
                continue

            results = data.get("query", {}).get("search", [])
            if not results:
                continue

            # Score and filter results
            candidates: list[tuple[int, str]] = []
            for r in results:
                title = r.get("title", "")
                snippet = r.get("snippet", "")
                combined = (title + " " + snippet).lower()

                # Skip disambiguation / name-etymology pages
                skip = False
                for pat in self._SKIP_TITLE_PATTERNS:
                    if re.search(pat, title, re.IGNORECASE):
                        skip = True
                        break
                if skip:
                    continue

                # Check that at least one name part appears in the article
                if parts and not any(p.lower() in combined for p in parts if len(p) > 2):
                    continue

                # Score: crime keywords → higher priority
                score = 0
                for kw in self._CRIME_KEYWORDS:
                    if kw in combined:
                        score += 10
                # Penalize very short titles (likely generic)
                if len(title) < 15:
                    score -= 5

                candidates.append((score, title))

            if candidates:
                # Sort by score descending, then pick best
                candidates.sort(key=lambda x: x[0], reverse=True)
                return candidates[0][1]

        return None

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
        for p_match in re.finditer(r'<p[^>]*>(.*?)</p>', html, re.DOTALL | re.IGNORECASE):
            text = self._strip_html(p_match.group(1)).strip()
            if len(text) < 80:
                continue
            if "From Wikipedia" in text or "may refer to:" in text:
                continue
            return text[:500]
        return ""

    def _extract_target_paragraphs(self, html: str, target_name: str) -> list[str]:
        """Extract paragraphs that mention the target by name (for redirect pages).

        When a Wikipedia page redirects (e.g., Massimo Bossetti → Murder of Yara
        Gambirasio), the infobox belongs to the redirect target. This method
        finds the paragraphs that actually discuss our search target.
        """
        paras: list[str] = []
        name_lower = target_name.lower()
        parts = [p.lower() for p in target_name.split() if len(p) > 2]
        first = parts[0] if parts else ""
        last = parts[-1] if len(parts) >= 2 else ""

        for p_match in re.finditer(r'<p[^>]*>(.*?)</p>', html, re.DOTALL | re.IGNORECASE):
            text = self._strip_html(p_match.group(1)).strip()
            if len(text) < 60:
                continue
            text_lower = text.lower()

            # Full name match — strongest signal
            if name_lower in text_lower:
                paras.append(text[:600])
                continue
            # First+last both appear (name may be split across sentence)
            if first and last and first in text_lower and last in text_lower:
                paras.append(text[:600])

        return paras

    async def _scrape_opensanctions(self, name: str) -> list[Finding]:
        """Check OpenSanctions via API (authenticated) with graceful fallback."""
        findings: list[Finding] = []
        import os

        api_key = os.environ.get("OPENSANCTIONS_API_KEY", "")

        # Try API first (authenticated)
        if api_key:
            try:
                import http.client, ssl, json, urllib.parse

                params = urllib.parse.urlencode({"q": name, "limit": 10})
                url = f"/search/default?{params}"

                ctx = ssl.create_default_context()
                conn = http.client.HTTPSConnection("api.opensanctions.org", timeout=15, context=ctx)
                conn.request("GET", url, headers={
                    "Authorization": f"ApiKey {api_key}",
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                })
                resp = conn.getresponse()
                body = resp.read().decode("utf-8", errors="replace")
                conn.close()

                if resp.status == 200:
                    data = json.loads(body)
                    results = data.get("results", [])
                    if results:
                        # ── RELEVANCE FILTER: score each result against the query ──
                        sanctioned = []
                        filtered_out = 0
                        for r in results[:10]:  # Check all results, not just first 5
                            caption = r.get("caption", r.get("name", "Unknown"))
                            schema = r.get("schema", "")
                            countries = ", ".join(r.get("countries", []))
                            datasets = r.get("datasets", [])
                            topics = r.get("topics", [])

                            # Build a description from all available fields for scoring
                            desc_parts = [caption, schema] + countries.split(", ") + datasets + topics
                            full_desc = " ".join(desc_parts)

                            score = self._score_entity_relevance(caption, full_desc, name)
                            if score < 0.35:
                                filtered_out += 1
                                continue

                            lines = [f"- **{caption}** [{schema}] (score: {score:.0%})"]
                            if countries:
                                lines.append(f"  Countries: {countries}")
                            if datasets:
                                lines.append(f"  Sanction lists: {', '.join(datasets)}")
                            if topics:
                                lines.append(f"  Topics: {', '.join(topics)}")
                            sanctioned.append("\n".join(lines))

                        if sanctioned:
                            findings.append(
                                self._make_finding(
                                    title=f"🚨 SANCTIONS MATCH: {len(sanctioned)} relevant entries for '{name}'",
                                    description="\n".join(sanctioned),
                                    evidence=[f"https://opensanctions.org/search/?q={urllib.parse.quote(name)}"],
                                    confidence=0.95,
                                    sanction_match=True,
                                    result_count=len(sanctioned),
                                    filtered_out=filtered_out,
                                )
                            )
                        elif filtered_out:
                            findings.append(
                                self._make_finding(
                                    title=f"🔍 OpenSanctions: {filtered_out} results filtered — none relevant to '{name}'",
                                    description="All API results were filtered out by relevance scoring. No named entity matched the target.",
                                    confidence=0.6,
                                    sanction_match=False,
                                )
                            )
                        return findings
                    else:
                        findings.append(
                            self._make_finding(
                                title=f"✅ No sanctions: '{name}' (OpenSanctions API)",
                                description="No matches found via authenticated OpenSanctions API search.",
                                confidence=0.7,
                                sanction_match=False,
                            )
                        )
                        return findings
                elif resp.status == 429:
                    logger.warning("opensanctions_rate_limited: API key exceeded monthly limit")
                    # Fall through to web search fallback
                else:
                    logger.warning("opensanctions_api_error: HTTP %d", resp.status)
                    # Fall through to web search fallback
            except Exception as e:
                logger.warning("opensanctions_api_failed: %s", e)
                # Fall through to web search fallback

        # Fallback: search via DuckDuckGo for opensanctions.org entity pages
        try:
            from ddgs import DDGS
            search_query = f'"{name}" site:opensanctions.org'
            
            results = []
            with DDGS() as ddgs:
                results = list(ddgs.text(search_query, max_results=5))
            
            if results:
                entity_lines = []
                filtered_out = 0
                for r in results[:5]:
                    title = r.get("title", "")
                    url = r.get("href", "")
                    body = r.get("body", "")

                    # ── Filter out search pages, not entity pages ──
                    # Search redirects like /search/?q=X return garbage tracking URLs
                    # Startpage tracking redirects (/clev?event=StartpageResultClick...) are also noise
                    if "/search/" in url or "/search?" in url or "StartpageResultClick" in url:
                        filtered_out += 1
                        continue

                    # DDG snippets all contain the bare search term, so body-only
                    # matches are noise. But the body ALSO contains entity descriptions.
                    # Check if the body mentions entity-specific aliases beyond the
                    # bare search term (e.g. "Norilsk Nickel" for "Nornickel").
                    # This catches Vladimir Potanin (body: "President of Norilsk Nickel")
                    # while filtering Mohammad Ali Jafari (body: generic sanctions info).
                    aliases = self._derive_aliases(name)
                    body_has_alias = any(alias.lower() in body.lower() for alias in aliases)

                    # Feed the body text into the scorer so it can check description tokens.
                    # Previously passed "" which made desc-based token overlap useless.
                    score = self._score_entity_relevance(title, body, name)
                    if score < 0.35 and not body_has_alias:
                        filtered_out += 1
                        continue

                    entity_lines.append(f"- **{title}**\n  {body[:200]}\n  {url}")

                if entity_lines:
                    findings.append(
                        self._make_finding(
                            title=f"🔍 OpenSanctions search results: {len(entity_lines)} for '{name}'",
                            description="\n".join(entity_lines),
                            evidence=[f"https://opensanctions.org/search/?q={urllib.parse.quote(name)}"],
                            confidence=0.7,
                            sanction_match=False,
                        )
                    )
                elif filtered_out:
                    findings.append(
                        self._make_finding(
                            title=f"🔍 OpenSanctions: {filtered_out} results filtered — none relevant to '{name}'",
                            description="All DDG results were filtered out by relevance scoring.",
                            confidence=0.5,
                            sanction_match=False,
                        )
                    )
            else:
                findings.append(
                    self._make_finding(
                        title=f"✅ No OpenSanctions results: '{name}'",
                        description="No matches found via DuckDuckGo search of opensanctions.org.",
                        confidence=0.5,
                        sanction_match=False,
                    )
                )
        except Exception as e:
            logger.warning("opensanctions_fallback_failed: %s", e)

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

    _RELEVANCE_STOP_WORDS: set[str] = {
        "the", "and", "for", "with", "that", "this", "from", "have", "been",
        "was", "are", "were", "not", "but", "its", "his", "her", "their",
        "has", "had", "will", "would", "could", "should", "may", "also",
        "inc", "corp", "ltd", "llc", "limited", "corporation", "company",
        "group", "international", "global", "world", "organization",
    }

    def _score_entity_relevance(self, entity_name: str, entity_desc: str, search_query: str) -> float:
        """Score how relevant an OpenSanctions result is to the search query.

        Returns 0.0 (completely unrelated) to 1.0 (exact match).
        Threshold of 0.35 keeps entities with at least partial name overlap.
        """
        query_lower = search_query.lower().strip()
        name_lower = entity_name.lower().strip()
        desc_lower = entity_desc.lower().strip()

        # Direct substring match (strongest signal)
        if query_lower in name_lower:
            return 1.0
        if name_lower in query_lower:
            return 0.95

        # Acronym matching: "MMC Norilsk Nickel" vs "Nornickel"
        query_chars = set(query_lower.replace(" ", ""))
        name_clean = name_lower.replace(" ", "").replace(".", "").replace(",", "")
        overlap_ratio = len(query_chars & set(name_clean)) / max(len(query_chars), 1)
        if overlap_ratio > 0.8 and len(query_chars) >= 4:
            return 0.85

        # Token overlap scoring
        query_tokens = set(
            t for t in re.findall(r'[a-z0-9]+', query_lower)
            if len(t) > 2 and t not in self._RELEVANCE_STOP_WORDS
        )
        name_tokens = set(
            t for t in re.findall(r'[a-z0-9]+', name_lower)
            if len(t) > 2 and t not in self._RELEVANCE_STOP_WORDS
        )

        if not query_tokens:
            return 1.0  # Can't judge, include

        # Token overlap
        overlap = query_tokens & name_tokens
        if overlap:
            score = len(overlap) / len(query_tokens)
            if len(name_tokens) <= 3:
                score = min(1.0, score + 0.15)
            return score

        # Check description for query token mentions
        desc_tokens = set(re.findall(r'[a-z0-9]+', desc_lower))
        desc_hits = query_tokens & desc_tokens
        if desc_hits:
            hit_ratio = len(desc_hits) / len(query_tokens)
            if hit_ratio >= 0.5:
                return 0.55 + hit_ratio * 0.3
            return 0.35 + hit_ratio * 0.2

        # Last resort: any query token as substring in name
        for token in query_tokens:
            if token in name_clean:
                return 0.40

        return 0.0

    @staticmethod
    def _derive_aliases(name: str) -> list[str]:
        """Generate DERIVED aliases for an entity name — NOT the original.

        Used in DDG fallback to check if a body snippet references the entity
        by a VARIANT name. The original search term is excluded because every
        DDG snippet already contains it (it's in the search query).
        
        E.g., for "Nornickel" → ["norilsk nickel", "mmc norilsk nickel"]
        """
        name_lower = name.lower().strip()

        # Known company aliases (original → variants)
        KNOWN_ALIASES = {
            "nornickel": ["norilsk nickel", "mmc norilsk nickel"],
            "norilsk nickel": ["nornickel", "mmc norilsk"],
            "mmc norilsk nickel": ["nornickel", "norilsk nickel"],
            "interros": ["interros holding"],
        }

        aliases = KNOWN_ALIASES.get(name_lower, [])

        # Space-separated component swaps
        if " " in name_lower:
            parts = name_lower.split()
            if len(parts) >= 2:
                swapped = " ".join(parts[-1:] + parts[:-1])
                if swapped != name_lower and swapped not in aliases:
                    aliases.append(swapped)

        return list(set(aliases))

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
