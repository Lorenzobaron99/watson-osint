"""
Browser Scraper — headless Playwright automation for Bellingcat OSINT tools.

Visits tool search URLs, waits for results to render, extracts structured data.
Provides per-tool CSS selectors for known tools, plus generic extraction for any URL.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

# ── Per-tool extraction patterns ────────────────────────────────────
# Each entry: CSS selectors + extraction logic for a specific tool

@dataclass
class ToolExtractor:
    """Defines how to extract results from a tool's search page."""
    name: str
    # URL template with {query} placeholder
    url_template: str | None = None
    # Wait for this selector to appear before extracting
    wait_for: str = "body"
    # Time to wait for dynamic content (seconds)
    wait_ms: int = 3000
    # CSS selectors
    result_items: str = ""          # container for each result
    title_selector: str = ""        # title/name within each result
    link_selector: str = ""         # link within each result
    desc_selector: str = ""         # description within each result
    # Whether to use generic text extraction fallback
    generic_fallback: bool = True
    # Max results to extract
    max_results: int = 10


# ── Extraction patterns for the most valuable Bellingcat tools ──────

EXTRACTORS: dict[str, ToolExtractor] = {
    "Shodan": ToolExtractor(
        name="Shodan",
        url_template="https://www.shodan.io/search?query={query}",
        wait_for=".search-results, .no-results, .heading",
        wait_ms=5000,
        result_items=".result",
        title_selector=".result h2, .result .title, .result a.title",
        desc_selector=".result p, .result .description",
    ),
    "BuiltWith": ToolExtractor(
        name="BuiltWith",
        url_template="https://builtwith.com/{query}",
        wait_for=".tech-item, .card-body, h1",
        wait_ms=5000,
        result_items=".tech-item, .card",
        title_selector="h2, .card-title, .tech-name",
        desc_selector="p, .card-text",
    ),
    "OpenCorporates": ToolExtractor(
        name="OpenCorporates",
        url_template="https://opencorporates.com/companies?q={query}",
        wait_for=".companies, .search-results, #results",
        wait_ms=5000,
        result_items=".company, .result, .search-result",
        title_selector=".company-name, .name a, h3 a",
        desc_selector=".company-details, .jurisdiction, .status",
    ),
    "Namechk": ToolExtractor(
        name="Namechk",
        url_template="https://namechk.com/",
        wait_for=".service-card, input[type=text]",
        wait_ms=4000,
        result_items=".service-card",
        title_selector=".service-name",
        desc_selector=".service-status",
    ),
    "Instant Username Search": ToolExtractor(
        name="Instant Username Search",
        url_template="https://instantusername.com/?q={query}",
        wait_for=".result, .results, #results",
        wait_ms=4000,
        result_items=".result, .results li, .site-result",
        title_selector=".site-name, .name, a",
        desc_selector=".status, .available",
    ),
    "SEC EDGAR": ToolExtractor(
        name="SEC EDGAR",
        url_template="https://www.sec.gov/cgi-bin/browse-edgar?company={query}&action=getcompany",
        wait_for=".tableFile, .companySearch, #seriesDiv",
        wait_ms=5000,
        result_items=".tableFile tr, table tr",
        title_selector="td:first-child a, td a",
        desc_selector="td:nth-child(2), td:nth-child(3)",
    ),
    "Google Maps": ToolExtractor(
        name="Google Maps",
        url_template="https://www.google.com/maps/search/{query}",
        wait_for="h1, .section-hero-header-title, [role=main]",
        wait_ms=6000,
        result_items="[role=article], .section-result",
        title_selector="h1, .section-result-title, [aria-label]",
        desc_selector=".section-result-details, .section-result-location",
    ),
    "OpenStreetMap": ToolExtractor(
        name="OpenStreetMap",
        url_template="https://www.openstreetmap.org/search?query={query}",
        wait_for=".search-results, #content",
        wait_ms=3000,
        result_items=".search-result, .search_results_entry",
        title_selector="a, .name",
        desc_selector=".type, .description",
    ),
    "FlightRadar24": ToolExtractor(
        name="FlightRadar24",
        url_template="https://www.flightradar24.com/data/search?q={query}",
        wait_for="#search-results, .search-results, table",
        wait_ms=5000,
        result_items=".search-result, table tbody tr",
        title_selector="a, .flight, td:first-child",
        desc_selector=".details, td:nth-child(2)",
    ),
    "Wayback Machine": ToolExtractor(
        name="Wayback Machine",
        url_template="https://web.archive.org/web/*/https://{query}",
        wait_for="#resultsUrl, .calendar-grid, .captures",
        wait_ms=5000,
        generic_fallback=True,  # Wayback uses calendar — use text extraction
    ),
}

# Tools where we can extract data by visiting the search page
BROWSER_TOOLS: set[str] = set(EXTRACTORS.keys())


# ── Browser Scraper Engine ──────────────────────────────────────────

class BrowserScraper:
    """Headless browser automation for Bellingcat tool data extraction."""

    def __init__(self):
        self._browser = None
        self._context = None
        self._page = None
        self._lock = asyncio.Lock()

    async def start(self):
        """Launch headless browser."""
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-web-security",
                "--disable-features=VizDisplayCompositor",
            ],
        )
        self._context = await self._browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1280, "height": 800},
            locale="en-US",
        )
        self._page = await self._context.new_page()

    async def stop(self):
        """Close browser."""
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

    async def scrape_tool(self, tool_name: str, query: str) -> list[dict]:
        """Visit a tool's search URL and extract results."""
        extractor = EXTRACTORS.get(tool_name)
        if not extractor or not extractor.url_template:
            return []

        url = extractor.url_template.format(query=quote(query, safe=""))
        async with self._lock:
            return await self._scrape_url(url, extractor)

    async def scrape_url(self, url: str, wait_ms: int = 3000) -> list[dict]:
        """Scrape any URL with generic extraction."""
        fallback = ToolExtractor(name="generic", wait_ms=wait_ms)
        return await self._scrape_url(url, fallback)

    async def _scrape_url(self, url: str, ex: ToolExtractor) -> list[dict]:
        """Core scraping: navigate, wait, extract."""
        try:
            await self._page.goto(url, timeout=15000, wait_until="domcontentloaded")
        except Exception as e:
            return [{"title": f"{ex.name}: Page load failed", "url": url, "error": True,
                     "description": str(e)[:200]}]

        # Wait for results to render
        try:
            await self._page.wait_for_selector(ex.wait_for, timeout=ex.wait_ms)
        except Exception:
            pass  # Page loaded but selector not found — try generic

        # Additional wait for JS rendering
        await asyncio.sleep(min(ex.wait_ms / 1000 * 0.5, 2))

        # Try structured extraction first
        results = []
        if ex.result_items:
            results = await self._extract_structured(ex)

        # Generic fallback
        if (not results and ex.generic_fallback) or (not ex.result_items):
            results = await self._extract_generic(ex.name, url)

        return results[:ex.max_results]

    async def _extract_structured(self, ex: ToolExtractor) -> list[dict]:
        """Extract results using CSS selectors."""
        try:
            items = await self._page.query_selector_all(ex.result_items)
            if not items:
                return []

            results = []
            for item in items[:ex.max_results]:
                result = {"source_tool": ex.name}

                if ex.title_selector:
                    el = await item.query_selector(ex.title_selector)
                    if el:
                        result["title"] = (await el.inner_text()).strip()[:200]

                if ex.link_selector:
                    el = await item.query_selector(ex.link_selector)
                    if el:
                        href = await el.get_attribute("href")
                        if href:
                            result["url"] = href

                if ex.desc_selector:
                    el = await item.query_selector(ex.desc_selector)
                    if el:
                        result["description"] = (await el.inner_text()).strip()[:300]

                if result.get("title") or result.get("description"):
                    results.append(result)

            return results
        except Exception:
            return []

    async def _extract_generic(self, tool_name: str, url: str) -> list[dict]:
        """Generic extraction: page title + visible text + all links."""
        try:
            title = await self._page.title()
            text = await self._page.inner_text("body")

            # Clean and truncate visible text
            lines = [l.strip() for l in text.split("\n") if l.strip()]
            clean_text = " | ".join(lines[:30])[:800]

            # Extract all links
            links = await self._page.evaluate("""() => {
                return Array.from(document.querySelectorAll('a[href]'))
                    .slice(0, 20)
                    .map(a => ({
                        text: a.innerText.trim().substring(0, 100),
                        href: a.href
                    }))
                    .filter(l => l.href.startsWith('http'));
            }""")

            result = {
                "source_tool": tool_name,
                "title": title[:200] if title else url[:100],
                "url": url,
                "description": clean_text,
            }

            if links:
                result["links"] = json.dumps(links[:10])

            return [result]
        except Exception:
            return [{"source_tool": tool_name, "title": f"{tool_name}: Extraction failed", "url": url, "error": True}]

    async def scrape_all(self, queries: list[tuple[str, str]]) -> dict:
        """Scrape multiple tools in sequence. Each query is (tool_name, search_query)."""
        results = {}
        for tool_name, query in queries:
            try:
                data = await self.scrape_tool(tool_name, query)
                results[tool_name] = data
            except Exception as e:
                results[tool_name] = [{"error": str(e), "source_tool": tool_name}]
        return results

    async def extract_article_text(self, url: str, timeout_ms: int = 15000) -> str:
        """Navigate to a URL and extract the main article text content.

        Uses generic extraction: finds the largest text block on the page,
        removes navigation/ads/sidebars/scripts.

        Returns up to 4000 chars of extracted article text, or empty string on failure.
        """
        if not self._browser:
            await self.start()

        try:
            page = await self._context.new_page()
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)

            # Wait for content to settle
            await asyncio.sleep(1.5)

            # Extract text content: try article area, then <p> aggregation, fall back to body
            text = await page.evaluate("""() => {
                // ── Strategy 1: Find main content area via CSS selectors ──
                const selectors = [
                    'article', '[role="main"]', 'main',
                    '.article-body', '.article-content', '.post-content',
                    '.story-body', '.content-body', '#article-body',
                    '.article__body', '.article__content',
                    // Government/CMS templates
                    '.govuk-main-wrapper', '#main-content', '#content',
                    '.entry-content', '.post-body', '.single-post',
                    '.blog-post', '.news-article', '.press-release',
                    '[itemprop="articleBody"]', '.c-article-body',
                ];
                for (const sel of selectors) {
                    const el = document.querySelector(sel);
                    if (el && el.innerText && el.innerText.length > 200) {
                        return el.innerText;
                    }
                }

                // ── Strategy 2: Collect substantive <p> tags ──
                // This naturally skips nav menus, cookie banners, and sidebars
                // since those use <ul>/<div>/<button>, not <p> with real content
                const paragraphs = document.querySelectorAll('p');
                const substantial = [];
                for (const p of paragraphs) {
                    const txt = p.innerText.trim();
                    // Skip short fragments, cookie boilerplate, nav-like text
                    if (txt.length < 40) continue;
                    if (/^(Accept|Reject|Decline|Allow|Deny|Manage|Customise|Customize|Settings|Save|Close)\\s/i.test(txt)) continue;
                    if (/cookies? (policy|settings|preferences)/i.test(txt)) continue;
                    substantial.push(txt);
                }
                if (substantial.length >= 3) {
                    return substantial.join('\\n\\n');
                }

                // ── Strategy 3: Body fallback with heavy noise stripping ──
                if (!document.body) return '';
                
                const clone = document.body.cloneNode(true);
                
                const noiseSelectors = [
                    'nav', 'header', 'footer', 'aside',
                    '.nav', '.navbar', '.navigation', '.menu',
                    '.sidebar', '.footer', '.header',
                    '.advertisement', '.ad', '.ads',
                    '.cookie-banner', '.cookie-consent', '.cookie-notice',
                    '.cookie-bar', '.cc-banner', '#cookie-banner',
                    '[aria-label="cookieconsent"]', '.consent-banner',
                    '.related-articles', '.related-posts',
                    '.recommended', '.trending', '.popular',
                    '.comments', '.comment-section',
                    '.social-share', '.share-buttons',
                    '.newsletter', '.subscribe', '.email-signup',
                    'script', 'style', 'noscript', 'iframe',
                    // Common mobile nav
                    '.mobile-nav', '.mobile-menu', '.hamburger-menu',
                    // Breadcrumbs
                    '.breadcrumb', '.breadcrumbs',
                    // Author/social/meta bars
                    '.author-bio', '.byline', '.meta-info',
                ];
                noiseSelectors.forEach(sel => {
                    try {
                        clone.querySelectorAll(sel).forEach(el => el.remove());
                    } catch(e) {}
                });
                
                let text = clone.innerText || '';
                
                // ── Aggressive boilerplate stripping ──
                // Cookie consent line patterns (single-line removal)
                const cookieLinePatterns = [
                    /^.*(?:uses? cookies?|cookie (?:policy|settings|preferences|notice)|This site (?:uses|employs|requires) cookies?).*$/gmi,
                    /^.*(?:Accept|Reject|Decline|Allow|Deny|Manage|Customi[sz]e|Save) (?:All )?Cookies?.*$/gmi,
                    /^.*(?:I (?:Accept|Do Not Accept|Reject|Decline) Cookies?).*$/gmi,
                    /^.*(?:Necessary|Essential|Analytical|Analytics|Marketing|Advertising|Functional|Performance|Targeting|Preference|Statistics) Cookies?.*$/gmi,
                    /^.*(?:On\\s*Off|On / Off).*$/gmi,
                    /^.*(?:About this tool).*$/gmi,
                    /^.*(?:Opens in a new window).*$/gmi,
                    /^.*(?:Cookie declaration|Cookie consent|Cookie notice|Cookie settings|Cookie preferences).*$/gmi,
                    /^.*(?:Powered by|Hosted by).*$/gmi,
                ];
                cookieLinePatterns.forEach(pattern => {
                    text = text.replace(pattern, '');
                });

                // Multi-line boilerplate block removal
                const blockPatterns = [
                    /Today's Stocks[\\s\\S]*?(?=\\n\\n|$)/gi,
                    /Stock quotes[\\s\\S]{0,500}?(?=\\n\\n)/gi,
                    /Subscribe( to our newsletter)?[\\s\\S]{0,200}?(?=\\n\\n)/gi,
                    /Follow us on[\\s\\S]{0,200}?(?=\\n\\n)/gi,
                    /We use (essential )?cookies[\\s\\S]{0,300}?(?=\\n\\n)/gi,
                    /Accept (all )?cookies[\\s\\S]{0,200}?(?=\\n\\n)/gi,
                    /Sign (in|up)[\\s\\S]{0,200}?(?=\\n\\n)/gi,
                    /Log (in|out)[\\s\\S]{0,200}?(?=\\n\\n)/gi,
                    /Privacy Policy[\\s\\S]{0,200}?(?=\\n\\n)/gi,
                    /Terms of (Service|Use)[\\s\\S]{0,200}?(?=\\n\\n)/gi,
                    // Nav menu junk: repeated short capitalised tokens
                    /(?:PRODUCT TOURS?|Platform|Solutions?|Products?|Services?|Resources?|Company|About Us|Contact Us?|Blog|Support|Pricing|Integrations?|Documentation|Login|Register|Get Started|Request Demo|Free Trial)(?:\\n(?:PRODUCT TOURS?|Platform|Solutions?|Products?|Services?|Resources?|Company|About Us|Contact Us?|Blog|Support|Pricing|Integrations?|Documentation|Seleziona lingua|Login|Register|Get Started|Request Demo|Free Trial|Analysis & Investigations?|Security Orchestration|Threat Intelligence|Vulnerability Intelligence|National Security Intelligence|Managed Intelligence|Managed Attribution|Fraud Intelligence|Brand Intelligence|External Attack Surface|Threat Response|Threat Actor|Professional Services|Product Integrations?|Curated Alerting|Proactive Acquisitions|Tailored Reporting|Request for Information)){2,}/gi,
                ];
                blockPatterns.forEach(pattern => {
                    text = text.replace(pattern, '');
                });
                
                // Remove lines that are clearly UI boilerplate
                const lines = text.split('\\n');
                const cleaned = [];
                for (const line of lines) {
                    const trimmed = line.trim();
                    if (!trimmed) { cleaned.push(''); continue; }
                    // Skip pure navigation/menu lines
                    if (/^(Facebook|Twitter|X|LinkedIn|Reddit|WhatsApp|Instagram|YouTube|Email|Share|Save|Print|Copy Link|Subscribe|Follow)$/i.test(trimmed)) continue;
                    // Skip isolated cookie controls
                    if (/^(On|Off)$/i.test(trimmed)) continue;
                    // Skip single-word lines that look like nav
                    if (/^(PLAY|GAMING|EUR|USD|CAD|GBP|RUB|CNY|INR|BRL|TRY|Platform)$/i.test(trimmed)) continue;
                    cleaned.push(trimmed);
                }
                text = cleaned.join('\\n');
                
                // Remove repeated newlines and whitespace
                text = text.replace(/\\n{3,}/g, '\\n\\n');
                text = text.replace(/^\\s+|\\s+$/g, '');
                
                return text;
            }""")

            await page.close()
            return text[:4000] if text else ""

        except Exception as e:
            return ""


# ── Singleton ───────────────────────────────────────────────────────
_scraper: BrowserScraper | None = None
_NO_BROWSER = os.environ.get("WATSON_NO_BROWSER", "").lower() in ("1", "true", "yes")


async def get_scraper() -> BrowserScraper | None:
    global _scraper
    if _NO_BROWSER:
        return None
    if _scraper is None:
        _scraper = BrowserScraper()
        await _scraper.start()
    return _scraper


async def close_scraper():
    global _scraper
    if _scraper:
        await _scraper.stop()
        _scraper = None
