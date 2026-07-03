"""Article scraper — extract real text from web pages, not cookie banners."""

from __future__ import annotations
import logging
import re

logger = logging.getLogger("watson.scraper")

# ── 3-stage extraction ────────────────────────────────────────

_STRIP_PATTERNS = [
    re.compile(r"I Accept Cookies|Accept All Cookies|Cookie Settings|Manage Cookies", re.I),
    re.compile(r"We use cookies|This site uses cookies|By continuing", re.I),
    re.compile(r"Subscribe to our newsletter|Sign up for our newsletter", re.I),
    re.compile(r"Advertisement|Sponsored Content|Promoted", re.I),
    re.compile(r"Share on (?:Facebook|Twitter|LinkedIn|Reddit)", re.I),
    re.compile(r"All (?:rights reserved|products featured).*?(?:independently|selected).*?[.]", re.I),
]

def extract_content(html: str, url: str = "") -> str:
    """Extract readable text from HTML. 3-stage pipeline."""
    if not html:
        return ""
    
    # Stage 1: Try content selectors (article, main, etc.)
    content = _extract_by_selectors(html)
    if content and len(content) > 200:
        return _clean_text(content)
    
    # Stage 2: Aggregate <p> tags
    content = _extract_paragraphs(html)
    if content and len(content) > 200:
        return _clean_text(content)
    
    # Stage 3: Extract body text with noise stripping
    content = _extract_body(html)
    return _clean_text(content)


def _extract_by_selectors(html: str) -> str:
    """Try known content containers."""
    selectors = [
        r'<article[^>]*>(.*?)</article>',
        r'<main[^>]*>(.*?)</main>',
        r'<div[^>]*class="[^"]*content[^"]*"[^>]*>(.*?)</div>',
        r'<div[^>]*class="[^"]*article[^"]*"[^>]*>(.*?)</div>',
        r'<div[^>]*id="content"[^>]*>(.*?)</div>',
        r'<div[^>]*class="[^"]*post[^"]*"[^>]*>(.*?)</div>',
        r'<section[^>]*>(.*?)</section>',
    ]
    
    for pattern in selectors:
        m = re.search(pattern, html, re.DOTALL | re.I)
        if m:
            text = re.sub(r'<[^>]+>', ' ', m.group(1))
            text = re.sub(r'\s+', ' ', text).strip()
            if len(text) > 200:
                return text
    
    return ""


def _extract_paragraphs(html: str) -> str:
    """Extract all <p> tag text."""
    paragraphs = re.findall(r'<p[^>]*>(.*?)</p>', html, re.DOTALL | re.I)
    texts = []
    for p in paragraphs:
        text = re.sub(r'<[^>]+>', ' ', p)
        text = re.sub(r'\s+', ' ', text).strip()
        if len(text) > 20:
            texts.append(text)
    return ' '.join(texts)


def _extract_body(html: str) -> str:
    """Extract body, strip scripts, styles, navigation."""
    # Remove script and style blocks
    html = re.sub(r'<(script|style|nav|header|footer)[^>]*>.*?</\1>', '', html, flags=re.DOTALL | re.I)
    # Remove remaining tags
    text = re.sub(r'<[^>]+>', ' ', html)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def _clean_text(text: str) -> str:
    """Strip noise patterns from extracted text."""
    for pattern in _STRIP_PATTERNS:
        text = pattern.sub('', text)
    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    # Truncate at max chars
    if len(text) > 4000:
        text = text[:4000] + "..."
    return text
