"""Utility helpers — domain extraction, URL parsing, text cleaning."""

from __future__ import annotations

import re
from urllib.parse import urlparse


def extract_domain(url: str) -> str:
    """Extract the domain from a URL, stripping www prefix."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split("/")[0]
    return domain.removeprefix("www.")


def extract_domains(text: str) -> list[str]:
    """Extract all domains from arbitrary text."""
    pattern = r"(?:https?://)?(?:www\.)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)"
    matches = re.findall(pattern, text)
    return list(dict.fromkeys(matches))  # Deduplicated, order preserved


def clean_username(text: str) -> str:
    """Clean and extract a username from text (strip @, URLs, etc.)."""
    text = text.strip().removeprefix("@")
    # If it's a URL, extract the handle
    if "/" in text:
        parts = text.rstrip("/").split("/")
        text = parts[-1] if parts[-1] else parts[-2]
    return text


def is_email(text: str) -> bool:
    """Check if text looks like an email address."""
    return bool(re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", text.strip()))


def is_url(text: str) -> bool:
    """Check if text looks like a URL."""
    return bool(re.match(r"^https?://", text.strip()))


def truncate(text: str, max_len: int = 200) -> str:
    """Truncate text to max_len with ellipsis."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."
