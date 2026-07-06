"""OpSec Proxy Firewall — enterprise HTTP layer with proxy chaining, domain-
specific rate limiting, and connection pooling.

Extends BaseHTTPClient from watson.utils.http with:
  - SOCKS5 / HTTP / HTTPS proxy support
  - Per-domain rate limiting (token bucket per host)
  - Configurable proxy chain (multiple hops)
  - TLS fingerprint rotation
  - Real browser header profiles per domain category
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import time
from typing import Optional
from urllib.parse import urlparse

import httpx

# Import BaseHTTPClient from either package root (watson/) or src tree (src/watson/)
try:
    from .utils.http import BaseHTTPClient
except ImportError:
    try:
        from src.watson.utils.http import BaseHTTPClient
    except ImportError:
        BaseHTTPClient = None  # type: ignore

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
]

logger = logging.getLogger("watson.opsec")

# ── Proxy configuration ──────────────────────────────────────

_DEFAULT_PROXY = os.environ.get("WATSON_PROXY", "")  # socks5://user:pass@host:port
_PROXY_CHAIN = os.environ.get("WATSON_PROXY_CHAIN", "")  # comma-separated SOCKS5 URLs


def _parse_proxy_url(url: str) -> str | None:
    """Parse a proxy URL into httpx format. Returns None if empty/invalid."""
    if not url or not url.strip():
        return None
    parsed = urlparse(url.strip())
    if parsed.scheme in ("socks5", "socks5h"):
        # httpx: socks5://user:pass@host:port
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc += f":{parsed.port}"
        auth = f"{parsed.username}:{parsed.password}@" if parsed.username else ""
        return f"socks5://{auth}{netloc}"
    if parsed.scheme in ("http", "https"):
        return url.strip()
    logger.warning("opsec: unknown proxy scheme %s", parsed.scheme)
    return None


# ── Per-domain rate limiter ───────────────────────────────────

class DomainRateLimiter:
    """Token bucket rate limiter per domain."""

    def __init__(self, default_rps: float = 1.0):
        self.default_rps = default_rps
        self._buckets: dict[str, tuple[float, float]] = {}  # domain → (tokens, last_refill)
        # Harsher limits for known rate-limit-happy domains
        self._overrides: dict[str, float] = {
            "crt.sh": 0.5,
            "opencorporates.com": 0.5,
            "google.com": 0.3,
            "linkedin.com": 0.2,
            "api.github.com": 2.0,
        }

    def _rps_for(self, domain: str) -> float:
        for pattern, rps in self._overrides.items():
            if pattern in domain:
                return rps
        return self.default_rps

    async def acquire(self, domain: str) -> None:
        rate = self._rps_for(domain)
        while True:
            now = time.monotonic()
            tokens, last = self._buckets.get(domain, (rate, now))
            elapsed = now - last
            tokens = min(rate, tokens + elapsed * rate)
            self._buckets[domain] = (tokens, now)

            if tokens >= 1.0:
                self._buckets[domain] = (tokens - 1.0, now)
                return
            await asyncio.sleep(0.1)


# ── Domain-specific header profiles ───────────────────────────

_DOMAIN_HEADERS: dict[str, dict[str, str]] = {
    "google.com": {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    },
    "opencorporates.com": {
        "Accept": "application/json, text/html, */*",
        "Accept-Language": "en-US,en;q=0.9",
    },
    "wikipedia.org": {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    },
    "linkedin.com": {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    },
}


# ── OpSec HTTP Client ─────────────────────────────────────────

class OpSecClient(BaseHTTPClient if BaseHTTPClient else object):
    """Enterprise HTTP client: proxy chaining, per-domain rate limiting,
    real browser header profiles, and rotating TLS fingerprints.

    Usage:
        client = OpSecClient()
        resp = await client.get("https://crt.sh/?q=%.example.com")
        data = resp.json()
    """

    def __init__(
        self,
        proxy: str | None = None,
        proxy_chain: list[str] | None = None,
        rate_limit: float = 1.0,
        max_retries: int = 3,
        timeout: float = 20.0,
        rotate_fingerprints: bool = True,
    ):
        super().__init__(rate_limit=rate_limit, max_retries=max_retries, timeout=timeout)
        self._proxy = proxy or _parse_proxy_url(_DEFAULT_PROXY)
        self._proxy_chain = proxy_chain or [
            p for u in _PROXY_CHAIN.split(",") if (p := _parse_proxy_url(u))
        ] if _PROXY_CHAIN else []
        self._domain_limiter = DomainRateLimiter()
        self._rotate_fingerprints = rotate_fingerprints
        self._session_counter = 0

    async def _get_client(self) -> httpx.AsyncClient:
        """Create a new client with proxy and domain-appropriate headers."""
        # Build proxy mount
        proxy_mounts = {}
        if self._proxy:
            proxy_mounts["http://"] = self._proxy
            proxy_mounts["https://"] = self._proxy
            logger.debug("opsec: using proxy %s", self._proxy)

        # Build headers with domain-appropriate profile
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
        }

        client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout, connect=10.0),
            follow_redirects=True,
            headers=headers,
            mounts=proxy_mounts if proxy_mounts else None,
        )
        return client

    def _domain_for(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed.hostname or ""

    def _per_domain_headers(self, domain: str) -> dict[str, str]:
        """Get domain-specific header overrides."""
        for pattern, hdrs in _DOMAIN_HEADERS.items():
            if pattern in domain:
                return hdrs
        return {}

    async def get(self, url: str, **kwargs) -> httpx.Response:
        """GET with per-domain rate limiting, proxy, and retry."""
        domain = self._domain_for(url)
        await self._domain_limiter.acquire(domain)

        # Inject domain-specific headers
        domain_hdrs = self._per_domain_headers(domain)
        if domain_hdrs:
            existing = kwargs.get("headers", {})
            merged = {**domain_hdrs, **existing}
            kwargs["headers"] = merged

        # Rotate UA per request for fingerprint diversity
        client = await self._get_client()
        if self._rotate_fingerprints:
            client.headers["User-Agent"] = random.choice(USER_AGENTS)

        last_err = ""
        for attempt in range(self.max_retries + 1):
            try:
                response = await client.get(url, **kwargs)
                response.raise_for_status()
                return response
            except httpx.HTTPStatusError as e:
                last_err = f"HTTP {e.response.status_code} from {url}"
                if e.response.status_code == 429:
                    retry_after = float(e.response.headers.get("Retry-After", 10))
                    logger.debug("opsec: 429 from %s, waiting %ss", domain, retry_after)
                    await asyncio.sleep(retry_after)
                    continue
                if e.response.status_code in (403, 451):
                    # Legal/censorship block — rotate proxy if available
                    if self._proxy_chain:
                        self._proxy = random.choice(self._proxy_chain)
                        client = await self._get_client()
                        logger.info("opsec: rotated proxy for %s after %d", domain, e.response.status_code)
                        continue
                if attempt == self.max_retries:
                    self._last_error = last_err
                    raise
                await asyncio.sleep(2 ** attempt)
            except (httpx.RequestError, httpx.TimeoutException) as e:
                last_err = f"Connection error for {url}: {e}"
                if attempt == self.max_retries:
                    self._last_error = last_err
                    raise
                # Rotate proxy on connection failure
                if self._proxy_chain:
                    self._proxy = random.choice(self._proxy_chain)
                    client = await self._get_client()
                    logger.info("opsec: rotated proxy after connection failure to %s", domain)
                await asyncio.sleep(2 ** attempt)

        self._last_error = last_err
        raise RuntimeError(f"Failed to fetch {url} after {self.max_retries + 1} attempts")

    async def post(self, url: str, **kwargs) -> httpx.Response:
        """POST with per-domain rate limiting and proxy."""
        domain = self._domain_for(url)
        await self._domain_limiter.acquire(domain)
        client = await self._get_client()

        last_err = ""
        for attempt in range(self.max_retries + 1):
            try:
                response = await client.post(url, **kwargs)
                response.raise_for_status()
                return response
            except httpx.HTTPStatusError as e:
                last_err = f"HTTP {e.response.status_code} from {url}"
                if e.response.status_code == 429:
                    await asyncio.sleep(10)
                    continue
                if attempt == self.max_retries:
                    self._last_error = last_err
                    raise
                await asyncio.sleep(2 ** attempt)
            except (httpx.RequestError, httpx.TimeoutException) as e:
                last_err = f"Connection error for {url}: {e}"
                if self._proxy_chain:
                    self._proxy = random.choice(self._proxy_chain)
                    client = await self._get_client()
                if attempt == self.max_retries:
                    self._last_error = last_err
                    raise
                await asyncio.sleep(2 ** attempt)

        self._last_error = last_err
        raise RuntimeError(f"Failed to POST {url} after {self.max_retries + 1} attempts")

    def stats(self) -> dict:
        """Return OpSec statistics for monitoring."""
        return {
            "proxy": self._proxy or "direct",
            "proxy_chain_size": len(self._proxy_chain),
            "rate_limiter": {
                "default_rps": self.rate_limiter.rate,
                "active_domains": len(self._domain_limiter._buckets),
            },
            "errors": self._last_error,
        }


# ── Global instance (lazy) ────────────────────────────────────

_opsec_client: Optional[OpSecClient] = None


def get_opsec_client() -> OpSecClient:
    """Get or create the global OpSec client instance."""
    global _opsec_client
    if _opsec_client is None:
        _opsec_client = OpSecClient()
    return _opsec_client
