"""Async HTTP client with retry, rate limiting, and rotating user agents."""

from __future__ import annotations

import asyncio
import random
import time
from typing import Optional

import httpx

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
]


class RateLimiter:
    """Token bucket rate limiter."""

    def __init__(self, requests_per_second: float = 1.0):
        self.rate = requests_per_second
        self._tokens = requests_per_second
        self._last_refill = time.monotonic()

    async def acquire(self) -> None:
        """Wait until a token is available."""
        while True:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self.rate, self._tokens + elapsed * self.rate)
            self._last_refill = now

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return

            await asyncio.sleep(0.1)


class BaseHTTPClient:
    """Async HTTP client with built-in retry and rate limiting."""

    def __init__(
        self,
        rate_limit: float = 1.0,
        max_retries: int = 2,
        timeout: float = 20.0,
    ):
        self.rate_limiter = RateLimiter(rate_limit)
        self.max_retries = max_retries
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._last_error: str = ""  # Exposed for tools to report failures

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout, connect=10.0),
                follow_redirects=True,
                headers={
                    "User-Agent": random.choice(USER_AGENTS),
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Language": "en-US,en;q=0.9",
                },
            )
        return self._client

    async def get(self, url: str, **kwargs) -> httpx.Response:
        """GET with retry and rate limiting."""
        await self.rate_limiter.acquire()
        client = await self._get_client()

        last_err = ""
        for attempt in range(self.max_retries + 1):
            try:
                response = await client.get(url, **kwargs)
                response.raise_for_status()
                return response
            except httpx.HTTPStatusError as e:
                last_err = f"HTTP {e.response.status_code} from {url}"
                if e.response.status_code == 429:
                    retry_after = float(e.response.headers.get("Retry-After", 5))
                    await asyncio.sleep(retry_after)
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
                await asyncio.sleep(2 ** attempt)

        self._last_error = last_err
        raise RuntimeError(f"Failed to fetch {url} after {self.max_retries + 1} attempts")

    async def get_json(self, url: str, **kwargs) -> dict | list:
        """GET and parse JSON response."""
        response = await self.get(url, **kwargs)
        return response.json()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def get_client(rate_limit: float = 1.0) -> BaseHTTPClient:
    """Create a new HTTP client with the given rate limit.

    Each tool gets its own client to avoid rate-limit contention across parallel tools.
    """
    return BaseHTTPClient(rate_limit=rate_limit)
