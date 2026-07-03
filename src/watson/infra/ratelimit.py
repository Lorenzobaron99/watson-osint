"""Token-bucket rate limiting."""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any, Dict, Optional


class RateLimitExceeded(Exception):
    """Raised when a rate-limited operation cannot acquire a token in time."""

    def __init__(self, name: str = "", message: str = ""):
        self.name = name
        super().__init__(message or f"rate limit exceeded for '{name}'")


class TokenBucket:
    """Classic token-bucket rate limiter.

    Tokens accumulate at *refill_rate* per second up to *capacity*. Each
    :meth:`acquire` consumes one token. ``acquire`` blocks up to *timeout*
    seconds waiting for a token to become available.
    """

    def __init__(
        self,
        name: str = "",
        capacity: float = 5,
        refill_rate: float = 1.0,
    ):
        self.name = name
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    # -- internals -------------------------------------------------
    def _refill(self) -> None:
        """Add tokens based on elapsed wall-clock time. Caller holds lock."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        if elapsed > 0 and self.refill_rate > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_rate)
        self._last_refill = now

    def _try_consume(self) -> bool:
        """Non-blocking consume. Caller must hold lock."""
        self._refill()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    # -- public API ------------------------------------------------
    def acquire(self, timeout: float = 0.0) -> bool:
        """Block up to *timeout* seconds for a token. Return True if acquired.

        A *timeout* of 0 means non-blocking: try once and return immediately.
        """
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                if self._try_consume():
                    return True
            if time.monotonic() >= deadline:
                return False
            # Sleep a short slice before retrying so we don't busy-spin hard.
            remaining = deadline - time.monotonic()
            time.sleep(max(0.0, min(0.005, remaining)))

    async def async_acquire(self, timeout: float = 0.0) -> bool:
        """Async variant of :meth:`acquire`."""
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                if self._try_consume():
                    return True
            if time.monotonic() >= deadline:
                return False
            remaining = deadline - time.monotonic()
            await asyncio.sleep(max(0.0, min(0.005, remaining)))

    # -- context manager ------------------------------------------
    def __enter__(self) -> "TokenBucket":
        if not self.acquire(timeout=0.0):
            raise RateLimitExceeded(self.name)
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False  # never suppress


# ─────────────────────────────────────────────────────────────────
# Pre-configured buckets
# ─────────────────────────────────────────────────────────────────

_PRECONFIGURED: Dict[str, Dict[str, Any]] = {
    "crt.sh": {"capacity": 3, "refill_rate": 1.0},
    "virustotal": {"capacity": 4, "refill_rate": 1.0},
    "shodan": {"capacity": 1, "refill_rate": 1.0},
}

_DEFAULT_CAPACITY = 5
_DEFAULT_REFILL_RATE = 1.0

_buckets: Dict[str, TokenBucket] = {}
_buckets_lock = threading.Lock()


def get_bucket(name: str) -> TokenBucket:
    """Get-or-create a singleton :class:`TokenBucket` for *name*."""
    with _buckets_lock:
        b = _buckets.get(name)
        if b is None:
            cfg = _PRECONFIGURED.get(name, {})
            b = TokenBucket(
                name=name,
                capacity=cfg.get("capacity", _DEFAULT_CAPACITY),
                refill_rate=cfg.get("refill_rate", _DEFAULT_REFILL_RATE),
            )
            _buckets[name] = b
        return b
