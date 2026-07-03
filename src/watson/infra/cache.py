"""TTL cache with size-bounded LRU eviction and stats.

Also exposes a small registry/helpers for aggregating cache statistics.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional


class _Entry:
    __slots__ = ("value", "expiry", "hits", "inserted_at")

    def __init__(self, value: Any, expiry: float, now: float):
        self.value = value
        self.expiry = expiry
        self.hits = 0
        self.inserted_at = now


class TTLCache:
    """In-memory TTL cache with max-size eviction.

    Note: :meth:`set` takes ``(value, key)`` — value first, key second —
    matching the project's OSINT-collection ergonomics.
    """

    def __init__(self, name: str, ttl: float = 60.0, max_size: int = 1000):
        self.name = name
        self.ttl = float(ttl)
        self.max_size = int(max_size)
        self._data: Dict[str, _Entry] = {}
        self._lock = threading.Lock()
        self.stats: Dict[str, Any] = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "size": 0,
        }

    # -- core operations ------------------------------------------
    def set(self, value: Any, key: str) -> None:
        """Store *value* under *key* with the configured TTL."""
        now = time.monotonic()
        with self._lock:
            if key in self._data:
                # Update in place, keep hit count
                entry = self._data[key]
                entry.value = value
                entry.expiry = now + self.ttl
            else:
                self._data[key] = _Entry(value, now + self.ttl, now)
                if len(self._data) > self.max_size:
                    self._evict()
            self.stats["size"] = len(self._data)

    def get(self, key: str) -> Any:
        """Return the value for *key* or ``None`` on miss/expiry."""
        now = time.monotonic()
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                self.stats["misses"] += 1
                return None
            if now >= entry.expiry:
                # Expired — remove and count as miss
                del self._data[key]
                self.stats["misses"] += 1
                self.stats["size"] = len(self._data)
                return None
            entry.hits += 1
            self.stats["hits"] += 1
            return entry.value

    def invalidate(self, key: str) -> None:
        """Remove *key* from the cache if present."""
        with self._lock:
            if key in self._data:
                del self._data[key]
                self.stats["size"] = len(self._data)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
            self.stats["size"] = 0

    # -- eviction --------------------------------------------------
    def _evict(self) -> None:
        """Evict the least-hit (oldest on tie) entry. Caller holds lock."""
        if not self._data:
            return
        # Find entry with fewest hits; ties broken by insertion order (oldest first)
        victim_key = None
        victim_hits = None
        for k, entry in self._data.items():
            if victim_key is None or entry.hits < victim_hits:
                victim_key = k
                victim_hits = entry.hits
        if victim_key is not None:
            del self._data[victim_key]
            self.stats["evictions"] += 1

    # -- derived metrics ------------------------------------------
    @property
    def hit_rate(self) -> float:
        total = self.stats["hits"] + self.stats["misses"]
        if total == 0:
            return 0.0
        return self.stats["hits"] / total


# ─────────────────────────────────────────────────────────────────
# Pre-configured caches
# ─────────────────────────────────────────────────────────────────

_PRECONFIGURED: Dict[str, Dict[str, Any]] = {
    "dns": {"ttl": 300, "max_size": 500},
    "whois": {"ttl": 3600, "max_size": 500},
    "cert": {"ttl": 600, "max_size": 1000},
    "default": {"ttl": 60, "max_size": 1000},
}

_caches: Dict[str, TTLCache] = {}
_caches_lock = threading.Lock()


def get_cache(name: str) -> TTLCache:
    """Get-or-create a singleton :class:`TTLCache` for *name*."""
    with _caches_lock:
        c = _caches.get(name)
        if c is None:
            cfg = _PRECONFIGURED.get(name, _PRECONFIGURED["default"])
            c = TTLCache(
                name=name,
                ttl=cfg.get("ttl", 60),
                max_size=cfg.get("max_size", 1000),
            )
            _caches[name] = c
        return c


# ─────────────────────────────────────────────────────────────────
# Stats aggregation (legacy helpers)
# ─────────────────────────────────────────────────────────────────

_cache_registry: Dict[str, Any] = {}


def register_cache(name: str, cache_obj: Any) -> None:
    """Register a cache for stats collection."""
    _cache_registry[name] = cache_obj


def all_cache_stats() -> Dict[str, Dict[str, Any]]:
    """Return stats for all registered caches."""
    stats: Dict[str, Dict[str, Any]] = {}
    for name, cache in _cache_registry.items():
        s = getattr(cache, "stats", None)
        if isinstance(s, dict):
            stats[name] = dict(s)
        elif callable(s):
            stats[name] = s()
        elif hasattr(cache, "get_stats"):
            stats[name] = cache.get_stats()
        else:
            stats[name] = {"size": 0, "hits": 0, "misses": 0}
    if not stats:
        stats["default"] = {"size": 0, "hits": 0, "misses": 0}
    return stats
