"""Metrics — Prometheus-compatible metrics endpoint and decorators."""

from __future__ import annotations

import functools
import threading
import time
from typing import Any, Callable, Dict


# ── Simple counter/gauge for Prometheus text format ─────────────────

class _Counter:
    """Thread-safe counter."""
    def __init__(self, name: str, help_: str = ""):
        self.name = name
        self.help = help_
        self._value = 0
        self._lock = threading.Lock()

    def inc(self, n: int = 1):
        with self._lock:
            self._value += n

    def value(self) -> int:
        with self._lock:
            return self._value


class _Gauge:
    """Thread-safe gauge."""
    def __init__(self, name: str, help_: str = ""):
        self.name = name
        self.help = help_
        self._value = 0.0
        self._lock = threading.Lock()

    def set(self, v: float):
        with self._lock:
            self._value = v

    def value(self) -> float:
        with self._lock:
            return self._value


class _Histogram:
    """Simple histogram."""
    def __init__(self, name: str, help_: str = "", buckets=None):
        self.name = name
        self.help = help_
        self.buckets = buckets or [0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]
        self._values: list[float] = []
        self._lock = threading.Lock()

    def observe(self, v: float):
        with self._lock:
            self._values.append(v)

    def values(self) -> list[float]:
        with self._lock:
            return list(self._values)


# ── Core metrics ────────────────────────────────────────────────────

investigations_total = _Counter("watson_investigations_total", "Total investigations started")
findings_total = _Counter("watson_findings_total", "Total findings collected")
findings_confirmed = _Counter("watson_findings_confirmed", "Total confirmed findings")
investigation_duration = _Histogram("watson_investigation_duration_seconds",
                                     "Investigation duration in seconds")
api_requests_total = _Counter("watson_api_requests_total", "Total API requests")
api_errors_total = _Counter("watson_api_errors_total", "Total API errors")

_registered_metrics = [investigations_total, findings_total, findings_confirmed,
                       investigation_duration, api_requests_total, api_errors_total]


# ── Prometheus text output ──────────────────────────────────────────

def prometheus_endpoint() -> str:
    """Generate Prometheus-compatible metrics text."""
    lines: list[str] = []

    for metric in _registered_metrics:
        if isinstance(metric, (_Counter, _Gauge)):
            lines.append(f"# HELP {metric.name} {metric.help}")
            lines.append(f"# TYPE {metric.name} {'counter' if isinstance(metric, _Counter) else 'gauge'}")
            lines.append(f"{metric.name} {metric.value()}")

    # Add some system-level info
    import os
    import sys
    lines.append(f"# HELP watson_info Watson version info")
    lines.append(f"# TYPE watson_info gauge")
    lines.append(f'watson_info{{version="0.3.0",python="{sys.version.split()[0]}"}} 1')

    return "\n".join(lines) + "\n"


# ── Track investigation decorator ───────────────────────────────────

def track_investigation(func: Callable) -> Callable:
    """Decorator to count investigations and track duration."""
    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs):
        investigations_total.inc()
        start = time.monotonic()
        try:
            result = await func(*args, **kwargs)
            return result
        finally:
            investigation_duration.observe(time.monotonic() - start)

    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs):
        investigations_total.inc()
        start = time.monotonic()
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            investigation_duration.observe(time.monotonic() - start)

    import asyncio
    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    return sync_wrapper
