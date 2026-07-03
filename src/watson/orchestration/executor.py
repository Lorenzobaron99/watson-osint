"""Tool executor — retry wrappers, circuit breakers, graceful degradation."""

from __future__ import annotations
import asyncio
import logging
import time
from typing import Any, Callable

logger = logging.getLogger("watson.executor")

# ── Circuit breaker ───────────────────────────────────────────

class CircuitBreaker:
    """Prevent hammering a failing API."""
    
    def __init__(self, name: str, failure_threshold: int = 3, cooldown: float = 60.0):
        self.name = name
        self.failure_threshold = failure_threshold
        self.cooldown = cooldown
        self._failures = 0
        self._last_failure = 0.0
        self._open = False
    
    @property
    def is_open(self) -> bool:
        if not self._open:
            return False
        if time.time() - self._last_failure > self.cooldown:
            self._open = False
            self._failures = 0
            return False
        return True
    
    def record_failure(self):
        self._failures += 1
        self._last_failure = time.time()
        if self._failures >= self.failure_threshold:
            self._open = True
            logger.warning("circuit_breaker_open: %s", self.name)
    
    def record_success(self):
        self._failures = 0
        self._open = False


# Global circuit breakers
_circuits: dict[str, CircuitBreaker] = {}


def get_circuit(name: str) -> CircuitBreaker:
    if name not in _circuits:
        _circuits[name] = CircuitBreaker(name)
    return _circuits[name]


# ── Retry wrapper ─────────────────────────────────────────────

async def with_retry(
    fn: Callable,
    *args,
    tool_name: str = "unknown",
    max_retries: int = 2,
    backoff: float = 2.0,
    **kwargs,
) -> Any:
    """Call fn with retry + circuit breaker. Returns result or error finding."""
    circuit = get_circuit(tool_name)
    
    if circuit.is_open:
        return _error_finding(tool_name, "Circuit breaker open — API unavailable")
    
    last_error = None
    for attempt in range(max_retries + 1):
        try:
            result = await fn(*args, **kwargs) if asyncio.iscoroutinefunction(fn) else fn(*args, **kwargs)
            circuit.record_success()
            return result
        except Exception as e:
            last_error = e
            logger.warning("tool_attempt_failed: %s attempt %d: %s", tool_name, attempt + 1, e)
            if attempt < max_retries:
                await asyncio.sleep(backoff * (attempt + 1))
    
    circuit.record_failure()
    return _error_finding(tool_name, str(last_error)[:200])


def _error_finding(tool_name: str, error_msg: str) -> dict:
    """Return a structured error finding — NOT None, so the pipeline knows the tool ran."""
    return {
        "title": f"⚠️ {tool_name}: API error",
        "description": f"Tool '{tool_name}' failed: {error_msg}",
        "source_type": "error",
        "confidence": 0.0,
        "evidence": [],
    }
