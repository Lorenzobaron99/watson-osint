"""Retry & circuit breaker infrastructure."""

from __future__ import annotations

import asyncio
import functools
import random
import threading
import time
from typing import Any, Callable, Dict, Tuple, Type


# ─────────────────────────────────────────────────────────────────
# Retryable exception classification
# ─────────────────────────────────────────────────────────────────

# TimeoutError, ConnectionError, ConnectionRefusedError, ConnectionResetError
# are all subclasses of OSError, so (OSError,) covers them all.
_RETRYABLE_EXCS: Tuple[Type[BaseException], ...] = (
    TimeoutError,
    ConnectionError,
    ConnectionRefusedError,
    ConnectionResetError,
    OSError,
)


def _is_retryable(exc: BaseException) -> bool:
    """Return True if *exc* is a transient/network failure worth retrying."""
    return isinstance(exc, _RETRYABLE_EXCS)


# ─────────────────────────────────────────────────────────────────
# Circuit breaker
# ─────────────────────────────────────────────────────────────────


class CircuitOpenError(Exception):
    """Raised when an operation is attempted on an open circuit."""

    def __init__(self, name: str = "", message: str = ""):
        self.name = name
        super().__init__(message or f"circuit '{name}' is open")


class CircuitBreaker:
    """Simple circuit breaker — opens after *failure_threshold* failures.

    States:
      * CLOSED  — normal operation, failures counted
      * OPEN    — requests short-circuit and raise :class:`CircuitOpenError`
      * HALF-OPEN — after *reset_timeout* elapses, one probe is allowed
    """

    def __init__(
        self,
        name: str = "",
        failure_threshold: int = 5,
        reset_timeout: float = 30.0,
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self._failures = 0
        self._last_failure: float = 0.0
        self._open_since: float = 0.0
        self._lock = threading.Lock()

    # -- state -----------------------------------------------------
    @property
    def is_open(self) -> bool:
        with self._lock:
            if self._failures < self.failure_threshold:
                return False
            # Half-open: allow a probe after reset_timeout
            if time.monotonic() - self._open_since > self.reset_timeout:
                return False
            return True

    # -- transitions -----------------------------------------------
    def success(self) -> None:
        with self._lock:
            self._failures = 0
            self._open_since = 0.0

    def failure(self) -> None:
        with self._lock:
            self._failures += 1
            self._last_failure = time.monotonic()
            if self._failures >= self.failure_threshold:
                self._open_since = time.monotonic()

    # -- context manager ------------------------------------------
    def __enter__(self) -> "CircuitBreaker":
        if self.is_open:
            raise CircuitOpenError(self.name)
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc is None:
            self.success()
        else:
            self.failure()
        return False  # never suppress


# Registry of named circuit breakers (singletons)
_circuits: Dict[str, CircuitBreaker] = {}
_circuits_lock = threading.Lock()


def get_circuit(name: str, **kwargs: Any) -> CircuitBreaker:
    """Get-or-create a singleton :class:`CircuitBreaker` by name."""
    with _circuits_lock:
        cb = _circuits.get(name)
        if cb is None:
            cb = CircuitBreaker(name=name, **kwargs)
            _circuits[name] = cb
        return cb


# ─────────────────────────────────────────────────────────────────
# Retry decorator
# ─────────────────────────────────────────────────────────────────


def retry(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    jitter: bool = True,
    exceptions: Tuple[Type[BaseException], ...] = (Exception,),
) -> Callable[[Callable], Callable]:
    """Retry a callable with exponential backoff.

    Only retryable exceptions (per :func:`_is_retryable`) are retried; any
    other exception is re-raised immediately without consuming an attempt.

    Works for both synchronous and ``async`` functions.
    """

    def decorator(func: Callable) -> Callable:
        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                last_exc: BaseException | None = None
                for attempt in range(max_attempts):
                    try:
                        return await func(*args, **kwargs)
                    except BaseException as e:  # noqa: BLE001
                        last_exc = e
                        if not _is_retryable(e):
                            raise
                        if attempt >= max_attempts - 1:
                            raise
                        delay = base_delay * (2 ** attempt)
                        if jitter:
                            delay = delay * random.uniform(0.5, 1.5)
                        await asyncio.sleep(delay)
                if last_exc is not None:  # pragma: no cover
                    raise last_exc

            return async_wrapper

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            last_exc: BaseException | None = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except BaseException as e:  # noqa: BLE001
                    last_exc = e
                    if not _is_retryable(e):
                        raise
                    if attempt >= max_attempts - 1:
                        raise
                    delay = base_delay * (2 ** attempt)
                    if jitter:
                        delay = delay * random.uniform(0.5, 1.5)
                    time.sleep(delay)
            if last_exc is not None:  # pragma: no cover
                raise last_exc

        return sync_wrapper

    return decorator
