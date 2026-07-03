"""Resilience layer — failure classification, safe execution, alternatives.

Wraps tool invocations so the orchestrator gets a uniform :class:`ToolResult`
regardless of whether a tool succeeded, returned nothing, or raised.
"""

from __future__ import annotations

import enum
import time
from typing import Any, Callable, List, Optional


class FailureReason(enum.Enum):
    """Why a tool invocation failed (or yielded no usable data)."""

    NO_RESULTS = "no_results"
    TIMEOUT = "timeout"
    CLOUDFLARE_PROTECTED = "cloudflare_protected"
    RATE_LIMITED = "rate_limited"
    WHOIS_REDACTED = "whois_redacted"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


# Reasons that indicate the target is actively blocking us — these are
# intelligence signals, not mere failures.
_BLOCK_REASONS = {
    FailureReason.CLOUDFLARE_PROTECTED,
    FailureReason.RATE_LIMITED,
    FailureReason.WHOIS_REDACTED,
    FailureReason.BLOCKED,
}


class ToolResult:
    """Uniform result wrapper for tool invocations."""

    __slots__ = (
        "tool",
        "success",
        "data",
        "failure_reason",
        "latency_ms",
        "retry_count",
        "context",
    )

    def __init__(
        self,
        success: bool,
        data: Any = None,
        failure_reason: Optional[FailureReason] = None,
        latency_ms: float = 0.0,
        retry_count: int = 0,
        tool: str = "",
        context: Any = None,
    ):
        self.tool = tool
        self.success = success
        self.data = data
        self.failure_reason = failure_reason
        self.latency_ms = latency_ms
        self.retry_count = retry_count
        self.context = context

    # -- derived properties ---------------------------------------
    @property
    def blocked(self) -> bool:
        """True when the failure reason indicates active blocking."""
        return self.failure_reason in _BLOCK_REASONS

    @property
    def is_intelligence(self) -> bool:
        """True when the outcome itself is an intelligence signal."""
        return self.failure_reason in _BLOCK_REASONS

    # -- serialization --------------------------------------------
    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "success": self.success,
            "data": self.data,
            "failure_reason": self.failure_reason.value if self.failure_reason else None,
            "latency_ms": self.latency_ms,
            "retry_count": self.retry_count,
            "context": self.context,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"ToolResult(success={self.success}, tool={self.tool!r}, "
            f"failure_reason={self.failure_reason}, latency_ms={self.latency_ms})"
        )


# ─────────────────────────────────────────────────────────────────
# Failure classification
# ─────────────────────────────────────────────────────────────────


def classify_failure(exc: BaseException) -> FailureReason:
    """Classify an exception into a :class:`FailureReason`."""
    # 1. Timeout
    if isinstance(exc, TimeoutError):
        return FailureReason.TIMEOUT

    # 2. HTTP-style rate limiting (objects exposing a status code)
    code = getattr(exc, "code", None)
    if code is None:
        code = getattr(exc, "status_code", None)
    if code == 429:
        return FailureReason.RATE_LIMITED

    msg = str(exc).lower()

    # 3. Cloudflare / WAF protection
    if "cloudflare" in msg or "cf-ray" in msg or "attention required" in msg:
        return FailureReason.CLOUDFLARE_PROTECTED

    # 4. WHOIS privacy / GDPR redaction
    if "redacted" in msg or "gdpr" in msg or "private registration" in msg:
        return FailureReason.WHOIS_REDACTED

    # 5. Generic network errors → could be transient; classify as unknown
    return FailureReason.UNKNOWN


# ─────────────────────────────────────────────────────────────────
# Safe execution
# ─────────────────────────────────────────────────────────────────


def safe_execute(
    tool: str,
    func: Callable[[], Any],
    context: Any = None,
    retry_count: int = 0,
) -> ToolResult:
    """Run *func* and return a :class:`ToolResult` capturing the outcome.

    A return value of ``None`` or an empty collection is treated as
    ``NO_RESULTS`` rather than success.
    """
    start = time.monotonic()
    try:
        data = func()
    except BaseException as exc:  # noqa: BLE001
        latency_ms = (time.monotonic() - start) * 1000.0
        reason = classify_failure(exc)
        return ToolResult(
            success=False,
            failure_reason=reason,
            latency_ms=latency_ms,
            retry_count=retry_count,
            tool=tool,
            context=context,
        )

    latency_ms = (time.monotonic() - start) * 1000.0

    # Treat None / empty containers as "no results"
    if data is None:
        return ToolResult(
            success=False,
            failure_reason=FailureReason.NO_RESULTS,
            latency_ms=latency_ms,
            retry_count=retry_count,
            tool=tool,
            context=context,
        )
    if isinstance(data, (list, tuple, set, dict, str)) and len(data) == 0:
        return ToolResult(
            success=False,
            failure_reason=FailureReason.NO_RESULTS,
            latency_ms=latency_ms,
            retry_count=retry_count,
            tool=tool,
            context=context,
        )

    return ToolResult(
        success=True,
        data=data,
        latency_ms=latency_ms,
        retry_count=retry_count,
        tool=tool,
        context=context,
    )


# ─────────────────────────────────────────────────────────────────
# Alternative-source suggestions
# ─────────────────────────────────────────────────────────────────

_ALTERNATIVES: dict = {
    FailureReason.WHOIS_REDACTED: [
        "crt.sh certificate transparency search",
        "DNS historical records (SecurityTrails)",
        "Search engine cached WHOIS",
        "Passive DNS replication",
    ],
    FailureReason.CLOUDFLARE_PROTECTED: [
        "Historical DNS records (SecurityTrails)",
        "crt.sh certificate transparency search",
        "Search engine cache / archive.org",
        "Shodan / Censys internet scan",
    ],
    FailureReason.RATE_LIMITED: [
        "Wait and retry with backoff",
        "Use an alternate data source",
        "Reduce request frequency",
    ],
    FailureReason.TIMEOUT: [
        "Retry with longer timeout",
        "Use an alternate data source",
        "crt.sh certificate transparency search",
    ],
    FailureReason.NO_RESULTS: [
        "Try alternate query / domain variant",
        "Use an alternate data source",
        "crt.sh certificate transparency search",
    ],
    FailureReason.BLOCKED: [
        "Historical DNS records",
        "crt.sh certificate transparency search",
        "archive.org",
    ],
    FailureReason.UNKNOWN: [
        "Retry the operation",
        "Use an alternate data source",
        "crt.sh certificate transparency search",
    ],
}


def suggest_alternatives(reason: FailureReason) -> List[str]:
    """Return a list of suggested alternative approaches for *reason*."""
    return list(_ALTERNATIVES.get(reason, _ALTERNATIVES[FailureReason.UNKNOWN]))
