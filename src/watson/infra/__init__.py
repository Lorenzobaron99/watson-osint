"""Infrastructure utilities — caching, retry, circuit breakers, rate limiting, resilience."""

from .retry import (
    retry,
    CircuitBreaker,
    CircuitOpenError,
    get_circuit,
    _is_retryable,
)
from .ratelimit import (
    TokenBucket,
    get_bucket,
    RateLimitExceeded,
)
from .cache import (
    TTLCache,
    get_cache,
)
from .resilience import (
    FailureReason,
    ToolResult,
    safe_execute,
    classify_failure,
    suggest_alternatives,
)

__all__ = [
    "retry",
    "CircuitBreaker",
    "CircuitOpenError",
    "get_circuit",
    "_is_retryable",
    "TokenBucket",
    "get_bucket",
    "RateLimitExceeded",
    "TTLCache",
    "get_cache",
    "FailureReason",
    "ToolResult",
    "safe_execute",
    "classify_failure",
    "suggest_alternatives",
]
