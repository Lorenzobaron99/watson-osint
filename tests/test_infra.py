"""
Unit tests: infra layer — retry, ratelimit, cache, resilience.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
import time
import threading
import asyncio
from unittest.mock import patch, MagicMock

from watson.infra.retry import retry, CircuitBreaker, CircuitOpenError, get_circuit, _is_retryable
from watson.infra.ratelimit import TokenBucket, get_bucket, RateLimitExceeded
from watson.infra.cache import TTLCache, get_cache
from watson.infra.resilience import (
    FailureReason, ToolResult, safe_execute, classify_failure, suggest_alternatives
)


# ═══════════════════════════════════════════════════════════════
# RETRY
# ═══════════════════════════════════════════════════════════════

class TestRetry:
    def test_retryable_exceptions(self):
        assert _is_retryable(TimeoutError())
        assert _is_retryable(ConnectionError())
        assert _is_retryable(ConnectionRefusedError())
        assert _is_retryable(ConnectionResetError())
        assert _is_retryable(OSError())
        assert not _is_retryable(ValueError("bad input"))
        assert not _is_retryable(KeyError("missing"))

    def test_retry_succeeds_first_attempt(self):
        call_count = [0]

        @retry(max_attempts=3, base_delay=0.01, jitter=False)
        def flaky():
            call_count[0] += 1
            return "ok"

        result = flaky()
        assert result == "ok"
        assert call_count[0] == 1

    def test_retry_eventually_succeeds(self):
        call_count = [0]

        @retry(max_attempts=3, base_delay=0.01, jitter=False)
        def flaky():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ConnectionError("transient")
            return "ok"

        result = flaky()
        assert result == "ok"
        assert call_count[0] == 3

    def test_retry_exhausted(self):
        @retry(max_attempts=2, base_delay=0.01, jitter=False)
        def always_fails():
            raise ConnectionError("always down")

        with pytest.raises(ConnectionError):
            always_fails()

    def test_retry_permanent_failure(self):
        call_count = [0]

        @retry(max_attempts=3, base_delay=0.01)
        def bad_input():
            call_count[0] += 1
            raise ValueError("permanent")

        with pytest.raises(ValueError):
            bad_input()
        assert call_count[0] == 1  # No retry on permanent

    def test_retry_async(self):
        call_count = [0]

        @retry(max_attempts=3, base_delay=0.01, jitter=False)
        async def flaky_async():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ConnectionError("transient")
            return "async_ok"

        result = asyncio.run(flaky_async())
        assert result == "async_ok"
        assert call_count[0] == 2


# ═══════════════════════════════════════════════════════════════
# CIRCUIT BREAKER
# ═══════════════════════════════════════════════════════════════

class TestCircuitBreaker:
    def test_starts_closed(self):
        cb = CircuitBreaker("test", failure_threshold=3)
        assert not cb.is_open

    def test_opens_after_threshold(self):
        cb = CircuitBreaker("test", failure_threshold=2, reset_timeout=60)
        cb.failure()
        assert not cb.is_open
        cb.failure()
        assert cb.is_open

    def test_resets_after_timeout(self):
        cb = CircuitBreaker("test", failure_threshold=2, reset_timeout=0.01)
        cb.failure()
        cb.failure()
        assert cb.is_open
        time.sleep(0.02)
        assert not cb.is_open

    def test_context_manager_success(self):
        cb = CircuitBreaker("test", failure_threshold=2)
        with cb:
            pass  # No exception = success
        assert not cb.is_open

    def test_context_manager_failure(self):
        cb = CircuitBreaker("test", failure_threshold=1)
        try:
            with cb:
                raise ConnectionError("fail")
        except ConnectionError:
            pass
        assert cb.is_open

    def test_context_manager_circuit_open(self):
        cb = CircuitBreaker("test", failure_threshold=1, reset_timeout=60)
        cb.failure()  # Open it
        with pytest.raises(CircuitOpenError):
            with cb:
                pass

    def test_get_circuit_singleton(self):
        c1 = get_circuit("singleton_test")
        c2 = get_circuit("singleton_test")
        assert c1 is c2


# ═══════════════════════════════════════════════════════════════
# RATE LIMITER
# ═══════════════════════════════════════════════════════════════

class TestRateLimiter:
    def test_acquire_within_capacity(self):
        b = TokenBucket("test", capacity=3, refill_rate=10)
        assert b.acquire(timeout=0.1)
        assert b.acquire(timeout=0.1)
        assert b.acquire(timeout=0.1)

    def test_acquire_exceeds_capacity(self):
        b = TokenBucket("test", capacity=1, refill_rate=0)  # Never refills
        assert b.acquire(timeout=0.1)
        assert not b.acquire(timeout=0.1)  # No tokens, no refill

    def test_refill_over_time(self):
        b = TokenBucket("test", capacity=2, refill_rate=100)  # 100 tokens/s
        b.acquire()  # 1 left
        b.acquire()  # 0 left
        time.sleep(0.02)  # ~2 tokens refilled
        assert b.acquire(timeout=0.1)

    def test_context_manager(self):
        b = TokenBucket("test", capacity=1, refill_rate=0)
        with b:
            pass
        with pytest.raises(RateLimitExceeded):
            with b:
                pass  # Timeout waiting for token

    def test_thread_safety(self):
        b = TokenBucket("test", capacity=100, refill_rate=1000)
        results = []
        barrier = threading.Barrier(10)

        def worker():
            barrier.wait()
            results.append(b.acquire(timeout=1.0))

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert all(results)

    def test_async_acquire(self):
        async def run():
            b = TokenBucket("test", capacity=1, refill_rate=100)
            assert await b.async_acquire(timeout=0.1)
            # Should refill quickly
            await asyncio.sleep(0.02)
            assert await b.async_acquire(timeout=0.1)

        asyncio.run(run())

    def test_get_bucket_preconfigured(self):
        b = get_bucket("crt.sh")
        assert b.capacity == 3
        assert b.refill_rate == 1.0

    def test_get_bucket_new(self):
        b = get_bucket("nonexistent_api")
        assert b.capacity == 5


# ═══════════════════════════════════════════════════════════════
# CACHE
# ═══════════════════════════════════════════════════════════════

class TestCache:
    def test_set_and_get(self):
        c = TTLCache("test", ttl=60)
        c.set("value", "key1")
        assert c.get("key1") == "value"

    def test_miss(self):
        c = TTLCache("test", ttl=60)
        assert c.get("nonexistent") is None

    def test_expiry(self):
        c = TTLCache("test", ttl=0.01)
        c.set("value", "key1")
        time.sleep(0.02)
        assert c.get("key1") is None

    def test_eviction(self):
        c = TTLCache("test", ttl=60, max_size=2)
        c.set("a", "1")
        c.set("b", "2")
        c.set("c", "3")  # Should evict oldest/least-hit
        assert c.stats["evictions"] >= 1
        # At least one of the original entries should be gone
        remaining = [c.get("1"), c.get("2"), c.get("3")]
        assert sum(1 for v in remaining if v is not None) <= 2

    def test_invalidate(self):
        c = TTLCache("test", ttl=60)
        c.set("value", "key1")
        c.invalidate("key1")
        assert c.get("key1") is None

    def test_hit_rate(self):
        c = TTLCache("test", ttl=60)
        assert c.hit_rate == 0.0
        c.get("miss")
        c.set("val", "key")
        c.get("key")
        c.get("key")
        assert c.hit_rate == 2/3

    def test_thread_safety(self):
        c = TTLCache("test", ttl=60, max_size=500)
        barrier = threading.Barrier(10)
        errors = []

        def worker(i):
            barrier.wait()
            try:
                c.set(f"val{i}", f"key{i}")
                _ = c.get(f"key{i}")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors

    def test_get_cache_preconfigured(self):
        c = get_cache("dns")
        assert c.ttl == 300
        assert c.max_size == 500


# ═══════════════════════════════════════════════════════════════
# RESILIENCE
# ═══════════════════════════════════════════════════════════════

class TestResilience:
    def test_safe_execute_success(self):
        result = safe_execute("test", lambda: "ok")
        assert result.success
        assert result.data == "ok"
        assert result.failure_reason is None

    def test_safe_execute_none_result(self):
        result = safe_execute("test", lambda: None, context="query")
        assert not result.success
        assert result.failure_reason == FailureReason.NO_RESULTS

    def test_safe_execute_empty_list(self):
        result = safe_execute("test", lambda: [])
        assert not result.success
        assert result.failure_reason == FailureReason.NO_RESULTS

    def test_safe_execute_exception(self):
        def raises():
            raise TimeoutError("timed out")

        result = safe_execute("whois", raises, context="test.com")
        assert not result.success
        assert result.failure_reason == FailureReason.TIMEOUT

    def test_classify_timeout(self):
        assert classify_failure(TimeoutError("timed out")) == FailureReason.TIMEOUT

    def test_classify_cloudflare(self):
        class FakeHTTPError(Exception):
            pass
        e = FakeHTTPError("cf-ray detected, attention required")
        # classify_failure checks message strings
        reason = classify_failure(e)
        # 'cloudflare' appears in message
        assert reason == FailureReason.CLOUDFLARE_PROTECTED

    def test_classify_rate_limit(self):
        class Fake429(Exception):
            code = 429
        assert classify_failure(Fake429()) == FailureReason.RATE_LIMITED

    def test_classify_whois_redacted(self):
        class FakeRedacted(Exception):
            pass
        e = FakeRedacted("GDPR redacted private registration")
        assert classify_failure(e) == FailureReason.WHOIS_REDACTED

    def test_tool_result_blocked(self):
        r = ToolResult(success=False, failure_reason=FailureReason.CLOUDFLARE_PROTECTED)
        assert r.blocked
        assert r.is_intelligence

    def test_tool_result_to_dict(self):
        r = ToolResult(success=True, data="test", latency_ms=42.0, retry_count=1)
        d = r.to_dict()
        assert d["success"] is True
        assert d["latency_ms"] == 42.0
        assert d["retry_count"] == 1

    def test_suggest_alternatives(self):
        alts = suggest_alternatives(FailureReason.WHOIS_REDACTED)
        assert len(alts) > 0
        assert any("crt.sh" in a for a in alts)

    def test_suggest_alternatives_unknown(self):
        alts = suggest_alternatives(FailureReason.UNKNOWN)
        assert len(alts) > 0


# ═══════════════════════════════════════════════════════════════
# CHAOS: Concurrent dispatch stress test
# ═══════════════════════════════════════════════════════════════

class TestChaos:
    def test_concurrent_token_bucket_stress(self):
        """100 threads hitting a small bucket — no crashes, correct limiting."""
        b = TokenBucket("stress", capacity=10, refill_rate=50)
        acquired = []
        barrier = threading.Barrier(50)

        def worker():
            barrier.wait()
            acquired.append(b.acquire(timeout=2.0))

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # At most ~10 should acquire immediately (capacity), more with refill
        assert sum(acquired) >= 10
        assert sum(acquired) <= 50

    def test_concurrent_cache_no_corruption(self):
        """Many threads reading/writing same cache — no data corruption."""
        c = TTLCache("stress", ttl=60, max_size=1000)
        barrier = threading.Barrier(20)
        errors = []

        def worker(i):
            barrier.wait()
            try:
                for j in range(100):
                    c.set(f"val-{i}-{j}", f"key-{i}-{j}")
                    v = c.get(f"key-{i}-{j}")
                    if v and v != f"val-{i}-{j}":
                        errors.append(f"corruption: {v} != val-{i}-{j}")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors

    def test_circuit_breaker_concurrent_trips(self):
        """Concurrent failures trip circuit breaker correctly."""
        cb = CircuitBreaker("chaos", failure_threshold=5, reset_timeout=60)
        barrier = threading.Barrier(10)
        tripped = []

        def worker():
            barrier.wait()
            if cb.is_open:
                tripped.append(True)
                return
            try:
                with cb:
                    raise ConnectionError("fail")
            except ConnectionError:
                pass

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Circuit should be open after 5 failures
        assert cb.is_open
        # Some threads should have seen the open circuit
        assert len(tripped) > 0
