"""
Enterprise middleware — auth, rate limiting, tracing, structured logging.

Loaded by watson.web.app on startup.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
import time
import uuid
from collections import defaultdict
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

# ── Structured JSON logging ─────────────────────────────────────

class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": _correlation_id.get(""),
            "module": record.module,
        }
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = str(record.exc_info[1])
        return json.dumps(log_entry)


def setup_logging(level: str = "INFO"):
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    # Silence noisy libs
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


# ── Correlation IDs ─────────────────────────────────────────────

_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")

def get_correlation_id() -> str:
    return _correlation_id.get() or ""

# ── API Key Auth ─────────────────────────────────────────────────

# Load valid keys from env: WATSON_API_KEYS=key1,key2
_VALID_KEYS: set[str] = set()
_raw = os.environ.get("WATSON_API_KEYS", "")
if _raw:
    _VALID_KEYS = {k.strip() for k in _raw.split(",") if k.strip()}

# Also accept the Hermes API key if configured
_hermes_key = os.environ.get("HERMES_API_KEY", "")
if _hermes_key:
    _VALID_KEYS.add(_hermes_key)

# Public endpoints — no auth required
_PUBLIC_PATHS = {"/", "/health", "/docs", "/openapi.json", "/redoc", "/static", "/api/settings"}

# Terminal endpoints — require auth AND elevated permission
_TERMINAL_PATHS = {"/api/agent/terminal"}

# Admin keys can access terminal
_ADMIN_KEYS: set[str] = set()
_raw_admin = os.environ.get("WATSON_ADMIN_KEYS", "")
if _raw_admin:
    _ADMIN_KEYS = {k.strip() for k in _raw_admin.split(",") if k.strip()}


def validate_api_key(key: str) -> bool:
    if not _VALID_KEYS:
        return True  # No keys configured — allow all (dev mode)
    return key in _VALID_KEYS


def validate_admin_key(key: str) -> bool:
    if not _ADMIN_KEYS:
        return False  # No admin keys — deny terminal
    return key in _ADMIN_KEYS


# ── Rate Limiting (token bucket per IP) ─────────────────────────

class TokenBucket:
    def __init__(self, rate: float = 10.0, burst: int = 20):
        self.rate = rate       # tokens per second
        self.burst = burst     # max bucket size
        self.tokens = float(burst)
        self.last_refill = time.monotonic()

    def consume(self, n: int = 1) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_refill = now
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False


_buckets: dict[str, TokenBucket] = {}
_bucket_lock = __import__('threading').Lock()

# Higher limits for investigation endpoints
_INVESTIGATE_RATE = float(os.environ.get("RATE_LIMIT_INVESTIGATE", "3"))    # 3/sec
_CHAT_RATE = float(os.environ.get("RATE_LIMIT_CHAT", "10"))                 # 10/sec
_DEFAULT_RATE = float(os.environ.get("RATE_LIMIT_DEFAULT", "30"))           # 30/sec


def _get_rate_for_path(path: str) -> float:
    if "investigate" in path:
        return _INVESTIGATE_RATE
    if "chat" in path:
        return _CHAT_RATE
    return _DEFAULT_RATE


def check_rate_limit(ip: str, path: str) -> tuple[bool, dict]:
    """Returns (allowed, headers_dict)."""
    with _bucket_lock:
        if ip not in _buckets:
            _buckets[ip] = TokenBucket(rate=_DEFAULT_RATE)
        bucket = _buckets[ip]
        # Adjust rate if needed
        target_rate = _get_rate_for_path(path)
        if bucket.rate != target_rate:
            bucket.rate = target_rate

        allowed = bucket.consume()
        remaining = int(bucket.tokens)
        headers = {
            "X-RateLimit-Limit": str(int(bucket.burst)),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(int(time.time() + remaining / bucket.rate)),
        }
        return allowed, headers

# Cleanup old buckets periodically
_last_cleanup = time.monotonic()

def _cleanup_buckets():
    global _last_cleanup
    now = time.monotonic()
    if now - _last_cleanup < 300:  # Every 5 minutes
        return
    _last_cleanup = now
    with _bucket_lock:
        stale = [ip for ip, b in _buckets.items() if now - b.last_refill > 600]
        for ip in stale:
            del _buckets[ip]


# ── Combined Middleware ──────────────────────────────────────────

class EnterpriseMiddleware(BaseHTTPMiddleware):
    """Auth + rate limiting + tracing + logging in one pass."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        corr_id = request.headers.get("X-Correlation-ID") or uuid.uuid4().hex[:12]
        _correlation_id.set(corr_id)
        
        start_time = time.monotonic()
        ip = request.client.host if request.client else "unknown"
        path = request.url.path
        
        _cleanup_buckets()

        # 1. Rate limit
        allowed, rl_headers = check_rate_limit(ip, path)
        if not allowed:
            return JSONResponse(
                {"error": "Rate limit exceeded", "retry_after": rl_headers["X-RateLimit-Reset"]},
                status_code=429,
                headers=rl_headers,
            )

        # 2. Auth (skip public paths)
        if path not in _PUBLIC_PATHS and not path.startswith("/static"):
            auth_header = request.headers.get("Authorization", "")
            api_key = ""
            if auth_header.startswith("Bearer "):
                api_key = auth_header[7:]
            elif auth_header.startswith("ApiKey "):
                api_key = auth_header[7:]

            if not validate_api_key(api_key):
                logging.getLogger("watson").warning(
                    "auth_denied", extra={"ip": ip, "path": path}
                )
                return JSONResponse(
                    {"error": "Unauthorized — provide API key via Bearer token"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Elevated: terminal requires admin key
            if path in _TERMINAL_PATHS and not validate_admin_key(api_key):
                return JSONResponse(
                    {"error": "Forbidden — admin key required for terminal access"},
                    status_code=403,
                )

        # 3. Process request
        try:
            response = await call_next(request)
        except Exception as e:
            logging.getLogger("watson").error(
                "request_failed",
                extra={"path": path, "method": request.method, "error": str(e)},
                exc_info=True,
            )
            return JSONResponse(
                {"error": "Internal server error", "correlation_id": corr_id},
                status_code=500,
            )

        # 4. Add response headers
        duration_ms = int((time.monotonic() - start_time) * 1000)
        response.headers["X-Correlation-ID"] = corr_id
        response.headers["X-Response-Time-Ms"] = str(duration_ms)
        for k, v in rl_headers.items():
            response.headers[k] = v

        # 5. Structured access log
        logging.getLogger("watson").info(
            "request",
            extra={
                "method": request.method,
                "path": path,
                "status": response.status_code,
                "duration_ms": duration_ms,
                "ip": ip,
            },
        )

        return response


# ── Graceful shutdown ────────────────────────────────────────────

import asyncio

_active_tasks: set[asyncio.Task] = set()

def register_task(task: asyncio.Task):
    """Track a background task for graceful shutdown."""
    _active_tasks.add(task)
    task.add_done_callback(_active_tasks.discard)

async def shutdown_tasks(timeout: float = 10.0):
    """Cancel all tracked tasks on shutdown."""
    logger = logging.getLogger("watson")
    logger.info("shutting_down", extra={"pending_tasks": len(_active_tasks)})
    for task in list(_active_tasks):
        task.cancel()
    if _active_tasks:
        done, pending = await asyncio.wait(_active_tasks, timeout=timeout)
        if pending:
            logger.warning("tasks_did_not_finish", extra={"count": len(pending)})


# ── Startup ──────────────────────────────────────────────────────

def init_app(app):
    """Wire enterprise middleware into FastAPI app."""
    setup_logging(os.environ.get("LOG_LEVEL", "INFO"))
    app.add_middleware(EnterpriseMiddleware)
    
    # Register shutdown handler
    @app.on_event("shutdown")
    async def on_shutdown():
        await shutdown_tasks()

    logger = logging.getLogger("watson")
    logger.info("enterprise_middleware_initialized", extra={
        "auth_enabled": bool(_VALID_KEYS),
        "admin_keys_configured": bool(_ADMIN_KEYS),
        "rate_limit_investigate": _INVESTIGATE_RATE,
        "rate_limit_chat": _CHAT_RATE,
        "rate_limit_default": _DEFAULT_RATE,
    })
