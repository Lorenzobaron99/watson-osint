"""Auth middleware — API key validation, workspace auth.

Delegates to watson.web.middleware for actual API key checking.
"""

from __future__ import annotations

import os
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class AuthMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware: validate API keys from X-API-Key or Authorization header.

    Delegates to watson.web.middleware.validate_api_key() when available,
    falling back to WATSON_API_KEYS env var check.
    """

    _PUBLIC_PATHS: set[str] = {"/", "/health", "/docs", "/openapi.json", "/redoc",
                                "/static", "/api/settings", "/api/agent/detect-intent"}

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Allow public paths
        if path in self._PUBLIC_PATHS or path.startswith("/static"):
            return await call_next(request)

        # Extract API key
        api_key = request.headers.get("X-API-Key", "")
        if not api_key:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                api_key = auth_header[7:]

        # Validate
        valid = self._validate(api_key)
        if not valid:
            return JSONResponse(
                {"error": "Unauthorized — provide API key via X-API-Key or Bearer token"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        return await call_next(request)

    @staticmethod
    def _validate(api_key: str) -> bool:
        # Try delegating to existing watson.web.middleware
        try:
            from watson.web.middleware import validate_api_key
            return validate_api_key(api_key)
        except ImportError:
            pass

        # Fallback: check env
        valid_keys_raw = os.environ.get("WATSON_API_KEYS", "")
        if not valid_keys_raw:
            return True  # Dev mode — no keys configured
        valid_keys = {k.strip() for k in valid_keys_raw.split(",") if k.strip()}
        hermes_key = os.environ.get("HERMES_API_KEY", "")
        if hermes_key:
            valid_keys.add(hermes_key)
        return api_key in valid_keys
