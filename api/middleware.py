"""
IMMUNEX API Middleware
=======================
Production-grade FastAPI middleware:
  - Request/response logging
  - Response timing
  - Rate limiting (in-process token bucket)
  - Centralized exception handling
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict
from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from utils.logger import log


# ─── Timing + Logging Middleware ──────────────────────────────────────────────

class LoggingTimingMiddleware(BaseHTTPMiddleware):
    """Logs every request with method, path, status, and latency."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = uuid.uuid4().hex[:8]
        t0 = time.perf_counter()

        log.debug(
            "API request",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client=request.client.host if request.client else "unknown",
        )

        try:
            response = await call_next(request)
        except Exception as exc:
            log.error(
                "Unhandled API exception",
                request_id=request_id,
                path=request.url.path,
                exc_info=exc,
            )
            return JSONResponse(
                status_code=500,
                content={
                    "error":   "Internal server error",
                    "detail":  str(exc),
                    "code":    500,
                    "path":    request.url.path,
                },
            )

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        response.headers["X-Request-ID"]    = request_id
        response.headers["X-Response-Time"] = f"{elapsed_ms}ms"

        log.info(
            "API response",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            latency_ms=elapsed_ms,
        )
        return response


# ─── Rate Limiter ─────────────────────────────────────────────────────────────

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple in-process token-bucket rate limiter.
    Limits per client IP: default 60 requests/minute.
    Heavy endpoints (/retrain) are limited to 5 requests/minute.
    """

    _HEAVY_PATHS = {"/retrain"}
    _DEFAULT_RATE  = 60   # requests per window
    _HEAVY_RATE    = 5
    _WINDOW_SECONDS = 60

    def __init__(self, app, default_rate: int = 60, heavy_rate: int = 5) -> None:
        super().__init__(app)
        self._default_rate = default_rate
        self._heavy_rate   = heavy_rate
        # {ip: {window_start: float, count: int}}
        self._buckets: dict[str, dict] = defaultdict(
            lambda: {"window_start": time.time(), "count": 0}
        )

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "0.0.0.0"
        path = request.url.path

        limit = self._heavy_rate if path in self._HEAVY_PATHS else self._default_rate
        bucket = self._buckets[f"{client_ip}:{path}"]

        now = time.time()
        if now - bucket["window_start"] > self._WINDOW_SECONDS:
            bucket["window_start"] = now
            bucket["count"]        = 0

        bucket["count"] += 1
        if bucket["count"] > limit:
            log.warning(
                "Rate limit exceeded",
                client=client_ip,
                path=path,
                count=bucket["count"],
                limit=limit,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error":  "Rate limit exceeded",
                    "detail": f"Max {limit} requests per {self._WINDOW_SECONDS}s window",
                    "code":   429,
                    "path":   path,
                },
                headers={"Retry-After": str(self._WINDOW_SECONDS)},
            )

        return await call_next(request)
