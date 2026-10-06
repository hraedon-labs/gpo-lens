"""Simple in-process rate limiting middleware.

State is held in-memory (per-process dict + threading.Lock).  In the deployed
single-worker uvicorn behind IIS this is sufficient.  If multiple workers are
ever used, each gets its own counters and the effective limit is multiplied —
a shared backend (SQLite, Redis) would be needed for cross-worker enforcement.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Awaitable, Callable

from fastapi import Request
from fastapi.responses import JSONResponse, Response

_EXEMPT_PATHS = frozenset({"/healthz", "/api/version"})
_EXEMPT_PREFIXES = ("/static/",)
_CLEANUP_INTERVAL = 128


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: float) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._lock = threading.Lock()
        self._requests: dict[str, list[float]] = {}
        self._check_count = 0

    def check(self, client_ip: str) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - self._window_seconds
        with self._lock:
            self._check_count += 1
            if self._check_count >= _CLEANUP_INTERVAL:
                self._evict_stale(cutoff)
                self._check_count = 0
            times = self._requests.get(client_ip)
            if times is None:
                self._requests[client_ip] = [now]
                return True, 0
            fresh = [t for t in times if t > cutoff]
            self._requests[client_ip] = fresh
            if len(fresh) >= self._max_requests:
                retry_after = int(fresh[0] + self._window_seconds - now) + 1
                return False, max(retry_after, 1)
            fresh.append(now)
            return True, 0

    def _evict_stale(self, cutoff: float) -> None:
        stale = [ip for ip, times in self._requests.items() if not times or times[-1] <= cutoff]
        for ip in stale:
            del self._requests[ip]


def make_rate_limit_middleware(
    ask_limiter: RateLimiter,
    ingest_limiter: RateLimiter,
    general_limiter: RateLimiter,
) -> Callable[[Request, Callable[[Request], Awaitable[Response]]], Awaitable[Response]]:
    async def _rate_limit(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if os.environ.get("GPO_LENS_DISABLE_RATE_LIMIT") == "1":
            return await call_next(request)
        path = request.url.path
        if path in _EXEMPT_PATHS or path.startswith(_EXEMPT_PREFIXES):
            return await call_next(request)
        client_ip = request.client.host if request.client else "unknown"
        if path in {"/ask", "/explain"}:
            limiter = ask_limiter
        elif path == "/ingest" and request.method == "POST":
            limiter = ingest_limiter
        else:
            limiter = general_limiter
        allowed, retry_after = limiter.check(client_ip)
        if not allowed:
            return JSONResponse(
                {"detail": "Rate limit exceeded"},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)

    return _rate_limit
