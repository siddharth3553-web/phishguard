"""Request-ID, body-size, and in-memory rate-limit middleware."""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict, deque
from threading import Lock

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from phishguard.core.config import Settings
from phishguard.core.metrics import LATENCY, REQUESTS

logger = logging.getLogger(__name__)

_EXEMPT_PREFIXES = ("/health", "/ready", "/metrics", "/version")


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        rid = request.headers.get("x-request-id") or str(uuid.uuid4())
        request.state.request_id = rid
        start = time.perf_counter()
        path = request.url.path
        try:
            response = await call_next(request)
        except Exception:
            logger.exception("unhandled error request_id=%s", rid)
            response = JSONResponse(
                {"detail": "internal error", "request_id": rid}, status_code=500
            )
        elapsed = time.perf_counter() - start
        route = path if path.startswith("/api/") or path in {
            "/health",
            "/ready",
            "/metrics",
            "/version",
            "/docs",
            "/redoc",
            "/openapi.json",
        } else "/other"
        REQUESTS.labels(request.method, route, str(response.status_code)).inc()
        LATENCY.labels(request.method, route).observe(elapsed)
        response.headers["X-Request-ID"] = rid
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_body_bytes: int) -> None:
        super().__init__(app)
        self.max_body_bytes = max_body_bytes

    async def dispatch(self, request: Request, call_next) -> Response:
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > self.max_body_bytes:
            return JSONResponse({"detail": "request body too large"}, status_code=413)
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window limiter per client IP (in-memory; fine for a single process)."""

    def __init__(self, app, requests_per_minute: int) -> None:
        super().__init__(app)
        self.limit = requests_per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path.startswith(_EXEMPT_PREFIXES):
            return await call_next(request)
        ip = _client_ip(request)
        now = time.time()
        window = 60.0
        with self._lock:
            q = self._hits[ip]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= self.limit:
                retry = max(1, int(window - (now - q[0])))
                return JSONResponse(
                    {"detail": "rate limit exceeded"},
                    status_code=429,
                    headers={"Retry-After": str(retry)},
                )
            q.append(now)
        return await call_next(request)


def apply_security_middleware(app, settings: Settings) -> None:
    app.add_middleware(BodySizeLimitMiddleware, max_body_bytes=settings.max_body_bytes)
    app.add_middleware(RateLimitMiddleware, requests_per_minute=settings.rate_limit_per_minute)
    app.add_middleware(RequestContextMiddleware)
