"""
app.middleware.request_log
~~~~~~~~~~~~~~~~~~~~~~~~~~
Structured access logging for every HTTP request: method, path, status,
latency, client IP and user agent. /metrics and /health* probe paths are
excluded so scrapes and health checks do not pollute the access log.
"""
from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.core.logging import get_logger

logger = get_logger(__name__)

_EXCLUDED_PREFIXES = ("/metrics", "/health")


class RequestLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path.startswith(_EXCLUDED_PREFIXES):
            return await call_next(request)

        method = request.method
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")
        start = time.perf_counter()

        try:
            response = await call_next(request)
        except Exception:
            logger.error(
                "http.request.error",
                method=method,
                path=path,
                status=500,
                latency_ms=round((time.perf_counter() - start) * 1000, 2),
                client_ip=client_ip,
                user_agent=user_agent,
                msg="request raised unhandled exception",
            )
            raise

        status = response.status_code
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        if status >= 500:
            logger.error(
                "http.request.error",
                method=method,
                path=path,
                status=status,
                latency_ms=latency_ms,
                client_ip=client_ip,
                user_agent=user_agent,
                msg="request completed with server error",
            )
        else:
            logger.info(
                "http.request",
                method=method,
                path=path,
                status=status,
                latency_ms=latency_ms,
                client_ip=client_ip,
                user_agent=user_agent,
            )
        return response
