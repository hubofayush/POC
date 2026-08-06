"""
app.middleware.http_metrics
~~~~~~~~~~~~~~~~~~~~~~~~~~~
ASGI middleware recording Prometheus HTTP telemetry: request counts by
method/path/status, latency histogram, and an in-flight gauge.

The /metrics endpoint itself is excluded from its own metrics so scrapes
do not inflate the counters.
"""
from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.observability import metrics


class HttpMetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/metrics":
            return await call_next(request)

        method = request.method
        path = request.url.path
        start = time.perf_counter()
        metrics.HTTP_INFLIGHT.inc()
        try:
            response = await call_next(request)
            status = response.status_code
        except Exception:
            status = 500
            raise
        finally:
            metrics.HTTP_INFLIGHT.dec()
            metrics.HTTP_REQUESTS.labels(
                method=method, path=path, status=str(status)
            ).inc()
            metrics.HTTP_REQUEST_DURATION.labels(
                method=method, path=path
            ).observe(time.perf_counter() - start)
        return response
