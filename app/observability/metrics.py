"""
app.observability.metrics
~~~~~~~~~~~~~~~~~~~~~~~~~
Prometheus metric registry for the D5 gateway: HTTP request telemetry,
guardrail decision counters, and the D3 circuit-breaker state gauge.
"""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

HTTP_REQUESTS = Counter(
    "d5_http_requests_total",
    "HTTP requests served, by method, path and status",
    ["method", "path", "status"],
)

HTTP_REQUEST_DURATION = Histogram(
    "d5_http_request_duration_seconds",
    "HTTP request latency in seconds, by method and path",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

HTTP_INFLIGHT = Gauge(
    "d5_http_inflight_requests",
    "HTTP requests currently being processed",
)

GUARDRAIL_DECISIONS = Counter(
    "d5_guardrail_decisions_total",
    "Ingress guardrail decisions, by layer, outcome and code",
    ["layer", "decision", "code"],
)

# 0 = closed, 1 = half_open, 2 = open
D3_CIRCUIT_STATE = Gauge(
    "d5_d3_circuit_state",
    "D3 circuit breaker state: 0=closed, 1=half_open, 2=open",
)

_CIRCUIT_STATE_VALUE = {"closed": 0.0, "half_open": 1.0, "open": 2.0}


def set_circuit_state(state: str) -> None:
    D3_CIRCUIT_STATE.set(_CIRCUIT_STATE_VALUE.get(state, 0.0))
