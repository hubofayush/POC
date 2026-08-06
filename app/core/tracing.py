"""
app.core.tracing
~~~~~~~~~~~~~~~~
Distributed Tracing Engine & Telemetry Spans.

Traces and spans are persisted to the database via TraceRepository so they
survive process restarts and can be queried by the API.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.repositories.trace_repository import trace_repository


class Span:
    def __init__(self, span_id: str, name: str, parent_span_id: str = ""):
        self.span_id = span_id
        self.name = name
        self.parent_span_id = parent_span_id
        self.start_time = datetime.now(UTC)
        self.end_time: datetime | None = None
        self.metadata: dict[str, Any] = {}

    def close(self, metadata: dict[str, Any] | None = None):
        self.end_time = datetime.now(UTC)
        if metadata:
            self.metadata = metadata

    def to_dict(self) -> dict[str, Any]:
        return {
            "span_id": self.span_id,
            "name": self.name,
            "parent_span_id": self.parent_span_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "metadata": self.metadata,
        }


def _trace_to_dict(trace) -> dict[str, Any]:
    spans = []
    if trace.spans_json:
        spans = json_loads(trace.spans_json)
    metadata = {}
    if trace.metadata_json:
        metadata = json_loads(trace.metadata_json)
    return {
        "trace_id": trace.trace_id,
        "user": trace.user_id,
        "org": trace.org,
        "action": trace.action,
        "input_preview": trace.input_preview,
        "start_time": _iso(trace.start_time),
        "end_time": _iso(trace.end_time) if trace.end_time else None,
        "status": trace.status,
        "metadata": metadata,
        "spans": spans,
    }


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.isoformat()


def json_loads(raw: str) -> Any:
    import json
    return json.loads(raw or "{}")


class Tracer:
    """Async facade over the persisted trace store."""

    async def create_trace(
        self,
        user: str,
        action: str,
        input_preview: str = "",
        trace_id: str | None = None,
        org: str = "unknown",
    ) -> str:
        tid = trace_id or str(uuid4())
        await trace_repository.create_trace(
            trace_id=tid,
            user_id=user,
            action=action,
            org=org,
            input_preview=input_preview,
        )
        return tid

    async def create_span(self, trace_id: str, name: str, parent_span_id: str = "") -> str:
        span = Span(str(uuid4()), name, parent_span_id)
        await trace_repository.add_span(trace_id, span.to_dict())
        return span.span_id

    async def end_span(self, span_id: str, metadata: dict[str, Any] | None = None):
        # Spans live on the trace row; find the owning trace (bounded scan of
        # recent traces — an index on span ids is needed at scale) and close
        # the span in place.
        for trace in await trace_repository.list_traces(limit=200):
            spans = json_loads(trace.spans_json) if trace.spans_json else []
            for span in spans:
                if span.get("span_id") == span_id:
                    span["end_time"] = datetime.now(UTC).isoformat()
                    if metadata:
                        span["metadata"] = metadata
                    await trace_repository.update_span(trace.trace_id, span)
                    return

    async def end_trace(self, trace_id: str, status: str = "success", metadata: dict[str, Any] | None = None):
        await trace_repository.end_trace(trace_id, status=status, metadata=metadata)

    async def get_traces(self, limit: int = 10, org: str | None = None) -> list[dict]:
        traces = await trace_repository.list_traces(limit=limit, org=org)
        return [_trace_to_dict(t) for t in traces]

    async def get_trace(self, trace_id: str) -> dict | None:
        trace = await trace_repository.get_trace(trace_id)
        return _trace_to_dict(trace) if trace else None


tracer = Tracer()
