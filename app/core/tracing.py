"""
app.core.tracing
~~~~~~~~~~~~~~~~
Distributed Tracing Engine & Telemetry Spans.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


class Span:
    def __init__(self, span_id: str, name: str, parent_span_id: str = ""):
        self.span_id = span_id
        self.name = name
        self.parent_span_id = parent_span_id
        self.start_time = datetime.now(timezone.utc)
        self.end_time: datetime | None = None
        self.metadata: dict[str, Any] = {}

    def close(self, metadata: dict[str, Any] | None = None):
        self.end_time = datetime.now(timezone.utc)
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


class Tracer:
    def __init__(self):
        self._traces: dict[str, dict[str, Any]] = {}

    def create_trace(
        self,
        user: str,
        action: str,
        input_preview: str = "",
        trace_id: str | None = None,
        org: str = "unknown",
    ) -> str:
        tid = trace_id or str(uuid4())
        self._traces[tid] = {
            "trace_id": tid,
            "user": user,
            "org": org,
            "action": action,
            "input_preview": input_preview,
            "start_time": datetime.now(timezone.utc),
            "end_time": None,
            "spans": [],
            "status": "pending",
            "metadata": {},
        }
        return tid

    def create_span(self, trace_id: str, name: str, parent_span_id: str = "") -> str:
        span = Span(str(uuid4()), name, parent_span_id)
        trace = self._traces.get(trace_id)
        if trace:
            trace["spans"].append(span)
        return span.span_id

    def end_span(self, span_id: str, metadata: dict[str, Any] | None = None):
        for trace in self._traces.values():
            for span in trace["spans"]:
                if span.span_id == span_id:
                    span.close(metadata)
                    return

    def end_trace(self, trace_id: str, status: str = "success", metadata: dict[str, Any] | None = None):
        trace = self._traces.get(trace_id)
        if trace:
            trace["end_time"] = datetime.now(timezone.utc)
            trace["status"] = status
            if metadata:
                trace["metadata"] = metadata

    def _format_trace(self, trace: dict[str, Any]) -> dict[str, Any]:
        formatted = dict(trace)
        if isinstance(formatted.get("start_time"), datetime):
            formatted["start_time"] = formatted["start_time"].isoformat()
        if isinstance(formatted.get("end_time"), datetime):
            formatted["end_time"] = formatted["end_time"].isoformat()
        formatted["spans"] = [
            s.to_dict() if isinstance(s, Span) else s for s in formatted.get("spans", [])
        ]
        return formatted

    def get_traces(self, limit: int = 10, org: str | None = None) -> list[dict]:
        raw = list(self._traces.values())
        if org:
            raw = [t for t in raw if t.get("org") == org]
        return [self._format_trace(t) for t in raw[-limit:]]

    def get_trace(self, trace_id: str) -> dict | None:
        raw = self._traces.get(trace_id)
        return self._format_trace(raw) if raw else None


tracer = Tracer()
