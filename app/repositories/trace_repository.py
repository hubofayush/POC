"""
app.repositories.trace_repository
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Persistence for distributed traces (spans embedded as JSON on the trace row).
"""
from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import desc, select

from app.models.database import Trace, async_session


class TraceRepository:
    async def create_trace(
        self,
        trace_id: str,
        user_id: str,
        action: str,
        org: str,
        input_preview: str = "",
    ) -> None:
        async with async_session() as session:
            session.add(
                Trace(
                    trace_id=trace_id,
                    user_id=user_id,
                    org=org,
                    action=action,
                    input_preview=input_preview,
                    start_time=datetime.now(UTC),
                )
            )
            await session.commit()

    async def add_span(
        self,
        trace_id: str,
        span: dict[str, Any],
    ) -> None:
        """Append a serialized span to the trace's JSON span list."""
        async with async_session() as session:
            trace = await session.get(Trace, trace_id)
            if trace is None:
                return
            spans = json.loads(trace.spans_json or "[]")
            spans.append(span)
            trace.spans_json = json.dumps(spans)
            await session.commit()

    async def update_span(
        self,
        trace_id: str,
        span: dict[str, Any],
    ) -> None:
        """Replace a span (matched by span_id) in the trace's JSON span list."""
        async with async_session() as session:
            trace = await session.get(Trace, trace_id)
            if trace is None:
                return
            spans = json.loads(trace.spans_json or "[]")
            for i, existing in enumerate(spans):
                if existing.get("span_id") == span.get("span_id"):
                    spans[i] = span
                    break
            trace.spans_json = json.dumps(spans)
            await session.commit()

    async def end_trace(
        self,
        trace_id: str,
        status: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        async with async_session() as session:
            trace = await session.get(Trace, trace_id)
            if trace is None:
                return
            trace.status = status
            trace.end_time = datetime.now(UTC)
            trace.metadata_json = json.dumps(metadata or {})
            await session.commit()

    async def list_traces(self, limit: int = 10, org: str | None = None) -> Sequence[Trace]:
        async with async_session() as session:
            stmt = select(Trace)
            if org:
                stmt = stmt.where(Trace.org == org)
            stmt = stmt.order_by(desc(Trace.start_time)).limit(limit)
            return (await session.execute(stmt)).scalars().all()

    async def get_trace(self, trace_id: str) -> Trace | None:
        async with async_session() as session:
            return await session.get(Trace, trace_id)


trace_repository = TraceRepository()
