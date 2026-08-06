import pytest

from app.core.tracing import tracer


@pytest.mark.asyncio
async def test_create_and_end_trace():
    tid = await tracer.create_trace("user1", "test_action")
    assert tid is not None
    await tracer.end_trace(tid, status="success")
    trace = await tracer.get_trace(tid)
    assert trace["status"] == "success"
    assert trace["end_time"] is not None


@pytest.mark.asyncio
async def test_spans():
    tid = await tracer.create_trace("user1", "test")
    sid = await tracer.create_span(tid, "child_span")
    assert sid is not None
    await tracer.end_span(sid, {"result": "ok"})
    await tracer.end_trace(tid)
    trace = await tracer.get_trace(tid)
    assert len(trace["spans"]) == 1
    assert trace["spans"][0]["end_time"] is not None
    assert trace["spans"][0]["metadata"] == {"result": "ok"}


@pytest.mark.asyncio
async def test_list_traces():
    await tracer.create_trace("user1", "a")
    await tracer.create_trace("user2", "b")
    traces = await tracer.get_traces(limit=10)
    assert len(traces) >= 2
