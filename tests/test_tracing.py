from app.core.tracing import tracer


def test_create_and_end_trace():
    tid = tracer.create_trace("user1", "test_action")
    assert tid is not None
    tracer.end_trace(tid, status="success")
    trace = tracer.get_trace(tid)
    assert trace["status"] == "success"
    assert trace["end_time"] is not None


def test_spans():
    tid = tracer.create_trace("user1", "test")
    sid = tracer.create_span(tid, "child_span")
    assert sid is not None
    tracer.end_span(sid, {"result": "ok"})
    tracer.end_trace(tid)
    trace = tracer.get_trace(tid)
    assert len(trace["spans"]) == 1


def test_list_traces():
    tracer.create_trace("user1", "a")
    tracer.create_trace("user2", "b")
    traces = tracer.get_traces(limit=10)
    assert len(traces) >= 2