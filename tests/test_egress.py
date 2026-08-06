"""
Egress hardening: timeout, retry with backoff, and circuit breaker on the D3 client.
"""
import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import settings
from app.integrations.d3_client import CircuitOpenError, D3CallError, D3Client, D3ProviderError
from app.main import app


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


async def _admin_token(client) -> str:
    from app.repositories.auth_repository import ensure_demo_users
    await ensure_demo_users()
    resp = await client.post("/auth/login", json={"username": "admin_01", "password": "pass123"})
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_retry_then_success():
    calls = {"n": 0}

    async def flaky(trace_id, input, context):
        calls["n"] += 1
        if calls["n"] < 3:
            raise D3ProviderError("boom", retryable=True)
        return {"output": "ok", "citations": [], "tier": "cheap"}

    client = D3Client(provider=flaky)
    result = await client.call_invoke("t1", "x", {})
    assert result["output"] == "ok"
    assert calls["n"] == 3


@pytest.mark.asyncio
async def test_exhausted_retries_raise():
    async def always_fail(trace_id, input, context):
        raise D3ProviderError("down", retryable=True)

    client = D3Client(provider=always_fail)
    with pytest.raises(D3CallError):
        await client.call_invoke("t1", "x", {})
    assert client.breaker.failures == 1


@pytest.mark.asyncio
async def test_non_retryable_failure_no_retry():
    calls = {"n": 0}

    async def bad(trace_id, input, context):
        calls["n"] += 1
        raise D3ProviderError("permanent", retryable=False)

    client = D3Client(provider=bad)
    with pytest.raises(D3CallError):
        await client.call_invoke("t1", "x", {})
    assert calls["n"] == 1


@pytest.mark.asyncio
async def test_timeout_is_retried_and_raises():
    calls = {"n": 0}

    async def slow(trace_id, input, context):
        calls["n"] += 1
        await asyncio.sleep(5)
        return {"output": "late"}

    old_timeout = settings.D3_TIMEOUT_SEC
    settings.D3_TIMEOUT_SEC = 0.05
    try:
        client = D3Client(provider=slow)
        with pytest.raises(D3CallError):
            await client.call_invoke("t1", "x", {})
        assert calls["n"] == settings.D3_MAX_RETRIES + 1
    finally:
        settings.D3_TIMEOUT_SEC = old_timeout


@pytest.mark.asyncio
async def test_circuit_breaker_opens_and_short_circuits():
    calls = {"n": 0}

    async def always_fail(trace_id, input, context):
        calls["n"] += 1
        raise D3ProviderError("down", retryable=True)

    client = D3Client(provider=always_fail)
    for _ in range(settings.D3_CIRCUIT_FAILURE_THRESHOLD):
        with pytest.raises(D3CallError):
            await client.call_invoke("t1", "x", {})
    assert client.breaker.state == "open"
    calls["n"] = 0

    with pytest.raises(CircuitOpenError):
        await client.call_invoke("t1", "x", {})
    assert calls["n"] == 0  # provider never called while open


@pytest.mark.asyncio
async def test_half_open_probe_recovers():
    calls = {"n": 0}
    attempts_per_failure = settings.D3_MAX_RETRIES + 1
    fail_until = settings.D3_CIRCUIT_FAILURE_THRESHOLD * attempts_per_failure

    async def provider(trace_id, input, context):
        calls["n"] += 1
        if calls["n"] <= fail_until:
            raise D3ProviderError("down", retryable=True)
        return {"output": "recovered", "citations": [], "tier": "cheap"}

    old_reset = settings.D3_CIRCUIT_RESET_SEC
    settings.D3_CIRCUIT_RESET_SEC = 0.05
    try:
        client = D3Client(provider=provider)  # breaker captures 0.05s reset
        for _ in range(settings.D3_CIRCUIT_FAILURE_THRESHOLD):
            with pytest.raises(D3CallError):
                await client.call_invoke("t1", "x", {})
        assert client.breaker.state == "open"

        await asyncio.sleep(0.1)
        result = await client.call_invoke("t1", "x", {})
        assert result["output"] == "recovered"
        assert client.breaker.state == "closed"
    finally:
        settings.D3_CIRCUIT_RESET_SEC = old_reset


@pytest.mark.asyncio
async def test_invoke_returns_503_when_d3_down(client):
    import app.services.invoke as invoke_module

    async def down(trace_id, input, context):
        raise D3ProviderError("down", retryable=True)

    original = invoke_module.d3_client
    invoke_module.d3_client = D3Client(provider=down)
    try:
        token = await _admin_token(client)
        resp = await client.post(
            "/invoke",
            headers={"Authorization": f"Bearer {token}"},
            json={"input": "Check nurse license", "context": {"consent_granted": True}},
        )
        assert resp.status_code == 503
        assert "Downstream service unavailable" in resp.json()["detail"]
    finally:
        invoke_module.d3_client = original
