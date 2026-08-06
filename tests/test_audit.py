"""
tests/test_audit.py
~~~~~~~~~~~~~~~~~~~
Unit & integration tests for Production-Grade Audit System (SOC2 / HIPAA Standard).
"""
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.audit import log_entry, query_entries, get_stats


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def admin_token(client):
    from app.repositories.auth_repository import ensure_demo_users
    await ensure_demo_users()
    resp = await client.post("/auth/login", json={"username": "admin_01", "password": "pass123"})
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_log_and_query_rich_forensics():
    eid = await log_entry(
        user_id="user1",
        user_role="admin",
        action="test_action",
        user_org="org_test",
        client_ip="192.168.1.50",
        user_agent="PytestAgent/1.0",
        latency_ms=12.5,
        input_bytes=256,
        guardrail_code="PROMPT_INJECTION_DETECTED",
        guardrail_layer="ingress.layer2.prompt_injection",
        resource_id="res_1",
    )
    entries = await query_entries(user_id="user1", client_ip="192.168.1.50")
    assert len(entries) >= 1
    target = entries[0]
    assert target.entry_id == eid
    assert target.user_org == "org_test"
    assert target.client_ip == "192.168.1.50"
    assert target.user_agent == "PytestAgent/1.0"
    assert target.latency_ms == 12.5
    assert target.guardrail_code == "PROMPT_INJECTION_DETECTED"
    assert len(target.entry_hash) == 64  # SHA-256 hash length


@pytest.mark.asyncio
async def test_get_stats():
    stats = await get_stats()
    assert "total_entries" in stats
    assert "avg_latency_ms" in stats
    assert "blocked_guardrails" in stats


@pytest.mark.asyncio
async def test_audit_endpoint(client, admin_token):
    resp = await client.get("/audit/logs", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "entries" in data


@pytest.mark.asyncio
async def test_audit_forbidden(client):
    from app.repositories.auth_repository import ensure_demo_users
    await ensure_demo_users()
    resp = await client.post("/auth/login", json={"username": "clinician_01", "password": "pass123"})
    token = resp.json()["access_token"]
    resp = await client.get("/audit/logs", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403