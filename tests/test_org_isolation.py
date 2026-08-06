"""
Tenant isolation tests: org scoping of audit/traces and context.org enforcement.
"""
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.audit import log_entry
from app.core.security.passwords import hash_password
from app.models.database import User, async_session


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


async def _make_user(username: str, role: str, org: str) -> None:
    async with async_session() as session:
        session.add(
            User(username=username, password_hash=hash_password("pass123"), role=role, org=org)
        )
        await session.commit()


async def _login(client, username: str, password: str = "pass123") -> str:
    resp = await client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_compliance_officer_only_sees_own_org_logs(client):
    from app.repositories.auth_repository import ensure_demo_users
    await ensure_demo_users()
    await _make_user("comp_other", "compliance_officer", "org_beta")

    await log_entry(user_id="admin_01", user_role="admin", action="org_scope_test", user_org="org_uma")
    await log_entry(user_id="comp_other", user_role="compliance_officer", action="org_scope_test", user_org="org_beta")

    token = await _login(client, "comp_01")
    # Even if the caller tries to filter for another org, the response is their org only
    resp = await client.get(
        "/audit/logs?action=org_scope_test&user_org=org_beta",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    entries = resp.json()["entries"]
    assert entries, "expected org_uma entries"
    assert all(e["user_org"] == "org_uma" for e in entries)

    stats = await client.get("/audit/stats", headers={"Authorization": f"Bearer {token}"})
    assert stats.status_code == 200
    scoped_total = stats.json()["total_entries"]
    assert scoped_total == 1, f"expected 1 org_uma entry, got {scoped_total}"


@pytest.mark.asyncio
async def test_admin_can_filter_any_org(client):
    from app.repositories.auth_repository import ensure_demo_users
    await ensure_demo_users()
    await _make_user("comp_other", "compliance_officer", "org_beta")
    await log_entry(user_id="comp_other", user_role="compliance_officer", action="cross_org_test", user_org="org_beta")

    token = await _login(client, "admin_01")
    resp = await client.get(
        "/audit/logs?action=cross_org_test",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    entries = resp.json()["entries"]
    assert any(e["user_org"] == "org_beta" for e in entries)


@pytest.mark.asyncio
async def test_invoke_rejects_cross_org_context(client):
    from app.repositories.auth_repository import ensure_demo_users
    await ensure_demo_users()
    token = await _login(client, "hr_01")
    resp = await client.post(
        "/invoke",
        headers={"Authorization": f"Bearer {token}"},
        json={"input": "Check nurse license", "context": {"org": "org_beta", "consent_granted": True}},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_invoke_accepts_matching_org_context(client):
    from app.repositories.auth_repository import ensure_demo_users
    await ensure_demo_users()
    token = await _login(client, "hr_01")
    resp = await client.post(
        "/invoke",
        headers={"Authorization": f"Bearer {token}"},
        json={"input": "Check nurse license", "context": {"org": "org_uma", "consent_granted": True}},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_traces_scoped_for_compliance(client):
    from app.repositories.auth_repository import ensure_demo_users
    from app.services.invoke import process_invoke
    from app.core.tracing import tracer

    await ensure_demo_users()
    await _make_user("comp_other", "compliance_officer", "org_beta")

    # create traces for two orgs
    await process_invoke(
        request=_InvokeRequestShim("Check license", {"consent_granted": True}),
        user={"sub": "hr_01", "role": "hr", "org": "org_uma"},
    )
    await process_invoke(
        request=_InvokeRequestShim("Check license", {"consent_granted": True}),
        user={"sub": "comp_other", "role": "compliance_officer", "org": "org_beta"},
    )

    token = await _login(client, "comp_01")
    resp = await client.get("/traces", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    traces = resp.json()["traces"]
    assert traces
    assert all(t["org"] == "org_uma" for t in traces)

    # compliance officer cannot read another org's trace by id
    other_trace = next(
        t for t in tracer.get_traces(limit=100) if t["org"] == "org_beta"
    )
    resp = await client.get(
        f"/traces/{other_trace['trace_id']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


class _InvokeRequestShim:
    """Minimal stand-in for InvokeRequest in service-level calls."""
    def __init__(self, input_text: str, context: dict):
        self.input = input_text
        self.context = context
        self.client_trace_id = None
