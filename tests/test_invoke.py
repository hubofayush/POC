import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


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
async def test_invoke_success(client, admin_token):
    resp = await client.post(
        "/invoke",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"input": "Check credentials", "context": {"clinician_id": "c1"}},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "output" in data
    assert "citations" in data
    assert data["metadata"]["phi_masked"] is True
    assert "audit_id" in data["metadata"]


@pytest.mark.asyncio
async def test_invoke_requires_auth(client):
    resp = await client.post("/invoke", json={"input": "test"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_invoke_expired_check(client, admin_token):
    resp = await client.post(
        "/invoke",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"input": "Is the nursing license expired?", "context": {}},
    )
    assert resp.status_code == 200
    assert "expired" in resp.json()["output"].lower()


@pytest.mark.asyncio
async def test_invoke_missing_check(client, admin_token):
    resp = await client.post(
        "/invoke",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"input": "What credentials are missing?", "context": {}},
    )
    assert resp.status_code == 200
    assert "missing" in resp.json()["output"].lower()