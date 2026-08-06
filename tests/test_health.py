"""
Wave 2.2 — liveness / readiness probes.
"""
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.models import database


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


async def test_liveness_always_ok(client):
    resp = await client.get("/health/live")
    assert resp.status_code == 200
    assert resp.json()["status"] == "alive"


async def test_readiness_ok_when_db_reachable(client):
    resp = await client.get("/health/ready")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ready"


async def test_readiness_503_when_db_unreachable(client, monkeypatch):
    import app.main as main

    class _BrokenEngine:
        async def connect(self):
            raise ConnectionError("db down")

    monkeypatch.setattr(main, "engine", _BrokenEngine())
    resp = await client.get("/health/ready")
    assert resp.status_code == 503
    assert "unavailable" in resp.json()["detail"]


async def test_legacy_health_unchanged(client):
    resp = await client.get("/health")
    body = resp.json()
    assert body["status"] == "ok"
    assert "version" in body
