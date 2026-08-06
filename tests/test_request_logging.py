"""
Wave 5.2 — structured access logging middleware.
"""
import re

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(record) -> str:
    return _ANSI.sub("", record.getMessage())


def _events(caplog, event: str):
    return [r for r in caplog.records if event in _plain(r)]


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


async def test_request_logged_with_status_and_latency(client, caplog):
    with caplog.at_level("INFO"):
        await client.post("/auth/login", json={"username": "nobody", "password": "x"})
    hits = _events(caplog, "http.request")
    assert len(hits) == 1
    text = _plain(hits[0])
    assert "method=POST" in text
    assert "/auth/login" in text
    assert "status=401" in text
    assert "latency_ms=" in text
    assert "client_ip=" in text


async def test_successful_invoke_logged(client, caplog):
    from app.repositories.auth_repository import ensure_demo_users

    await ensure_demo_users()
    with caplog.at_level("INFO"):
        login = await client.post(
            "/auth/login", json={"username": "admin_01", "password": "pass123"}
        )
        token = login.json()["access_token"]
        await client.post(
            "/invoke",
            json={"input": "verify credentials", "context": {"org": "org_uma", "consent_granted": True}},
            headers={"Authorization": f"Bearer {token}"},
        )
    statuses = [_plain(r) for r in _events(caplog, "http.request")]
    assert any("status=200" in s and "/invoke" in s for s in statuses)


async def test_metrics_and_health_excluded(client, caplog):
    with caplog.at_level("INFO"):
        await client.get("/metrics")
        await client.get("/health/live")
        await client.get("/health")
    assert _events(caplog, "http.request") == []


async def test_server_error_logged_as_error(caplog, monkeypatch):
    from app.repositories.auth_repository import ensure_demo_users
    from app.services import invoke as invoke_service

    await ensure_demo_users()

    class _Boom:
        async def call_invoke(self, trace_id, input, context):
            raise RuntimeError("boom")

    monkeypatch.setattr(invoke_service, "d3_client", _Boom())

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        with caplog.at_level("ERROR"):
            login = await ac.post(
                "/auth/login", json={"username": "admin_01", "password": "pass123"}
            )
            token = login.json()["access_token"]
            resp = await ac.post(
                "/invoke",
                json={"input": "verify credentials", "context": {"org": "org_uma", "consent_granted": True}},
                headers={"Authorization": f"Bearer {token}"},
            )
    assert resp.status_code == 500
    errors = _events(caplog, "http.request.error")
    assert any("/invoke" in _plain(e) for e in errors)
