import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.security.auth import create_token, decode_token


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_login_success(client):
    resp = await client.post("/auth/login", json={"user_id": "admin_01", "password": "pass123"})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data


@pytest.mark.asyncio
async def test_login_failure(client):
    resp = await client.post("/auth/login", json={"user_id": "admin_01", "password": "wrong"})
    assert resp.status_code == 401


def test_create_and_decode_token():
    token = create_token("test_user", "admin", "org_uma")
    payload = decode_token(token)
    assert payload["sub"] == "test_user"
    assert payload["role"] == "admin"
    assert payload["org"] == "org_uma"


def test_expired_token():
    from datetime import datetime, timezone, timedelta
    import jwt
    from app.core.security.auth import _load_private_key
    payload = {"sub": "u", "exp": datetime(2020, 1, 1, tzinfo=timezone.utc)}
    token = jwt.encode(payload, _load_private_key(), algorithm="RS256")
    with pytest.raises(Exception):
        decode_token(token)