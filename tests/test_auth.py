"""Auth tests: real user store (argon2), refresh rotation, reuse detection, lockout."""
from datetime import UTC

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.security.auth import TOKEN_AUDIENCE, TOKEN_ISSUER, create_token, decode_token
from app.main import app


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def seeded(client):
    """Ensure the four demo users exist in the DB (idempotent)."""
    from app.repositories.auth_repository import ensure_demo_users
    await ensure_demo_users()
    return True


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_login_success(client, seeded):
    resp = await client.post("/auth/login", json={"username": "admin_01", "password": "pass123"})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_failure(client, seeded):
    resp = await client.post("/auth/login", json={"username": "admin_01", "password": "wrong"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_unknown_user(client, seeded):
    resp = await client.post("/auth/login", json={"username": "ghost", "password": "x"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_locks_after_repeated_failures(client, seeded):
    for _ in range(5):
        await client.post("/auth/login", json={"username": "hr_01", "password": "bad"})
    resp = await client.post("/auth/login", json={"username": "hr_01", "password": "pass123"})
    assert resp.status_code == 401
    assert "lock" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_login_requires_username_and_password(client, seeded):
    resp = await client.post("/auth/login", json={"username": "admin_01"})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Token claims & decoding
# ---------------------------------------------------------------------------

def test_token_claims_include_iss_aud_jti():
    token = create_token("u1", "admin", "org_uma")
    payload = decode_token(token)
    assert payload["iss"] == TOKEN_ISSUER
    assert payload["aud"] == TOKEN_AUDIENCE
    assert payload["jti"]
    assert payload["sub"] == "u1"
    assert payload["role"] == "admin"
    assert payload["org"] == "org_uma"
    assert payload["type"] == "access"


def test_decode_rejects_wrong_audience():
    import jwt

    from app.core.security.auth import _load_private_key
    token = jwt.encode(
        {"sub": "u", "iss": TOKEN_ISSUER, "aud": "other-app", "exp": 9999999999},
        _load_private_key(), algorithm="RS256",
    )
    with pytest.raises(Exception):
        decode_token(token)


def test_expired_token_rejected():
    from datetime import datetime

    import jwt

    from app.core.security.auth import _load_private_key
    payload = {"sub": "u", "exp": datetime(2020, 1, 1, tzinfo=UTC),
               "iss": TOKEN_ISSUER, "aud": TOKEN_AUDIENCE}
    token = jwt.encode(payload, _load_private_key(), algorithm="RS256")
    with pytest.raises(Exception):
        decode_token(token)


# ---------------------------------------------------------------------------
# Refresh rotation & reuse detection
# ---------------------------------------------------------------------------

async def _login(client) -> dict:
    resp = await client.post("/auth/login", json={"username": "admin_01", "password": "pass123"})
    assert resp.status_code == 200
    return resp.json()


@pytest.mark.asyncio
async def test_refresh_rotates_tokens(client, seeded):
    tokens = await _login(client)
    resp = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 200
    new = resp.json()
    assert new["access_token"]
    assert new["refresh_token"] != tokens["refresh_token"]


@pytest.mark.asyncio
async def test_refresh_rejects_reused_rotated_token_and_revokes_family(client, seeded):
    tokens = await _login(client)
    old_refresh = tokens["refresh_token"]

    first = await client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert first.status_code == 200
    new_refresh = first.json()["refresh_token"]

    # Reusing the already-rotated token = token theft signal -> family revoked
    replay = await client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert replay.status_code == 401

    # The freshly issued token from the same family must also be dead
    replay_new = await client.post("/auth/refresh", json={"refresh_token": new_refresh})
    assert replay_new.status_code == 401


@pytest.mark.asyncio
async def test_refresh_rejects_access_token(client, seeded):
    tokens = await _login(client)
    resp = await client.post("/auth/refresh", json={"refresh_token": tokens["access_token"]})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_requires_body_param(client, seeded):
    tokens = await _login(client)
    resp = await client.post(f"/auth/refresh?refresh_token={tokens['refresh_token']}")
    assert resp.status_code == 422  # query-param usage must not work


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_logout_revokes_refresh_token(client, seeded):
    tokens = await _login(client)
    resp = await client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 200
    replay = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert replay.status_code == 401


# ---------------------------------------------------------------------------
# /auth/me
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_me_returns_claims(client, seeded):
    tokens = await _login(client)
    resp = await client.get(
        "/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert resp.status_code == 200
    assert resp.json()["sub"] == "admin_01"
    assert resp.json()["role"] == "admin"


@pytest.mark.asyncio
async def test_me_requires_auth(client, seeded):
    resp = await client.get("/auth/me")
    assert resp.status_code == 401
