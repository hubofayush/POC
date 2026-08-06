"""
Tamper-evident audit hash chaining: chain continuity and tamper detection.
"""
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import text

from app.main import app
from app.core.audit import log_entry, verify_chain
from app.models.database import async_session


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


async def _seed_entries(n: int = 3) -> list[str]:
    ids = []
    for i in range(n):
        ids.append(
            await log_entry(
                user_id=f"u{i}",
                user_role="hr",
                action="invoke",
                user_org="org_uma",
                details=f"seed-{i}",
            )
        )
    return ids


@pytest.mark.asyncio
async def test_empty_log_chain_is_valid():
    report = await verify_chain()
    assert report == {"valid": True, "entries_checked": 0, "first_broken_entry_id": None}


@pytest.mark.asyncio
async def test_chain_links_entries_consecutively():
    await _seed_entries(4)
    report = await verify_chain()
    assert report["valid"] is True
    assert report["entries_checked"] == 4
    assert report["first_broken_entry_id"] is None


@pytest.mark.asyncio
async def test_tampered_entry_breaks_chain():
    await _seed_entries(3)
    async with async_session() as session:
        await session.execute(text("UPDATE audit_log SET details='tampered' WHERE details='seed-1'"))
        await session.commit()

    report = await verify_chain()
    assert report["valid"] is False
    assert report["entries_checked"] == 3
    broken = report["first_broken_entry_id"]
    assert broken is not None

    async with async_session() as session:
        result = await session.execute(
            text("SELECT details FROM audit_log WHERE entry_id = :id"), {"id": broken}
        )
        assert result.scalar() == "tampered"


@pytest.mark.asyncio
async def test_broken_prev_hash_breaks_chain():
    await _seed_entries(3)
    async with async_session() as session:
        await session.execute(
            text("UPDATE audit_log SET prev_hash='deadbeef' WHERE details='seed-2'")
        )
        await session.commit()

    report = await verify_chain()
    assert report["valid"] is False


@pytest.mark.asyncio
async def test_verify_endpoint_admin_only(client):
    from app.repositories.auth_repository import ensure_demo_users
    await ensure_demo_users()
    await _seed_entries(2)

    admin = (await client.post(
        "/auth/login", json={"username": "admin_01", "password": "pass123"}
    )).json()["access_token"]
    resp = await client.get(
        "/audit/verify", headers={"Authorization": f"Bearer {admin}"}
    )
    assert resp.status_code == 200
    assert resp.json()["valid"] is True
    assert resp.json()["entries_checked"] == 2

    comp = (await client.post(
        "/auth/login", json={"username": "comp_01", "password": "pass123"}
    )).json()["access_token"]
    resp = await client.get(
        "/audit/verify", headers={"Authorization": f"Bearer {comp}"}
    )
    assert resp.status_code == 403
