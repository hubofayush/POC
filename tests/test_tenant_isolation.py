"""
tests/test_tenant_isolation.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Integration tests for Tenant Isolation, TenantIsolationGuard, cross-tenant attack blocking,
and per-tenant audit chain verification.
"""
import pytest
from httpx import ASGITransport, AsyncClient

from app.core.guardrails.ingress.layer3_tenant_guard import TenantIsolationGuard
from app.main import app
from app.repositories.audit_repository import audit_repository


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_tenant_isolation_guard_blocks_cross_tenant_injection():
    guard = TenantIsolationGuard()
    user = {"sub": "user_hr", "role": "hr", "org": "org_uma"}
    context = {"org": "org_kaiser", "consent_granted": True}

    result = await guard.check("Check license", context, user)
    assert result.passed is False
    assert result.code == "TENANT_ISOLATION_VIOLATION"
    assert result.layer == "ingress.layer3.tenant_isolation"


@pytest.mark.asyncio
async def test_tenant_isolation_guard_allows_admin_cross_tenant():
    guard = TenantIsolationGuard()
    admin_user = {"sub": "admin_01", "role": "admin", "org": "org_uma"}
    context = {"org": "org_kaiser", "consent_granted": True}

    result = await guard.check("Check license", context, admin_user)
    assert result.passed is True


@pytest.mark.asyncio
async def test_tenant_isolation_guard_allows_matching_org():
    guard = TenantIsolationGuard()
    user = {"sub": "user_hr", "role": "hr", "org": "org_uma"}
    context = {"org": "org_uma", "consent_granted": True}

    result = await guard.check("Check license", context, user)
    assert result.passed is True


@pytest.mark.asyncio
async def test_per_tenant_audit_hash_chain_verification():
    # Insert entries for two different tenants
    id1 = await audit_repository.create_entry(
        user_id="u1", user_role="hr", action="invoke", user_org="org_alpha", status="success"
    )
    id2 = await audit_repository.create_entry(
        user_id="u2", user_role="hr", action="invoke", user_org="org_beta", status="success"
    )
    id3 = await audit_repository.create_entry(
        user_id="u1", user_role="hr", action="invoke", user_org="org_alpha", status="success"
    )

    # Verify chain for org_alpha
    res_alpha = await audit_repository.verify_chain(org="org_alpha")
    assert res_alpha["valid"] is True
    assert res_alpha["entries_checked"] >= 2

    # Verify chain for org_beta
    res_beta = await audit_repository.verify_chain(org="org_beta")
    assert res_beta["valid"] is True
    assert res_beta["entries_checked"] >= 1
