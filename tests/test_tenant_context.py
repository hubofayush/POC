"""
tests/test_tenant_context.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Unit tests for TenantContext and thread-safe ContextVar binding.
"""
import asyncio
import pytest

from app.core.security.tenant_context import (
    TenantContext,
    build_tenant_context,
    clear_tenant_context,
    get_current_tenant,
    set_current_tenant,
)


def test_build_tenant_context_admin():
    claims = {"sub": "user_admin", "org": "org_uma", "role": "admin"}
    ctx = build_tenant_context(claims)
    assert ctx.org_id == "org_uma"
    assert ctx.user_id == "user_admin"
    assert ctx.role == "admin"
    assert ctx.is_admin is True


def test_build_tenant_context_non_admin():
    claims = {"sub": "user_hr", "org": "org_kaiser", "role": "hr"}
    ctx = build_tenant_context(claims)
    assert ctx.org_id == "org_kaiser"
    assert ctx.user_id == "user_hr"
    assert ctx.role == "hr"
    assert ctx.is_admin is False


@pytest.mark.asyncio
async def test_contextvar_async_isolation():
    """Verify that concurrent async tasks maintain distinct TenantContext bindings."""

    async def task_a():
        ctx_a = TenantContext(org_id="org_a", user_id="user_a", role="hr")
        set_current_tenant(ctx_a)
        await asyncio.sleep(0.01)
        res = get_current_tenant()
        assert res is not None
        assert res.org_id == "org_a"

    async def task_b():
        ctx_b = TenantContext(org_id="org_b", user_id="user_b", role="clinician")
        set_current_tenant(ctx_b)
        await asyncio.sleep(0.01)
        res = get_current_tenant()
        assert res is not None
        assert res.org_id == "org_b"

    await asyncio.gather(task_a(), task_b())
    clear_tenant_context()
    assert get_current_tenant() is None
