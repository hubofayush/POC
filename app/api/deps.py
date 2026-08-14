"""
app.api.deps
~~~~~~~~~~~~
FastAPI Route Dependencies (JWT Authentication, Tenant Context & Role Requirements).
"""
from __future__ import annotations

from fastapi import Depends, Header, HTTPException, status

from app.core.security.auth import decode_token
from app.core.security.rbac import check_role, require_org_scope
from app.core.security.tenant_context import (
    TenantContext,
    build_tenant_context,
    set_current_tenant,
)


async def get_current_user(authorization: str | None = Header(None)) -> dict:
    """Extracts, verifies Bearer JWT token, and binds TenantContext."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header",
        )
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid auth scheme",
        )
    token = authorization.split(" ", 1)[1]
    claims = decode_token(token)

    # Bind TenantContext to ContextVar for this request execution path
    tenant_ctx = build_tenant_context(claims)
    set_current_tenant(tenant_ctx)

    return claims


async def get_tenant_context(user: dict = Depends(get_current_user)) -> TenantContext:
    """Dependency that returns the active TenantContext for the request."""
    return build_tenant_context(user)


def require_roles(allowed_roles: list[str]):
    """FastAPI Dependency factory enforcing RBAC role requirements."""
    async def checker(user: dict = Depends(get_current_user)):
        check_role(user, allowed_roles)
        return user
    return checker


__all__ = ["get_current_user", "get_tenant_context", "require_roles", "require_org_scope"]
