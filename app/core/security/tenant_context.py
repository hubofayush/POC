"""
app.core.security.tenant_context
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Thread-safe & async-safe Tenant Context management using Python `contextvars`.

Guarantees that tenant state (organization ID, user ID, role) is bound to the
active request context and accessible across all layers (API, guardrails,
service, ORM session) without parameter drilling.
"""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

# Global ContextVar for the current request's tenant context
_current_tenant_var: ContextVar[TenantContext | None] = ContextVar(
    "current_tenant", default=None
)


@dataclass(frozen=True)
class TenantContext:
    """Immutable context object representing the current tenant and user."""
    org_id: str
    user_id: str
    role: str
    is_admin: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_id": self.org_id,
            "user_id": self.user_id,
            "role": self.role,
            "is_admin": self.is_admin,
        }


def get_current_tenant() -> TenantContext | None:
    """Retrieve the TenantContext bound to the current async context."""
    return _current_tenant_var.get()


def set_current_tenant(tenant: TenantContext) -> None:
    """Bind a TenantContext to the current async context."""
    _current_tenant_var.set(tenant)


def clear_tenant_context() -> None:
    """Reset the tenant context for the current async context."""
    _current_tenant_var.set(None)


def build_tenant_context(user_claims: dict[str, Any]) -> TenantContext:
    """Construct a TenantContext from decoded JWT claims."""
    org_id = user_claims.get("org", "unknown")
    user_id = user_claims.get("sub", "unknown")
    role = user_claims.get("role", "hr")
    is_admin = role in ("admin",)
    return TenantContext(
        org_id=org_id,
        user_id=user_id,
        role=role,
        is_admin=is_admin,
    )
