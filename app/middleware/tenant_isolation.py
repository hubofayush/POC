"""
app.middleware.tenant_isolation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
TenantIsolationMiddleware — binds and clears TenantContext per request.

Responsibilities:
  1. Decode JWT (without re-verifying signature — auth dep already does that)
     to extract org/user/role claims and bind a TenantContext to the ContextVar.
  2. Populate request.state.tenant_org for use by the rate limiter.
  3. ALWAYS clear the TenantContext in a finally block after the response —
     prevents context bleed between async requests sharing the same worker.

Unauthenticated paths (/auth/*, /health*, /metrics) are passed through
without attempting JWT extraction.
"""
from __future__ import annotations

import jwt
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.core.logging import get_logger
from app.core.security.tenant_context import (
    TenantContext,
    clear_tenant_context,
    set_current_tenant,
)

logger = get_logger(__name__)

# Paths that don't require tenant context (no JWT expected)
_PASSTHROUGH_PREFIXES = (
    "/auth/",
    "/health",
    "/metrics",
    "/docs",
    "/openapi",
    "/redoc",
)


class TenantIsolationMiddleware(BaseHTTPMiddleware):
    """
    Middleware that binds TenantContext at the start of every authenticated
    request and guarantees its cleanup at the end of every request.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Passthrough for unauthenticated routes
        if any(path.startswith(prefix) for prefix in _PASSTHROUGH_PREFIXES):
            return await call_next(request)

        # Attempt to extract org from Bearer JWT (no full re-verification here —
        # just read claims. The auth dep will raise 401 on invalid tokens.)
        tenant_org: str = "unknown"
        try:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                raw_token = auth_header.split(" ", 1)[1]
                # Decode without verification (signature already checked by dep)
                claims = jwt.decode(
                    raw_token,
                    options={"verify_signature": False},
                    algorithms=["RS256"],
                )
                tenant_org = claims.get("org", "unknown")
                user_id = claims.get("sub", "unknown")
                role = claims.get("role", "unknown")
                is_admin = role == "admin"

                # Bind TenantContext to the current async context
                set_current_tenant(
                    TenantContext(
                        org_id=tenant_org,
                        user_id=user_id,
                        role=role,
                        is_admin=is_admin,
                    )
                )
                logger.debug(
                    "tenant.context_bound",
                    user_id=user_id,
                    org_id=tenant_org,
                    role=role,
                    path=path,
                )
        except Exception:
            # Any failure here is non-fatal — the auth dep will reject the
            # request with 401 if the token is genuinely invalid.
            pass

        # Expose on request.state for the rate limiter key function
        request.state.tenant_org = tenant_org

        try:
            return await call_next(request)
        finally:
            # Critical: always clear to prevent context leakage between requests
            clear_tenant_context()
            logger.debug("tenant.context_cleared", org_id=tenant_org, path=path)
