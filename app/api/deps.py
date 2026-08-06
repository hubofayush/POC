"""
app.api.deps
~~~~~~~~~~~~
FastAPI Route Dependencies (JWT Authentication & Role Requirements).
"""
from __future__ import annotations

from fastapi import Header, HTTPException, status, Depends
from app.core.security.auth import decode_token
from app.core.security.rbac import check_role


async def get_current_user(authorization: str | None = Header(None)) -> dict:
    """Extracts and verifies Bearer JWT token from Authorization header."""
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
    return decode_token(token)


def require_roles(allowed_roles: list[str]):
    """FastAPI Dependency factory enforcing RBAC role requirements."""
    async def checker(user: dict = Depends(get_current_user)):
        check_role(user, allowed_roles)
        return user
    return checker
