"""
app.api.v1.auth
~~~~~~~~~~~~~~~
Authentication endpoints backed by the real user store:
login (argon2 + lockout), refresh (rotation + reuse detection), logout, me.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, HTTPException, status, Depends, Request
from pydantic import BaseModel, Field

from app.config import settings
from app.middleware.rate_limit import limiter

from app.core.security.auth import (
    create_token,
    decode_token,
    hash_refresh_token,
)
from app.core.security.passwords import dummy_verify, verify_password
from app.repositories.auth_repository import auth_repository
from app.api.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])


def _ensure_aware(dt: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes — normalize to UTC-aware."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=200)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=1, max_length=2048)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


async def _issue_token_pair(user_id: str, role: str, org: str) -> TokenResponse:
    """Create an access token plus a persisted, rotatable refresh token."""
    access = create_token(user_id, role, org, token_type="access")
    refresh = create_token(user_id, role, org, token_type="refresh")
    payload = decode_token(refresh)  # verified; carries jti/exp

    await auth_repository.create_refresh_token(
        jti=payload["jti"],
        user_id=user_id,
        token_hash=hash_refresh_token(refresh),
        family_id=str(uuid4()),
        expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
    )
    return TokenResponse(access_token=access, refresh_token=refresh)


@limiter.limit(settings.AUTH_LOGIN_RATE_LIMIT)
@router.post("/login", response_model=TokenResponse)
async def login(request: Request, body: LoginRequest):
    user = await auth_repository.get_user_by_username(body.username)

    if user is None:
        # Burn comparable time to defeat username enumeration via timing
        await asyncio.to_thread(dummy_verify, body.password)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account disabled")

    if _ensure_aware(user.locked_until) and _ensure_aware(user.locked_until) > datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account temporarily locked due to too many failed attempts",
        )

    # argon2 verify is CPU-bound; run off the event loop
    if not await asyncio.to_thread(verify_password, body.password, user.password_hash):
        await auth_repository.record_login_failure(user)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    await auth_repository.record_login_success(user)
    return await _issue_token_pair(user.username, user.role, user.org)


@limiter.limit(settings.AUTH_REFRESH_RATE_LIMIT)
@router.post("/refresh", response_model=TokenResponse)
async def refresh(request: Request, body: RefreshRequest):
    payload = decode_token(body.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )

    token_hash = hash_refresh_token(body.refresh_token)
    record = await auth_repository.get_refresh_token_by_hash(token_hash)

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )

    if record.revoked_at is not None:
        # A rotated token presented again = theft signal. Revoke the whole family.
        await auth_repository.revoke_family(record.family_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token reuse detected"
        )

    if datetime.fromtimestamp(payload["exp"], tz=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired"
        )

    # Rotate: revoke current, issue a new one in the same family
    new_jti = str(uuid4())
    await auth_repository.revoke_token(record.jti, replaced_by_jti=new_jti)

    access = create_token(record.user_id, payload["role"], payload["org"], token_type="access")
    refresh = create_token(record.user_id, payload["role"], payload["org"], token_type="refresh")
    new_payload = decode_token(refresh)

    await auth_repository.create_refresh_token(
        jti=new_payload["jti"],
        user_id=record.user_id,
        token_hash=hash_refresh_token(refresh),
        family_id=record.family_id,
        expires_at=datetime.fromtimestamp(new_payload["exp"], tz=timezone.utc),
    )
    return TokenResponse(access_token=access, refresh_token=refresh)


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(body: RefreshRequest):
    try:
        payload = decode_token(body.refresh_token)
    except HTTPException:
        # Unknown/invalid tokens are treated as already logged out
        return {"detail": "Logged out"}
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )
    record = await auth_repository.get_refresh_token_by_hash(hash_refresh_token(body.refresh_token))
    if record is not None and record.revoked_at is None:
        await auth_repository.revoke_token(record.jti)
    return {"detail": "Logged out"}


@router.get("/me")
async def me(user: dict = Depends(get_current_user)):
    return user
