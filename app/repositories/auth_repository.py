"""
app.repositories.auth_repository
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
DAO for users and refresh-token registry (rotation, reuse detection, lockout).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update

from app.config import settings
from app.core.security.passwords import hash_password
from app.models.database import RefreshToken, User, async_session


class AuthRepository:
    """Persistence for authentication primitives."""

    # -- users -----------------------------------------------------------------

    async def get_user_by_username(self, username: str) -> User | None:
        async with async_session() as session:
            result = await session.execute(
                select(User).where(User.username == username)
            )
            return result.scalar_one_or_none()

    async def record_login_failure(self, user: User) -> None:
        """Increment failed attempts; lock the account once the threshold is hit."""
        async with async_session() as session:
            failed = user.failed_attempts + 1
            locked_until = None
            if failed >= settings.AUTH_MAX_FAILED_ATTEMPTS:
                locked_until = datetime.now(UTC) + timedelta(
                    minutes=settings.AUTH_LOCKOUT_MINUTES
                )
            await session.execute(
                update(User)
                .where(User.id == user.id)
                .values(failed_attempts=failed, locked_until=locked_until)
            )
            await session.commit()

    async def record_login_success(self, user: User) -> None:
        """Reset the failure counter and stamp last_login_at."""
        async with async_session() as session:
            await session.execute(
                update(User)
                .where(User.id == user.id)
                .values(failed_attempts=0, last_login_at=datetime.now(UTC))
            )
            await session.commit()

    # -- refresh-token registry ------------------------------------------------

    async def create_refresh_token(
        self,
        jti: str,
        user_id: str,
        token_hash: str,
        family_id: str,
        expires_at: datetime,
    ) -> None:
        async with async_session() as session:
            session.add(
                RefreshToken(
                    jti=jti,
                    user_id=user_id,
                    token_hash=token_hash,
                    family_id=family_id,
                    expires_at=expires_at,
                )
            )
            await session.commit()

    async def get_refresh_token_by_hash(self, token_hash: str) -> RefreshToken | None:
        async with async_session() as session:
            result = await session.execute(
                select(RefreshToken).where(RefreshToken.token_hash == token_hash)
            )
            return result.scalar_one_or_none()

    async def revoke_token(self, jti: str, replaced_by_jti: str | None = None) -> None:
        """Revoke a token; optionally record which token replaced it."""
        async with async_session() as session:
            await session.execute(
                update(RefreshToken)
                .where(RefreshToken.jti == jti)
                .values(
                    revoked_at=datetime.now(UTC),
                    replaced_by_jti=replaced_by_jti,
                )
            )
            await session.commit()

    async def revoke_family(self, family_id: str) -> None:
        """Revoke every token in a family (theft / reuse response)."""
        async with async_session() as session:
            await session.execute(
                update(RefreshToken)
                .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
                .values(revoked_at=datetime.now(UTC))
            )
            await session.commit()


# ---------------------------------------------------------------------------
# Demo / bootstrap seeding (dev convenience — replaced by IdP in production)
# ---------------------------------------------------------------------------

_DEMO_USERS = {
    "admin_01": ("admin", "org_uma"),
    "comp_01": ("compliance_officer", "org_uma"),
    "hr_01": ("hr", "org_uma"),
    "clinician_01": ("clinician", "org_uma"),
}


async def ensure_demo_users() -> None:
    """Idempotently seed the demo users used by tests and smoke scripts."""
    async with async_session() as session:
        existing = set((await session.execute(select(User.username))).scalars().all())
        for username, (role, org) in _DEMO_USERS.items():
            if username not in existing:
                session.add(
                    User(
                        username=username,
                        password_hash=hash_password("pass123"),
                        role=role,
                        org=org,
                    )
                )
        await session.commit()


auth_repository = AuthRepository()
