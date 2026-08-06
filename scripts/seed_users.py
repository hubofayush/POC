"""
Seed script for the D5 user store.

Usage:
    py scripts/seed_users.py                # bootstrap admin from env (BOOTSTRAP_*)
    py scripts/seed_users.py --demo         # also (re)create the 4 demo users
"""
from __future__ import annotations

import argparse
import os

from sqlalchemy import select

from app.models.database import async_session, create_tables, User
from app.core.security.passwords import hash_password
from app.repositories.auth_repository import ensure_demo_users, _DEMO_USERS


async def seed() -> None:
    await create_tables()

    username = os.getenv("BOOTSTRAP_ADMIN_USERNAME", "admin")
    password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "")
    org = os.getenv("BOOTSTRAP_ADMIN_ORG", "org_uma")

    if not password:
        print("BOOTSTRAP_ADMIN_PASSWORD must be set. Aborting.")
        return

    async with async_session() as session:
        existing = (
            await session.execute(select(User).where(User.username == username))
        ).scalar_one_or_none()
        if existing:
            print(f"User '{username}' already exists — skipping admin bootstrap.")
        else:
            session.add(
                User(
                    username=username,
                    password_hash=hash_password(password),
                    role="admin",
                    org=org,
                )
            )
            await session.commit()
            print(f"Bootstrap admin '{username}' created (org={org}).")


async def seed_demo() -> None:
    await ensure_demo_users()
    print(f"Demo users ensured: {', '.join(sorted(_DEMO_USERS))} (password: pass123)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed D5 users")
    parser.add_argument("--demo", action="store_true", help="Create demo users too")
    args = parser.parse_args()

    import asyncio

    asyncio.run(seed())
    if args.demo:
        asyncio.run(seed_demo())
