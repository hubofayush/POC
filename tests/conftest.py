import os

# Isolate tests to a dedicated DB BEFORE any app module is imported.
# Prevents test runs from wiping/contending with the dev server's d5_dev.db
# and lets schema changes evolve without migrating the dev file.
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./d5_test.db"
os.environ["DB_AUTO_CREATE"] = "false"

import asyncio
import pathlib
from contextlib import suppress

import pytest

from app.models.database import Base, create_tables, engine

_TEST_DB = pathlib.Path("d5_test.db")


@pytest.fixture(scope="session", autouse=True)
async def _fresh_test_db():
    """Start every session from a clean, schema-current test database."""
    with suppress(OSError):
        _TEST_DB.unlink()  # may be briefly locked; drop_all below is schema-independent
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    yield
    with suppress(OSError):
        _TEST_DB.unlink()


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(autouse=True)
async def setup_db():
    await create_tables()
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
