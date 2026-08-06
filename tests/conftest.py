import pytest
import asyncio
from app.models.database import create_tables, engine, Base


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
