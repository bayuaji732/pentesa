"""Database session and engine management."""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine
)

from database.base import Base
from packages.common.config import settings

# Engine configuration
engine: AsyncEngine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    future=True
)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency providing an async database session with automatic transaction management."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def run_migrations_programmatic(url: str = None) -> None:
    """Run Alembic migrations programmatically up to head."""
    from alembic.config import Config
    from alembic import command
    cfg = Config("alembic.ini")
    if url:
        cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")


async def init_db(custom_engine: AsyncEngine = None) -> None:
    """Apply Alembic migrations or create tables in test sqlite."""
    target_engine = custom_engine or engine
    url = str(target_engine.url)
    if ":memory:" in url or ("sqlite" in url and "test" in (getattr(settings, "env", "") or "").lower()):
        async with target_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    else:
        import asyncio
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, run_migrations_programmatic, url)


async def close_db(custom_engine: AsyncEngine = None) -> None:
    """Dispose of engine connections."""
    target_engine = custom_engine or engine
    await target_engine.dispose()

