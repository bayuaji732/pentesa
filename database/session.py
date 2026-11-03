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


async def init_db(custom_engine: AsyncEngine = None) -> None:
    """Create all tables in the database."""
    target_engine = custom_engine or engine
    async with target_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db(custom_engine: AsyncEngine = None) -> None:
    """Dispose of engine connections."""
    target_engine = custom_engine or engine
    await target_engine.dispose()

