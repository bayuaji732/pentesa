import asyncio
import os
import sys
from logging.config import fileConfig

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine
from alembic import context

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from database.base import Base
import database.models
from packages.common.config import settings

config = context.config

if config.config_file_name is not None and not config.attributes.get("configure_logger", True) is False:
    try:
        fileConfig(config.config_file_name)
    except Exception:
        pass

target_metadata = Base.metadata

MIGRATION_ADVISORY_LOCK_ID = 84729103


def get_url() -> str:
    url = config.get_main_option("sqlalchemy.url")
    if not url:
        url = (
            os.getenv("PENTESA_DATABASE_URL")
            or os.getenv("DATABASE_URL")
            or getattr(settings, "database_url", "")
        )
    if not url:
        url = "sqlite+aiosqlite:///:memory:"
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif url.startswith("sqlite://") and "+aiosqlite" not in url:
        url = url.replace("sqlite://", "sqlite+aiosqlite://", 1)
    return url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = get_url()
    if "+aiosqlite" in url:
        url = url.replace("+aiosqlite", "")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations in 'online' mode with transactional advisory lock for PostgreSQL."""
    url = get_url()
    connectable = create_async_engine(url)
    is_postgres = "postgres" in url.lower()

    async with connectable.connect() as connection:
        lock_acquired = False
        if is_postgres:
            try:
                await connection.execute(
                    sa.text(f"SELECT pg_advisory_lock({MIGRATION_ADVISORY_LOCK_ID});")
                )
                lock_acquired = True
            except Exception as e:
                sys.stderr.write(f"Warning: Failed to acquire advisory lock: {e}\n")

        try:
            await connection.run_sync(do_run_migrations)
            await connection.commit()
        finally:
            if is_postgres and lock_acquired:
                try:
                    await connection.execute(
                        sa.text(f"SELECT pg_advisory_unlock({MIGRATION_ADVISORY_LOCK_ID});")
                    )
                except Exception:
                    pass

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    if context.is_offline_mode():
        run_migrations_offline()
    else:
        asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
