"""Pytest configuration, fixtures, and test database setup."""

import asyncio
import os
import uuid

os.environ.setdefault("PENTESA_ENV", "test")
os.environ.setdefault("PENTESA_LLM_PROVIDER", "mock")
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from apps.api.main import app
from database.base import Base
from database.models.project import Project, ProjectMember
from database.models.scope import ScopeRule
from database.models.user import User
from database.session import get_db
from packages.common.security import create_access_token, hash_password

# Use dedicated test database
TEST_DB_FILE = "./test_pentesa.db"
TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL", f"sqlite+aiosqlite:///{TEST_DB_FILE}")

engine_kwargs = {"echo": False}
if "postgresql" in TEST_DATABASE_URL:
    engine_kwargs["poolclass"] = NullPool

test_engine = create_async_engine(TEST_DATABASE_URL, **engine_kwargs)
TestSessionLocal = async_sessionmaker(bind=test_engine, class_=AsyncSession, expire_on_commit=False)


@pytest_asyncio.fixture(loop_scope="function")
async def setup_test_database():
    """Create test database schema before tests."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with TestSessionLocal() as session:
        from services.execution_engine.planner import seed_wstg_catalog
        await seed_wstg_catalog(session)
        await session.commit()
    yield
    async with test_engine.begin() as conn:
        if "postgresql" in TEST_DATABASE_URL:
            await conn.execute(text("DROP SCHEMA public CASCADE;"))
            await conn.execute(text("CREATE SCHEMA public;"))
        else:
            await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session(setup_test_database) -> AsyncGenerator[AsyncSession, None]:
    """Provide isolated async session for tests."""
    async with TestSessionLocal() as session:
        yield session
        await session.rollback()
        await session.close()


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Provide AsyncClient wired with test database session override."""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def admin_user(db_session: AsyncSession) -> User:
    """Fixture providing an active Administrator user."""
    user = User(
        id=uuid.uuid4(),
        email=f"admin_{uuid.uuid4().hex[:6]}@example.com",
        password_hash=hash_password("AdminPass123!"),
        full_name="Admin Test User",
        role="ADMIN",
        is_active=True
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def admin_token(admin_user: User) -> str:
    """Fixture providing valid JWT token for admin user."""
    return create_access_token(
        subject=str(admin_user.id),
        claims={"role": admin_user.role, "email": admin_user.email}
    )


@pytest_asyncio.fixture
async def tester_user(db_session: AsyncSession) -> User:
    """Fixture providing an active Tester user."""
    user = User(
        id=uuid.uuid4(),
        email=f"tester_{uuid.uuid4().hex[:6]}@example.com",
        password_hash=hash_password("TesterPass123!"),
        full_name="Tester Test User",
        role="TESTER",
        is_active=True
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def tester_token(tester_user: User) -> str:
    """Fixture providing valid JWT token for tester user."""
    return create_access_token(
        subject=str(tester_user.id),
        claims={"role": tester_user.role, "email": tester_user.email}
    )


@pytest_asyncio.fixture
async def test_project(db_session: AsyncSession, admin_user: User) -> Project:
    """Fixture providing an authorized active project with scope rules."""
    now = datetime.now(timezone.utc)
    project = Project(
        id=uuid.uuid4(),
        name="Test Engagement Project",
        description="Automated testing target project",
        status="ACTIVE",
        target_domains=["target.com", "*.target.com"],
        allowed_cidrs=["203.0.113.0/24"],
        excluded_paths=["/logout", "/admin/delete"],
        allow_internal_networks=False,
        authorization_start=now - timedelta(days=2),
        authorization_end=now + timedelta(days=20),
        created_by=admin_user.id
    )
    db_session.add(project)

    # Add admin as Lead
    membership = ProjectMember(
        id=uuid.uuid4(),
        project_id=project.id,
        user_id=admin_user.id,
        role="LEAD"
    )
    db_session.add(membership)

    # Scope Rules
    r1 = ScopeRule(
        id=uuid.uuid4(),
        project_id=project.id,
        rule_type="DOMAIN_WILDCARD",
        target_type="IN_SCOPE",
        pattern="*.target.com",
        protocol="https,http",
        port_range="80,443,8443"
    )
    r2 = ScopeRule(
        id=uuid.uuid4(),
        project_id=project.id,
        rule_type="IP_CIDR",
        target_type="IN_SCOPE",
        pattern="203.0.113.0/24",
        protocol="https,http"
    )
    r3 = ScopeRule(
        id=uuid.uuid4(),
        project_id=project.id,
        rule_type="EXCLUDED_PATH",
        target_type="OUT_OF_SCOPE",
        pattern="/logout"
    )
    r4 = ScopeRule(
        id=uuid.uuid4(),
        project_id=project.id,
        rule_type="EXCLUDED_PATH",
        target_type="OUT_OF_SCOPE",
        pattern="/admin/delete"
    )
    db_session.add_all([r1, r2, r3, r4])
    await db_session.commit()
    await db_session.refresh(project)
    return project
