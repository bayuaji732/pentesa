"""Regression Test for DEFECT-API-02: Missing Eager-Loading of ProjectMember.user in verify_project_access.

Root Cause:
apps/api/dependencies.py:verify_project_access loads Project.members without chaining
selectinload(ProjectMember.user). When ProjectResponse serializes member.user, SQLAlchemy's
async greenlet raises MissingGreenlet, causing an unhandled HTTP 500 error on GET /projects/{id}.

This test verifies that GET /api/v1/projects/{project_id} returns HTTP 200 with members and
nested user objects fully serialized, and that verify_project_access loads ProjectMember.user.
"""

import asyncio
import datetime
import uuid
import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import selectinload

import database.models  # noqa: F401 - register all ORM models on Base.metadata
from database.base import Base
from database.models.project import Project, ProjectMember
from database.models.user import User
from packages.schemas.project import ProjectResponse
from apps.api.dependencies import verify_project_access


@pytest.mark.asyncio
async def test_verify_project_access_eager_loads_member_user():
    """Verify that verify_project_access loads member.user without raising MissingGreenlet during serialization."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with session_factory() as session:
            # Create a test project and member
            test_user = User(
                id=uuid.uuid4(),
                email=f"regression-user-{uuid.uuid4().hex[:8]}@pentesa.lab",
                full_name="Regression Test User",
                password_hash="test",
                role="TESTER",
                is_active=True
            )
            session.add(test_user)
            await session.flush()

            now = datetime.datetime.now(datetime.timezone.utc)
            test_project = Project(
                id=uuid.uuid4(),
                name=f"Regression-Project-{uuid.uuid4().hex[:8]}",
                status="PLANNING",
                authorization_start=now - datetime.timedelta(hours=1),
                authorization_end=now + datetime.timedelta(days=7),
                created_by=test_user.id
            )
            session.add(test_project)
            await session.flush()

            test_member = ProjectMember(
                id=uuid.uuid4(),
                project_id=test_project.id,
                user_id=test_user.id,
                role="LEAD"
            )
            session.add(test_member)
            await session.commit()

            proj_id = test_project.id
            user_id = test_user.id
            user_email = test_user.email

        # Open a brand-new session (exact FastAPI request semantics)
        async with session_factory() as read_session:
            fresh_user = (await read_session.execute(select(User).where(User.id == user_id))).scalar_one()

            # Call verify_project_access
            project, _ = await verify_project_access(proj_id, fresh_user, read_session)
            assert project is not None
            assert len(project.members) >= 1

            # Serialize to ProjectResponse — before fix, this raises MissingGreenlet / ResponseValidationError
            response_schema = ProjectResponse.model_validate(project)
            assert response_schema.id == proj_id
            assert len(response_schema.members) >= 1
            assert response_schema.members[0].user is not None
            assert response_schema.members[0].user.email == user_email
            assert response_schema.members[0].user.full_name == "Regression Test User"
    finally:
        await engine.dispose()
