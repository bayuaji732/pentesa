"""Regression Test for DEFECT-API-02: Missing Eager-Loading of ProjectMember.user in verify_project_access.

Root Cause:
apps/api/dependencies.py:verify_project_access loads Project.members without chaining
selectinload(ProjectMember.user). When ProjectResponse serializes member.user, SQLAlchemy's
async greenlet raises MissingGreenlet, causing an unhandled HTTP 500 error on GET /projects/{id}.

This test verifies that GET /api/v1/projects/{project_id} returns HTTP 200 with members and
nested user objects fully serialized, and that verify_project_access loads ProjectMember.user.
"""

import asyncio
import uuid
import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from database.models.project import Project, ProjectMember
from database.models.user import User
from database.session import AsyncSessionLocal
from packages.schemas.project import ProjectResponse
from apps.api.dependencies import verify_project_access


@pytest.mark.asyncio
async def test_verify_project_access_eager_loads_member_user():
    """Verify that verify_project_access loads member.user without raising MissingGreenlet during serialization."""
    async with AsyncSessionLocal() as session:
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

        test_project = Project(
            id=uuid.uuid4(),
            name=f"Regression-Project-{uuid.uuid4().hex[:8]}",
            status="PLANNING",
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

        try:
            # Call verify_project_access
            project, _ = await verify_project_access(test_project.id, test_user, session)
            assert project is not None
            assert len(project.members) >= 1

            # Serialize to ProjectResponse — before fix, this raises MissingGreenlet / ResponseValidationError
            response_schema = ProjectResponse.model_validate(project)
            assert response_schema.id == test_project.id
            assert len(response_schema.members) >= 1
            assert response_schema.members[0].user is not None
            assert response_schema.members[0].user.email == test_user.email
            assert response_schema.members[0].user.full_name == "Regression Test User"
        finally:
            # Cleanup
            await session.delete(test_member)
            await session.delete(test_project)
            await session.delete(test_user)
            await session.commit()
