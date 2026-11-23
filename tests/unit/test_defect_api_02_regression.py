"""Regression Test for DEFECT-API-02: Missing Eager-Loading of ProjectMember.user in verify_project_access.

Root Cause:
apps/api/dependencies.py:verify_project_access loads Project.members without chaining
selectinload(ProjectMember.user). When ProjectResponse serializes member.user, SQLAlchemy's
async greenlet raises MissingGreenlet, causing an unhandled HTTP 500 error on GET /projects/{id}.

This test verifies that verify_project_access includes chained selectinload for ProjectMember.user
and that ProjectResponse serializes nested member user objects cleanly without MissingGreenlet.
"""

import asyncio
import datetime
import uuid
from unittest.mock import AsyncMock, MagicMock

from apps.api.dependencies import verify_project_access
from database.models.project import Project, ProjectMember
from database.models.user import User
from packages.schemas.project import ProjectResponse


def test_verify_project_access_eager_loads_member_user():
    """Verify that verify_project_access chains selectinload(ProjectMember.user) and serializes cleanly."""
    async def _run_test():
        mock_session = AsyncMock()
        mock_result = MagicMock()

        proj_id = uuid.uuid4()
        user_id = uuid.uuid4()
        now = datetime.datetime.now(datetime.timezone.utc)

        test_user = User(
            id=user_id,
            email="regression-user@pentesa.lab",
            full_name="Regression Test User",
            password_hash="test",
            role="TESTER",
            is_active=True,
            created_at=now,
            updated_at=now
        )

        mock_project = Project(
            id=proj_id,
            name="Regression-Project",
            status="PLANNING",
            target_domains=[],
            allowed_cidrs=[],
            excluded_paths=[],
            allow_internal_networks=False,
            authorization_start=now,
            authorization_end=now,
            created_by=user_id,
            created_at=now,
            updated_at=now
        )

        mock_member = ProjectMember(
            id=uuid.uuid4(),
            project_id=proj_id,
            user_id=user_id,
            role="LEAD",
            created_at=now
        )
        mock_member.user = test_user
        mock_project.members = [mock_member]
        mock_project.scope_rules = []

        mock_result.scalar_one_or_none.return_value = mock_project
        mock_session.execute.return_value = mock_result

        project, member = await verify_project_access(proj_id, test_user, mock_session)

        # 1. Verify execute was called with a statement chaining ProjectMember.user
        assert mock_session.execute.called
        stmt = mock_session.execute.call_args[0][0]

        # Verify eager loading options in the query
        paths = [str(getattr(opt, "path", opt)) for opt in stmt._with_options]
        combined_paths = " ".join(paths)
        assert "members" in combined_paths
        assert "user" in combined_paths

        # 2. Verify serialization to ProjectResponse succeeds without MissingGreenlet
        response_schema = ProjectResponse.model_validate(project)
        assert response_schema.id == proj_id
        assert len(response_schema.members) == 1
        assert response_schema.members[0].user is not None
        assert response_schema.members[0].user.email == "regression-user@pentesa.lab"
        assert response_schema.members[0].user.full_name == "Regression Test User"

    asyncio.run(_run_test())


