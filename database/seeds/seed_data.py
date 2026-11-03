"""Initial database seeding for administrative user and standard project."""

import uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.user import User
from database.models.project import Project, ProjectMember
from database.models.scope import ScopeRule
from packages.common.security import hash_password


async def seed_initial_data(session: AsyncSession) -> None:
    """Seed initial administrator account and initial demonstration project if empty."""
    # Check if admin already exists
    stmt = select(User).where(User.email == "admin@example.com")
    result = await session.execute(stmt)
    admin_user = result.scalar_one_or_none()

    if not admin_user:
        admin_user = User(
            id=uuid.uuid4(),
            email="admin@example.com",
            password_hash=hash_password("Admin123!Secure"),
            full_name="Platform Administrator",
            role="ADMIN",
            is_active=True
        )
        session.add(admin_user)
        await session.flush()

        # Create demo authorized project
        now = datetime.now(timezone.utc)
        demo_project = Project(
            id=uuid.uuid4(),
            name="Authorized Demo Pentest",
            description="Initial demonstration project for authorized penetration testing.",
            status="ACTIVE",
            target_domains=["example.com", "*.example.com"],
            allowed_cidrs=["93.184.216.34/32"],
            excluded_paths=["/logout", "/admin/destroy"],
            allow_internal_networks=False,
            authorization_document_ref="ROE-DEMO-2026-001",
            authorization_start=now - timedelta(days=1),
            authorization_end=now + timedelta(days=30),
            created_by=admin_user.id
        )
        session.add(demo_project)
        await session.flush()

        # Add admin as Lead on demo project
        membership = ProjectMember(
            id=uuid.uuid4(),
            project_id=demo_project.id,
            user_id=admin_user.id,
            role="LEAD"
        )
        session.add(membership)

        # Add scope rules
        rule1 = ScopeRule(
            id=uuid.uuid4(),
            project_id=demo_project.id,
            rule_type="DOMAIN_WILDCARD",
            target_type="IN_SCOPE",
            pattern="*.example.com",
            protocol="https,http"
        )
        rule2 = ScopeRule(
            id=uuid.uuid4(),
            project_id=demo_project.id,
            rule_type="EXCLUDED_PATH",
            target_type="OUT_OF_SCOPE",
            pattern="/logout"
        )
        session.add_all([rule1, rule2])
        await session.commit()
