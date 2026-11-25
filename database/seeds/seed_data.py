"""Initial database seeding for administrator account and optional demo project."""

import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Tuple
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.user import User
from database.models.project import Project, ProjectMember
from packages.common.config import settings
from packages.common.security import hash_password
from services.execution_engine.planner import seed_wstg_catalog

logger = logging.getLogger(__name__)


def is_strong_password(password: str) -> Tuple[bool, str]:
    """Validate administrator password complexity (SEC-PWD-01)."""
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one numeric digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_]", password):
        return False, "Password must contain at least one special character."
    lower = password.lower()
    if any(b in lower for b in ["password", "admin", "123456", "pentesa"]):
        return False, "Password contains prohibited common phrases."
    return True, ""


async def seed_initial_data(session: AsyncSession) -> None:
    """
    Seed initial system data adhering to SEC-PWD-01:
    - Always seed official OWASP WSTG test catalog
    - Never unconditionally seed default admin@example.com credentials
    - Bootstrap admin ONLY if explicit valid bootstrap credentials provided
      (PENTESA_BOOTSTRAP_ADMIN_EMAIL / PENTESA_BOOTSTRAP_ADMIN_PASSWORD)
    - OR if PENTESA_ENV=development AND PENTESA_SEED_DEMO_DATA=1
    """
    # 1. Populate/refresh official WSTG Catalog
    await seed_wstg_catalog(session)

    bootstrap_flag = os.getenv("PENTESA_BOOTSTRAP_ADMIN", "").lower() in ("1", "true", "yes")
    bootstrap_email = os.getenv("PENTESA_BOOTSTRAP_ADMIN_EMAIL")
    bootstrap_pwd = os.getenv("PENTESA_BOOTSTRAP_ADMIN_PASSWORD")

    # 2. Handle explicit bootstrap admin creation if requested
    if bootstrap_flag or bootstrap_email:
        if not bootstrap_email or not bootstrap_pwd:
            raise ValueError(
                "SEC-PWD-01: PENTESA_BOOTSTRAP_ADMIN is enabled but PENTESA_BOOTSTRAP_ADMIN_EMAIL "
                "or PENTESA_BOOTSTRAP_ADMIN_PASSWORD is missing. Both must be provided."
            )

        # Idempotency check: verify if this bootstrap admin already exists
        target_email = bootstrap_email.strip().lower()
        user_stmt = select(User).where(User.email == target_email)
        existing_bootstrap_user = (await session.execute(user_stmt)).scalar_one_or_none()
        if existing_bootstrap_user:
            logger.info(f"Bootstrap admin account already exists: {target_email}. Skipping creation (idempotent).")
            return

        is_strong, reason = is_strong_password(bootstrap_pwd)
        if not is_strong:
            raise ValueError(
                f"SEC-PWD-01: PENTESA_BOOTSTRAP_ADMIN_PASSWORD rejected: {reason}"
            )

        admin_user = User(
            id=uuid.uuid4(),
            email=target_email,
            password_hash=hash_password(bootstrap_pwd),
            full_name="System Administrator",
            role="ADMIN",
            is_active=True,
        )
        session.add(admin_user)
        await session.commit()
        logger.info(f"Successfully bootstrapped initial admin account: {target_email}")
        return

    # 3. Check if any admin account already exists
    admin_stmt = select(User).where(User.role == "ADMIN")
    existing_admin = (await session.execute(admin_stmt)).first()
    if existing_admin:
        return

    # 4. Handle development demo data seeding
    env = (getattr(settings, "env", "") or os.getenv("PENTESA_ENV", "")).lower()
    seed_demo = os.getenv("PENTESA_SEED_DEMO_DATA", "").lower() in ("1", "true", "yes")

    if env in ("development", "test") and seed_demo:
        demo_pwd = os.getenv("PENTESA_DEMO_ADMIN_PASSWORD") or os.getenv("PENTESA_ADMIN_PASSWORD") or "DevAdmin2026!Complex"
        admin_user = User(
            id=uuid.uuid4(),
            email=os.getenv("PENTESA_ADMIN_EMAIL", "admin@example.com"),
            password_hash=hash_password(demo_pwd),
            full_name="Development Administrator",
            role="ADMIN",
            is_active=True,
        )
        session.add(admin_user)
        await session.flush()

        if os.getenv("PENTESA_SEED_DEMO_PROJECT", "").lower() == "true":
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
                created_by=admin_user.id,
            )
            session.add(demo_project)
            await session.flush()

            membership = ProjectMember(
                id=uuid.uuid4(),
                project_id=demo_project.id,
                user_id=admin_user.id,
                role="LEAD",
            )
            session.add(membership)

        await session.commit()
        logger.info("Initialized development demo data (PENTESA_SEED_DEMO_DATA=1).")
        return

    logger.info("SEC-PWD-01: Zero admin accounts seeded. Set PENTESA_BOOTSTRAP_ADMIN_EMAIL to create admin.")
