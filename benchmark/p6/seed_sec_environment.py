"""
Seed Script for Phase 6 Security Audit Stack (pentesa-sec).
Executes out-of-band directly against postgresql://127.0.0.1:5433/pentesa_sec.
Reads untracked credentials from .env.sec.
NEVER prints or leaks passwords or JWT tokens to stdout.
"""

import asyncio
import datetime
import os
import sys
import uuid
from typing import Dict

from dotenv import dotenv_values
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from database.base import Base
from database.models.auth_profile import AuthProfile
from database.models.discovery import Endpoint
from database.models.finding import Finding
from database.models.project import Project, ProjectMember
from database.models.scope import ScopeRule
from database.models.user import User
from packages.common.security import hash_password


async def seed_sec_environment():
    env_path = os.path.join(REPO_ROOT, ".env.sec")
    if not os.path.exists(env_path):
        print("ERROR: .env.sec does not exist! Aborting.", file=sys.stderr)
        sys.exit(1)

    cfg = dotenv_values(env_path)
    pg_user = cfg.get("POSTGRES_USER", "pentesa_user")
    pg_pwd = cfg.get("POSTGRES_PASSWORD")
    pg_db = cfg.get("POSTGRES_DB", "pentesa_sec")

    if not pg_pwd:
        print("ERROR: POSTGRES_PASSWORD missing in .env.sec!", file=sys.stderr)
        sys.exit(1)

    db_url = f"postgresql+asyncpg://{pg_user}:{pg_pwd}@127.0.0.1:5433/{pg_db}"
    engine = create_async_engine(db_url, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        # Ensure all tables exist
        await conn.run_sync(Base.metadata.create_all)

    async with async_session() as session:
        # Clear existing data for idempotent seeding
        from sqlalchemy import text
        await session.execute(text("TRUNCATE TABLE users, projects, project_members, scope_rules, findings, auth_profiles CASCADE;"))
        await session.commit()

        now = datetime.datetime.now(datetime.timezone.utc)
        auth_end = now + datetime.timedelta(days=60)

        # ---------------------------------------------------------------------
        # 1. Provision Tenant A Users
        # ---------------------------------------------------------------------
        user_a_admin = User(
            id=uuid.uuid4(),
            email=cfg["USER_A_ADMIN_EMAIL"],
            password_hash=hash_password(cfg["USER_A_ADMIN_PASSWORD"]),
            full_name="Tenant A Administrator",
            role="ADMIN",
            is_active=True,
        )
        user_a_member = User(
            id=uuid.uuid4(),
            email=cfg["USER_A_MEMBER_EMAIL"],
            password_hash=hash_password(cfg["USER_A_MEMBER_PASSWORD"]),
            full_name="Tenant A Security Tester",
            role="TESTER",
            is_active=True,
        )
        user_a_viewer = User(
            id=uuid.uuid4(),
            email=cfg["USER_A_VIEWER_EMAIL"],
            password_hash=hash_password(cfg["USER_A_VIEWER_PASSWORD"]),
            full_name="Tenant A Auditor Viewer",
            role="TESTER",
            is_active=True,
        )

        # ---------------------------------------------------------------------
        # 2. Provision Tenant B Users
        # ---------------------------------------------------------------------
        user_b_admin = User(
            id=uuid.uuid4(),
            email=cfg["USER_B_ADMIN_EMAIL"],
            password_hash=hash_password(cfg["USER_B_ADMIN_PASSWORD"]),
            full_name="Tenant B Project Lead",
            role="TESTER",  # Non-system admin, but lead of Tenant B
            is_active=True,
        )
        user_b_member = User(
            id=uuid.uuid4(),
            email=cfg["USER_B_MEMBER_EMAIL"],
            password_hash=hash_password(cfg["USER_B_MEMBER_PASSWORD"]),
            full_name="Tenant B Security Member",
            role="TESTER",
            is_active=True,
        )

        session.add_all([user_a_admin, user_a_member, user_a_viewer, user_b_admin, user_b_member])
        await session.commit()
        print(f"[+] Successfully seeded 5 users across Tenant A and Tenant B.")

        # ---------------------------------------------------------------------
        # 3. Provision Project A (Tenant A)
        # ---------------------------------------------------------------------
        proj_a = Project(
            id=uuid.uuid4(),
            name="Project Alpha (Tenant A)",
            description="Tenant A Primary Banking Infrastructure Engagement",
            status="RUNNING",
            target_domains=["bench-pentesa-app.internal", "alpha.sec.test"],
            allowed_cidrs=["172.19.0.0/16", "172.21.0.0/16"],
            excluded_paths=["/admin/purge", "/logout"],
            allow_internal_networks=True,
            authorization_document_ref="ROE-TENANT-A-2026-001",
            authorization_start=now,
            authorization_end=auth_end,
            created_by=user_a_admin.id,
        )
        session.add(proj_a)
        await session.commit()

        # Memberships for Project A
        members_a = [
            ProjectMember(project_id=proj_a.id, user_id=user_a_admin.id, role="LEAD"),
            ProjectMember(project_id=proj_a.id, user_id=user_a_member.id, role="TESTER"),
            ProjectMember(project_id=proj_a.id, user_id=user_a_viewer.id, role="VIEWER"),
        ]
        session.add_all(members_a)

        # Scope rules for Project A
        scope_a1 = ScopeRule(
            project_id=proj_a.id,
            target_type="DOMAIN",
            pattern="alpha.sec.test",
            rule_type="INCLUDE",
        )
        scope_a2 = ScopeRule(
            project_id=proj_a.id,
            target_type="PATH",
            pattern="/admin/purge",
            rule_type="EXCLUDE",
        )
        session.add_all([scope_a1, scope_a2])
        await session.commit()
        print(f"[+] Provisioned Project Alpha (ID: {proj_a.id}) with 3 members and 2 scope rules.")

        # ---------------------------------------------------------------------
        # 4. Provision Project B (Tenant B)
        # ---------------------------------------------------------------------
        proj_b = Project(
            id=uuid.uuid4(),
            name="Project Beta (Tenant B)",
            description="Tenant B E-Commerce & Retail Assessment",
            status="RUNNING",
            target_domains=["bench-juiceshop.internal", "beta.sec.test"],
            allowed_cidrs=["172.19.0.0/16"],
            excluded_paths=["/rest/admin/delete"],
            allow_internal_networks=True,
            authorization_document_ref="ROE-TENANT-B-2026-002",
            authorization_start=now,
            authorization_end=auth_end,
            created_by=user_b_admin.id,
        )
        session.add(proj_b)
        await session.commit()

        # Memberships for Project B (User A is NOT a member)
        members_b = [
            ProjectMember(project_id=proj_b.id, user_id=user_b_admin.id, role="LEAD"),
            ProjectMember(project_id=proj_b.id, user_id=user_b_member.id, role="TESTER"),
        ]
        session.add_all(members_b)

        scope_b1 = ScopeRule(
            project_id=proj_b.id,
            target_type="DOMAIN",
            pattern="beta.sec.test",
            rule_type="INCLUDE",
        )
        scope_b2 = ScopeRule(
            project_id=proj_b.id,
            target_type="PATH",
            pattern="/rest/admin/delete",
            rule_type="EXCLUDE",
        )
        session.add_all([scope_b1, scope_b2])
        await session.commit()
        print(f"[+] Provisioned Project Beta (ID: {proj_b.id}) with 2 members and 2 scope rules.")

        # Seed initial findings for IDOR testing
        finding_a = Finding(
            id=uuid.uuid4(),
            project_id=proj_a.id,
            title="Tenant A Sensitive Data Disclosure",
            description="Proprietary financial balance endpoint exposed to authorized users.",
            severity="High",
            status="Confirmed",
            detection_source="manual",
            cwe_id="CWE-200",
            affected_parameter="account_id",
            confidence="High",
        )
        finding_b = Finding(
            id=uuid.uuid4(),
            project_id=proj_b.id,
            title="Tenant B Customer Order Secret",
            description="Customer transaction order details accessible via order_id.",
            severity="Medium",
            status="Confirmed",
            detection_source="manual",
            cwe_id="CWE-639",
            affected_parameter="order_id",
            confidence="High",
        )
        session.add_all([finding_a, finding_b])
        await session.commit()
        print(f"[+] Seeded baseline findings for cross-tenant access testing.")

    await engine.dispose()
    print("[+] Seeding of Phase 6 pentesa-sec environment COMPLETE.")


if __name__ == "__main__":
    asyncio.run(seed_sec_environment())
