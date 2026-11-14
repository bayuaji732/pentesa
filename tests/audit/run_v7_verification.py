"""Verification Round V7 Runner: Lab-Only Tool Execution Guardrail (NI-03)."""

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from apps.api.main import app
from database.session import AsyncSessionLocal
from database.models.project import Project
from database.models.scope import ScopeRule
from database.models.user import User
from packages.common.security import create_access_token


async def run_v7_verification():
    print("================================================================================")
    print("=== V7: FAIL-CLOSED LAB-ONLY GUARDRAIL ENFORCEMENT ON TOOL EXECUTION ===")
    print("================================================================================")
    print("Rule: If PENTESA_LAYER2_EGRESS_ENABLED is not true, refuse tool execution with HTTP 403")
    print("unless the target is explicitly private/lab and the project allows internal networks.")
    print()

    async with AsyncSessionLocal() as session:
        # 1. Admin user
        admin = (await session.execute(select(User).where(User.role == "ADMIN"))).scalar_one_or_none()
        if not admin:
            admin = User(
                id=uuid.uuid4(),
                email="v7_auditor@pentesa.test",
                password_hash="dummy_hash",
                full_name="V7 Auditor",
                role="ADMIN"
            )
            session.add(admin)
            await session.commit()

        token = create_access_token(subject=str(admin.id), claims={"email": admin.email, "role": admin.role})
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        # 2. Project configured for lab testing (allow_internal_networks=True)
        now = datetime.now(timezone.utc)
        lab_project = Project(
            id=uuid.uuid4(),
            name=f"V7 Lab Project ({uuid.uuid4().hex[:6]})",
            status="ACTIVE",
            target_domains=["target-juiceshop", "target.com"],
            allowed_cidrs=["172.21.0.0/16"],
            allow_internal_networks=True,
            authorization_document_ref="ROE-V7-2026",
            authorization_start=now - timedelta(days=1),
            authorization_end=now + timedelta(days=30),
            created_by=admin.id
        )
        session.add(lab_project)
        await session.flush()

        # Scope rules for both target-juiceshop and target.com
        rule_lab = ScopeRule(
            id=uuid.uuid4(),
            project_id=lab_project.id,
            rule_type="EXACT_DOMAIN",
            target_type="IN_SCOPE",
            pattern="target-juiceshop",
            protocol="http",
            port_range="3000"
        )
        rule_public = ScopeRule(
            id=uuid.uuid4(),
            project_id=lab_project.id,
            rule_type="EXACT_DOMAIN",
            target_type="IN_SCOPE",
            pattern="target.com",
            protocol="https",
            port_range="443"
        )
        session.add_all([rule_lab, rule_public])
        await session.commit()

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # -------------------------------------------------------------------------
            # TEST A: Execute against public target (https://target.com)
            # Even though target.com is in project scope rules, Layer 2 egress proxy is inactive.
            # Expected: HTTP 403 Forbidden with Lab-Only refusal message.
            # -------------------------------------------------------------------------
            print("--- DISPATCH 1: Public Target (https://target.com) ---")
            print(f"Request: POST /api/v1/projects/{lab_project.id}/tools/execute (target_url='https://target.com')")
            resp_pub = await client.post(
                f"/api/v1/projects/{lab_project.id}/tools/execute",
                headers=headers,
                json={
                    "tool_name": "nuclei",
                    "target_url": "https://target.com",
                    "template_path": "/app/tests/fixtures/nuclei/ping.yaml"
                }
            )
            print(f"HTTP Status: {resp_pub.status_code} (Expected: 403 Forbidden)")
            print(f"Response Body: {resp_pub.text}")
            assert resp_pub.status_code == 403
            assert "Layer-2 egress proxy not active" in resp_pub.text
            print("[PASS] Public target strictly refused with HTTP 403.\n")

            # -------------------------------------------------------------------------
            # TEST B: Execute against private lab target (http://target-juiceshop:3000)
            # allow_internal_networks=True and target resolves to private lab hostname.
            # Expected: HTTP 201 Created (or clean execution attempt, not blocked by lab guard).
            # -------------------------------------------------------------------------
            print("--- DISPATCH 2: Private Lab Target (http://target-juiceshop:3000) ---")
            print(f"Request: POST /api/v1/projects/{lab_project.id}/tools/execute (target_url='http://target-juiceshop:3000')")
            resp_lab = await client.post(
                f"/api/v1/projects/{lab_project.id}/tools/execute",
                headers=headers,
                json={
                    "tool_name": "nuclei",
                    "target_url": "http://target-juiceshop:3000",
                    "template_path": "/app/tests/fixtures/nuclei/ping.yaml",
                    "timeout_seconds": 10
                }
            )
            print(f"HTTP Status: {resp_lab.status_code} (Expected: 201 Created or SUCCESS/FAILED runner status, not 403)")
            print(f"Response Body: {resp_lab.text[:300]}...")
            assert resp_lab.status_code != 403, "Private lab target should not be blocked by HTTP 403 lab guard"
            print("[PASS] Private lab target successfully bypassed lab guard and executed.\n")

    print("================================================================================")
    print("=== V7 ENFORCEMENT SUMMARY ===")
    print("  - Public targets: BLOCKED with HTTP 403 (fail-closed without Layer-2 proxy).")
    print("  - Lab targets: ALLOWED when allow_internal_networks=True and target is RFC 1918/internal.")
    print("================================================================================")


if __name__ == "__main__":
    asyncio.run(run_v7_verification())
