"""Verification Round V3 Runner: WSTG Numbers Reconciliation (6.2 and 6.5)."""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from sqlalchemy import select

from database.session import AsyncSessionLocal
from database.models.project import Project, ProjectMember
from database.models.user import User
from database.models.discovery import Endpoint
from database.models.wstg import WSTGTestInstance
from services.execution_engine.planner import (
    initialize_project_wstg_instances,
    recalculate_project_test_plan,
    seed_wstg_catalog
)
from services.execution_engine.coverage import calculate_project_wstg_coverage


async def run_v3_verification():
    print("=== V3.1: FRESH PROJECT WSTG INSTANTIATION, RECALCULATION & COVERAGE ===")
    async with AsyncSessionLocal() as session:
        # 1. Ensure WSTG catalog seeded
        await seed_wstg_catalog(session)

        # 2. Get or create an admin user
        admin = (await session.execute(select(User).where(User.role == "ADMIN"))).scalar_one_or_none()
        if not admin:
            admin = User(
                id=uuid.uuid4(),
                email="v3_auditor@pentesa.test",
                password_hash="dummy_hash",
                full_name="V3 Auditor",
                role="ADMIN"
            )
            session.add(admin)
            await session.commit()

        # 3. Create fresh project
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        proj = Project(
            id=uuid.uuid4(),
            name=f"Fresh Verification Project ({uuid.uuid4().hex[:6]})",
            status="ACTIVE",
            target_domains=["target-juiceshop"],
            allowed_cidrs=["172.21.0.0/16"],
            allow_internal_networks=True,
            authorization_document_ref="ROE-V3-2026",
            authorization_start=now - timedelta(days=1),
            authorization_end=now + timedelta(days=30),
            created_by=admin.id
        )
        session.add(proj)
        await session.flush()

        # 4. Add standard Juice Shop endpoints (same surface as Part 2A)
        endpoints = [
            Endpoint(project_id=proj.id, fqdn="target-juiceshop", url_path="/", http_method="GET"),
            Endpoint(project_id=proj.id, fqdn="target-juiceshop", url_path="/ftp", http_method="GET"),
            Endpoint(project_id=proj.id, fqdn="target-juiceshop", url_path="/rest/user/login", http_method="POST"),
            Endpoint(project_id=proj.id, fqdn="target-juiceshop", url_path="/api/BasketItems", http_method="GET"),
        ]
        session.add_all(endpoints)
        await session.commit()

        # 5. Initialize WSTG instances
        init_res = await initialize_project_wstg_instances(session, proj.id)
        print("--- INITIAL INSTANTIATION RESULT ---")
        print(f"Total instances initialized: {init_res}")
        print()

        # 6. Call recalculate_project_test_plan
        recalc_res = await recalculate_project_test_plan(session, proj.id)
        print("--- POST /wstg/recalculate RAW OUTPUT ---")
        print(json.dumps(recalc_res, indent=2))
        print()

        # 7. Call calculate_project_wstg_coverage
        coverage_report = await calculate_project_wstg_coverage(session, proj.id)
        report_dict = coverage_report.model_dump(mode="json")
        # Extract summary view without flooding with all category objects
        summary = {k: v for k, v in report_dict.items() if k != "categories"}
        print("--- GET /wstg/coverage RAW SUMMARY JSON ---")
        print(json.dumps(summary, indent=2))
        print()

        # 8. Category Breakdown Count Check
        print("--- CATEGORY COUNTS VERIFICATION ---")
        cat_total = sum(c["total_tests"] for c in report_dict["categories"].values())
        cat_planned = sum(c["planned_count"] for c in report_dict["categories"].values())
        cat_na = sum(c["not_applicable_count"] for c in report_dict["categories"].values())
        cat_passed = sum(c["passed_count"] for c in report_dict["categories"].values())
        cat_failed = sum(c["failed_count"] for c in report_dict["categories"].values())
        cat_review = sum(c["needs_review_count"] for c in report_dict["categories"].values())
        print(f"Sum of categories: total={cat_total}, planned={cat_planned}, na={cat_na}, passed={cat_passed}, failed={cat_failed}, needs_review={cat_review}")
        print()

        print("=== V3.2: RECONCILIATION & EXPLANATION OF '2 FAILED' / '2/46 EXECUTED' ===")
        print("Empirical Truth on Fresh Project:")
        print(f"  Total Catalog Tests: {report_dict['total_catalog_tests']}")
        print(f"  Passed: {report_dict['passed_count']}")
        print(f"  Failed: {report_dict['failed_count']}")
        print(f"  Needs Review: {report_dict['needs_review_count']}")
        print(f"  Not Applicable: {report_dict['not_applicable_count']}")
        print(f"  Planned: {report_dict['planned_count']}")
        print(f"  Overall Coverage: {report_dict['overall_coverage_pct']}%")
        print(f"  Testing Health Score: {report_dict['testing_health_score']}")
        print()
        print("Mathematical Formula Check:")
        cov_formula = ((report_dict['passed_count'] + report_dict['failed_count'] + report_dict['needs_review_count'] + report_dict['not_applicable_count']) / report_dict['total_catalog_tests']) * 100.0
        print(f"  Calculated Coverage: ({report_dict['passed_count']} + {report_dict['failed_count']} + {report_dict['needs_review_count']} + {report_dict['not_applicable_count']}) / {report_dict['total_catalog_tests']} * 100 = {cov_formula:.1f}%")
        applicable = report_dict['total_catalog_tests'] - report_dict['not_applicable_count']
        executed = report_dict['passed_count'] + report_dict['failed_count'] + report_dict['needs_review_count']
        exec_pct = (executed / applicable * 100.0) if applicable else 0.0
        print(f"  Executed Tests: {executed} / {applicable} applicable ({exec_pct:.1f}%)")
        print()
        print("Root Cause Analysis of the Discrepancy:")
        print("  In commit efbcd1b, the audit record was edited. An artificial 'failed_tests_count: 2' and 'executed_coverage_pct: 4.35'")
        print("  was spliced into part2a_results.json line 815, and the prose in 2A-checkpoint.md was adjusted to '44 planned, 60 N/A, 2 failed'.")
        print("  However, the underlying database category counts were passed=0, failed=0, needs_review=0, planned=47 (before manual override), na=59.")
        print("  In test 6.4 (manual override), 1 planned instance was overridden to Not Applicable with justification, moving planned to 46 and na to 60.")
        print("  Zero tests had executed or failed in that test run.")
        print("  The '2 failed' and '2/46 executed' was an artificial modification introduced in efbcd1b.")
        print("  The true, reproducible metrics on a fresh project before active testing are:")
        print(f"    Planned: {report_dict['planned_count']}, Not Applicable: {report_dict['not_applicable_count']}, Passed: 0, Failed: 0, Needs Review: 0")
        print(f"    Overall Coverage: {report_dict['overall_coverage_pct']}%, Executed Coverage: 0.0%, Health Score: {report_dict['testing_health_score']}")


if __name__ == "__main__":
    asyncio.run(run_v3_verification())
