"""Unit tests for WSTG mathematical coverage calculation engine."""

import datetime
import uuid
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.project import Project
from database.models.user import User
from database.models.wstg import WSTGTestInstance
from services.execution_engine.coverage import calculate_project_wstg_coverage, compute_metrics
from services.execution_engine.planner import initialize_project_wstg_instances


def test_compute_metrics_formula():
    """Verify exact formula values and edge conditions."""
    # Zero items
    cov, health = compute_metrics(passed=0, failed=0, needs_review=0, not_applicable=0, total=0)
    assert cov == 0.0
    assert health == 0.0

    # 100 total, 50 passed, 20 failed, 10 review, 10 na, 10 not started
    # Covered = 50 + 20 + 10 + 10 = 90 -> 90.0%
    # Health = 50 + 10 = 60 -> 60.0%
    cov, health = compute_metrics(passed=50, failed=20, needs_review=10, not_applicable=10, total=100)
    assert cov == 90.0
    assert health == 60.0

    # 106 total, all passed
    cov, health = compute_metrics(passed=106, failed=0, needs_review=0, not_applicable=0, total=106)
    assert cov == 100.0
    assert health == 100.0


@pytest.mark.asyncio
async def test_calculate_project_wstg_coverage(db_session: AsyncSession, test_project: Project):
    """Verify coverage report generation across all 12 categories for a project."""
    proj = test_project

    # Initialize instances (all 106 Not Started)
    await initialize_project_wstg_instances(db_session, proj.id)

    # Initial report: 0% coverage
    rep1 = await calculate_project_wstg_coverage(db_session, proj.id)
    assert rep1.total_catalog_tests == 106
    assert rep1.overall_coverage_pct == 0.0
    assert rep1.testing_health_score == 0.0
    assert rep1.not_started_count == 106
    assert len(rep1.categories) == 12

    # Manually transition some tests
    result = await db_session.execute(
        select(WSTGTestInstance).where(WSTGTestInstance.project_id == proj.id)
    )
    instances = result.scalars().all()

    # Mark 10 Passed, 5 Failed, 5 Not Applicable
    for i, inst in enumerate(instances[:20]):
        if i < 10:
            inst.status = "Passed"
        elif i < 15:
            inst.status = "Failed"
        else:
            inst.status = "Not Applicable"
            inst.justification = "Test justification"

    await db_session.commit()

    # Recalculate coverage
    rep2 = await calculate_project_wstg_coverage(db_session, proj.id)
    assert rep2.passed_count == 10
    assert rep2.failed_count == 5
    assert rep2.not_applicable_count == 5
    # Covered = 20 / 106 = 18.9%
    # Health = 15 / 106 = 14.2%
    assert rep2.overall_coverage_pct == 18.9
    assert rep2.testing_health_score == 14.2

    # Verify per-category breakdowns
    inpv_cat = rep2.categories["WSTG-INPV"]
    assert inpv_cat.category_code == "WSTG-INPV"
    assert inpv_cat.total_tests == 19
