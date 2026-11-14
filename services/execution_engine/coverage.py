"""OWASP WSTG Mathematical Coverage Engine.

Computes empirical coverage metrics and testing health scores grounded strictly
in test execution outcomes and verified applicability determinations.
Never relies on AI estimations or hallucinated numbers.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.wstg import WSTGTestCatalog, WSTGTestInstance
from packages.schemas.wstg import CoverageCategoryMetrics, WSTGCoverageReport
from services.execution_engine.wstg_catalog_data import WSTG_CATEGORIES


def compute_metrics(
    passed: int,
    failed: int,
    needs_review: int,
    not_applicable: int,
    total: int
) -> tuple[float, float, float]:
    """Compute mathematical coverage percentage, health score, and executed coverage percentage.
    
    Formulae:
        Coverage % = ((Passed + Failed + Needs Review + Not Applicable) / Total) * 100
        Health Score = ((Passed + Not Applicable) / Total) * 100
        Executed Coverage % = ((Passed + Failed + Needs Review) / (Total - Not Applicable)) * 100
    """
    if total <= 0:
        return 0.0, 0.0, 0.0

    covered = passed + failed + needs_review + not_applicable
    healthy = passed + not_applicable
    executed = passed + failed + needs_review
    applicable = total - not_applicable

    coverage_pct = round((covered / total) * 100.0, 1)
    health_score = round((healthy / total) * 100.0, 1)
    executed_cov = round((executed / applicable) * 100.0, 1) if applicable > 0 else 0.0

    # Clamp between 0.0 and 100.0
    coverage_pct = max(0.0, min(100.0, coverage_pct))
    health_score = max(0.0, min(100.0, health_score))
    executed_cov = max(0.0, min(100.0, executed_cov))

    return coverage_pct, health_score, executed_cov


async def calculate_project_wstg_coverage(
    session: AsyncSession,
    project_id: uuid.UUID
) -> WSTGCoverageReport:
    """Calculate comprehensive WSTG coverage report for a project.
    
    Returns:
        Typed WSTGCoverageReport with overall and per-category breakdowns.
    """
    stmt = (
        select(WSTGTestInstance, WSTGTestCatalog)
        .join(WSTGTestCatalog, WSTGTestInstance.wstg_id == WSTGTestCatalog.id)
        .where(WSTGTestInstance.project_id == project_id)
    )
    rows = (await session.execute(stmt)).all()

    # Initialize per-category counts
    cat_counts: Dict[str, Dict[str, int]] = {
        code: {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "needs_review": 0,
            "not_applicable": 0,
            "planned": 0,
            "running": 0,
            "not_started": 0,
        }
        for code in WSTG_CATEGORIES
    }

    total_passed = 0
    total_failed = 0
    total_needs_review = 0
    total_na = 0
    total_planned = 0
    total_running = 0
    total_not_started = 0

    for instance, catalog in rows:
        code = catalog.category_code
        if code not in cat_counts:
            cat_counts[code] = {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "needs_review": 0,
                "not_applicable": 0,
                "planned": 0,
                "running": 0,
                "not_started": 0,
            }

        counts = cat_counts[code]
        counts["total"] += 1
        st = instance.status

        if st == "Passed":
            counts["passed"] += 1
            total_passed += 1
        elif st == "Failed":
            counts["failed"] += 1
            total_failed += 1
        elif st == "Needs Manual Review":
            counts["needs_review"] += 1
            total_needs_review += 1
        elif st == "Not Applicable":
            counts["not_applicable"] += 1
            total_na += 1
        elif st == "Planned":
            counts["planned"] += 1
            total_planned += 1
        elif st == "Running":
            counts["running"] += 1
            total_running += 1
        else:  # "Not Started", "Blocked", "Error"
            counts["not_started"] += 1
            total_not_started += 1

    total_catalog = len(rows)
    overall_cov, overall_health, overall_exec_cov = compute_metrics(
        total_passed, total_failed, total_needs_review, total_na, total_catalog
    )
    applicable_tests = max(0, total_catalog - total_na)

    category_reports: Dict[str, CoverageCategoryMetrics] = {}
    for code, counts in cat_counts.items():
        cov, health, exec_cov = compute_metrics(
            counts["passed"],
            counts["failed"],
            counts["needs_review"],
            counts["not_applicable"],
            counts["total"]
        )
        category_reports[code] = CoverageCategoryMetrics(
            category_code=code,
            category_name=WSTG_CATEGORIES.get(code, code),
            total_tests=counts["total"],
            passed_count=counts["passed"],
            failed_count=counts["failed"],
            needs_review_count=counts["needs_review"],
            not_applicable_count=counts["not_applicable"],
            planned_count=counts["planned"],
            running_count=counts["running"],
            not_started_count=counts["not_started"],
            coverage_pct=cov,
            health_score=health,
            executed_coverage_pct=exec_cov
        )

    return WSTGCoverageReport(
        project_id=project_id,
        overall_coverage_pct=overall_cov,
        testing_health_score=overall_health,
        executed_coverage_pct=overall_exec_cov,
        total_catalog_tests=total_catalog,
        in_scope_tests_count=total_catalog,
        applicable_tests_count=applicable_tests,
        passed_count=total_passed,
        failed_count=total_failed,
        needs_review_count=total_needs_review,
        not_applicable_count=total_na,
        planned_count=total_planned,
        running_count=total_running,
        not_started_count=total_not_started,
        categories=category_reports,
        generated_at=datetime.now(timezone.utc)
    )


class WSTGCoverageService:
    """Service wrapper for mathematical WSTG coverage calculations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def calculate_project_coverage(self, project_id: uuid.UUID) -> WSTGCoverageReport:
        return await calculate_project_wstg_coverage(self.session, project_id)


