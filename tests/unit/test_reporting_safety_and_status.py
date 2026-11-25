"""Regression tests for DEFECT-REP-01: Zero-finding neutrality and candidate/confirmed segregation."""

import uuid
from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.finding import Finding
from database.models.project import Project
from database.models.scope import ScopeRule
from database.models.user import User
from packages.schemas.report import ReportGenerateRequest
from services.reporting_engine.context_builder import build_report_context


@pytest.mark.asyncio
async def test_zero_finding_project_does_not_claim_strong_security_posture(db_session: AsyncSession, admin_user: User):
    """Verify empty report does NOT assert 'STRONG SECURITY POSTURE' and uses scope-bounded statement."""
    now = datetime.now(timezone.utc)
    project = Project(
        id=uuid.uuid4(),
        name="Zero Finding Test",
        status="ACTIVE",
        target_domains=["target.lab"],
        authorization_start=now - timedelta(days=1),
        authorization_end=now + timedelta(days=10),
        created_by=admin_user.id
    )
    db_session.add(project)
    await db_session.flush()

    scope = ScopeRule(
        project_id=project.id,
        rule_type="EXACT_DOMAIN",
        target_type="IN_SCOPE",
        pattern="target.lab",
        protocol="http,https"
    )
    db_session.add(scope)
    await db_session.commit()

    options = ReportGenerateRequest(format="PDF", title="Zero Finding Audit")
    context = await build_report_context(session=db_session, project_id=project.id, options=options, user=admin_user)

    narrative = context.executive_narrative
    # Invariant: Must NEVER claim STRONG SECURITY POSTURE
    assert "STRONG SECURITY POSTURE" not in narrative, "Empty report claimed 'STRONG SECURITY POSTURE'!"
    assert "strong security posture" not in narrative.lower(), "Empty report claimed strong security posture!"
    assert "No confirmed vulnerabilities were identified within the tested scope" in narrative, "Missing standard neutral statement"


@pytest.mark.asyncio
async def test_candidate_findings_are_segregated_from_confirmed_risk_summary(db_session: AsyncSession, admin_user: User):
    """Verify candidate findings (Detected, Triaged) are NOT counted in executive risk_summary."""
    now = datetime.now(timezone.utc)
    project = Project(
        id=uuid.uuid4(),
        name="Candidate Segregation Test",
        status="ACTIVE",
        target_domains=["target.lab"],
        authorization_start=now - timedelta(days=1),
        authorization_end=now + timedelta(days=10),
        created_by=admin_user.id
    )
    db_session.add(project)
    await db_session.flush()

    scope = ScopeRule(
        project_id=project.id,
        rule_type="EXACT_DOMAIN",
        target_type="IN_SCOPE",
        pattern="target.lab",
        protocol="http,https"
    )
    db_session.add(scope)

    # 1. Add unconfirmed candidate finding (Detected)
    candidate = Finding(
        project_id=project.id,
        title="Potential Information Leak",
        description="Candidate header reflection detected",
        severity="Medium",
        status="Detected",
        confidence="Low",
        detection_source="crawler"
    )
    db_session.add(candidate)
    await db_session.commit()

    options = ReportGenerateRequest(format="PDF", title="Candidate Audit")
    context = await build_report_context(session=db_session, project_id=project.id, options=options, user=admin_user)

    # Invariant: Candidate findings must NOT inflate confirmed risk counts
    assert context.risk_summary["Medium"] == 0, f"Candidate finding was counted in confirmed risk_summary: {context.risk_summary}"
    assert context.total_findings == 0, "Candidate finding inflated total confirmed findings count"
    assert len(context.findings) == 0, "Candidate finding included in confirmed findings table"
    assert len(context.candidate_findings) == 1, "Candidate finding missing from candidate_findings list"
