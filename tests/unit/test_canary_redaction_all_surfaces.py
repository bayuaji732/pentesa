"""Regression tests for DEFECT-REDACT-01: Comprehensive secret and canary redaction across all surfaces."""

import uuid
from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.auth_profile import AuthProfile
from database.models.project import Project
from database.models.scope import ScopeRule
from database.models.user import User
from packages.schemas.finding import FindingCreate
from packages.schemas.report import ReportGenerateRequest
from services.evidence_engine.finding_service import FindingService
from services.evidence_engine.redactor import redact_custom_secrets, redact_raw_stream
from services.reporting_engine.context_builder import build_report_context


@pytest.mark.asyncio
async def test_auth_profile_and_canary_scrubbed_across_all_surfaces(db_session: AsyncSession, admin_user: User, monkeypatch):
    """Verify custom secrets from AuthProfile and planted canaries are scrubbed from finding fields and evidence."""
    monkeypatch.setenv("PENTESA_ENCRYPTION_KEY", "test-encryption-key-32-chars-long!")
    now = datetime.now(timezone.utc)
    project = Project(
        id=uuid.uuid4(),
        name="Canary Redaction Test Project",
        status="ACTIVE",
        target_domains=["target.lab"],
        authorization_start=now - timedelta(days=1),
        authorization_end=now + timedelta(days=10),
        created_by=admin_user.id
    )
    db_session.add(project)
    await db_session.flush()

    # 1. Plant an AuthProfile with custom secret
    custom_secret_token = "VAULT_API_TOKEN_XYZ_987654321"
    auth_prof = AuthProfile(
        id=uuid.uuid4(),
        project_id=project.id,
        name="Target API Credentials",
        auth_type="API_KEY",
        is_active=True
    )
    auth_prof.set_credentials({"api_key": custom_secret_token, "client_secret": "PROD_CLIENT_SECRET_SECURE_1234"})
    db_session.add(auth_prof)
    await db_session.commit()

    planted_canary = "PENTESA_P7_CANARY_SECRET_9f8e7d6c"
    raw_req = (
        f"POST /api/v1/auth/login HTTP/1.1\r\n"
        f"Host: target.lab\r\n"
        f"X-Custom-Auth: {custom_secret_token}\r\n"
        f"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummytoken123456789\r\n"
        f"Content-Type: application/json\r\n\r\n"
        f'{{"canary":"{planted_canary}","key":"{custom_secret_token}"}}'
    )
    raw_resp = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: application/json\r\n\r\n"
        f'{{"status":"ok","vault_secret":"{custom_secret_token}","canary":"{planted_canary}"}}'
    )

    finding_service = FindingService(session=db_session)
    create_payload = FindingCreate(
        title=f"Injection with secret {custom_secret_token}",
        description=f"Planted canary in description: {planted_canary} and secret {custom_secret_token}",
        severity="High",
        status="Confirmed",
        confidence="Confirmed",
        remediation_guidance=f"Ensure {custom_secret_token} is rotated immediately.",
        reproduction_curl=f"curl -H 'X-Custom-Auth: {custom_secret_token}' https://target.lab/api/v1/auth/login",
        raw_request=raw_req,
        raw_response=raw_resp
    )

    finding = await finding_service.create_finding(
        project_id=project.id,
        payload=create_payload,
        user_id=admin_user.id
    )

    # Invariant: Neither the AuthProfile secret nor planted canary must exist in ANY finding field
    assert custom_secret_token not in finding.title, "AuthProfile secret leaked in finding.title"
    assert custom_secret_token not in finding.description, "AuthProfile secret leaked in finding.description"
    assert custom_secret_token not in finding.remediation_guidance, "AuthProfile secret leaked in remediation_guidance"
    assert planted_canary not in finding.description, "Canary secret leaked in finding.description"

    # Invariant: Neither must exist in forensic evidence fields
    evidence = finding.evidence[0]
    assert custom_secret_token not in evidence.raw_request, "AuthProfile secret leaked in evidence.raw_request"
    assert custom_secret_token not in evidence.raw_response, "AuthProfile secret leaked in evidence.raw_response"
    assert custom_secret_token not in evidence.reproduction_curl, "AuthProfile secret leaked in reproduction_curl"
    assert planted_canary not in evidence.raw_request, "Canary secret leaked in evidence.raw_request"
    assert planted_canary not in evidence.raw_response, "Canary secret leaked in evidence.raw_response"

    # Invariant: Neither must exist in generated ReportContext
    options = ReportGenerateRequest(format="HTML", title="Redaction Audit")
    ctx = await build_report_context(session=db_session, project_id=project.id, options=options, user=admin_user)
    finding_item = ctx.findings[0]
    assert custom_secret_token not in finding_item.description, "AuthProfile secret leaked in ReportContext finding description"
    assert planted_canary not in finding_item.description, "Canary leaked in ReportContext finding description"
    assert custom_secret_token not in (finding_item.raw_request or ""), "AuthProfile secret leaked in ReportContext raw_request"
    assert planted_canary not in (finding_item.raw_response or ""), "Canary leaked in ReportContext raw_response"


def test_benign_text_preserved_without_over_redaction():
    """Verify common short words or standard text are NOT over-redacted."""
    prose = "The administrator tested the HTTP API endpoint and found true negative results."
    # Secrets containing common stopwords
    secrets = ["admin", "test", "http", "true"]
    result = redact_custom_secrets(prose, secrets)
    assert result == prose, "Benign prose was corrupted by common word stoplist over-redaction!"


def test_redact_raw_stream_fail_closed_on_none_or_empty():
    """Verify empty or None streams fail closed safely."""
    assert redact_raw_stream("") == ""
    assert redact_raw_stream(None) == ""
