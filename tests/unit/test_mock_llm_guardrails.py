"""Unit tests verifying fail-closed mock LLM guardrails (AGT-MOCK-01).

Guarantees:
1. PENTESA_LLM_PROVIDER=mock can only be instantiated when PENTESA_ENV=test.
2. Selecting mock in development, staging, or production raises RuntimeError.
3. Startup validation fails closed if mock is selected in non-test environments or if provider is unset outside test.
4. In PENTESA_ENV=test, empty provider safely defaults to MockLLMProvider.
5. Findings created under mock or simulation are tagged with [SIMULATED] and is_simulated=True.
6. Report generation context builder suppresses all simulated findings.
"""

import os
import uuid
from datetime import datetime, timezone
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from agents.llm.provider import MockLLMProvider, get_default_llm_provider
from apps.api.main import app, validate_encryption_key_startup
from database.models.finding import Finding
from database.models.project import Project
from database.models.user import User
from packages.common.config import settings
from packages.schemas.finding import FindingCreate
from packages.schemas.report import ReportGenerateRequest
from services.evidence_engine.finding_service import FindingService
from services.reporting_engine.context_builder import build_report_context


def test_mock_llm_rejected_in_development(monkeypatch):
    """PENTESA_LLM_PROVIDER=mock must fail in development."""
    monkeypatch.setattr(settings, "env", "development")
    monkeypatch.setattr(settings, "llm_provider", "mock")

    with pytest.raises(RuntimeError, match="strictly restricted to PENTESA_ENV=test"):
        get_default_llm_provider()


def test_mock_llm_rejected_in_production(monkeypatch):
    """PENTESA_LLM_PROVIDER=mock must fail in production."""
    monkeypatch.setattr(settings, "env", "production")
    monkeypatch.setattr(settings, "llm_provider", "mock")

    with pytest.raises(RuntimeError, match="strictly restricted to PENTESA_ENV=test"):
        get_default_llm_provider()


def test_mock_llm_rejected_in_staging(monkeypatch):
    """PENTESA_LLM_PROVIDER=mock must fail in staging."""
    monkeypatch.setattr(settings, "env", "staging")
    monkeypatch.setattr(settings, "llm_provider", "mock")

    with pytest.raises(RuntimeError, match="strictly restricted to PENTESA_ENV=test"):
        get_default_llm_provider()


def test_unconfigured_provider_fails_outside_test(monkeypatch):
    """Unset PENTESA_LLM_PROVIDER outside test must fail closed."""
    monkeypatch.setattr(settings, "env", "development")
    monkeypatch.setattr(settings, "llm_provider", "")

    with pytest.raises(RuntimeError, match="PENTESA_LLM_PROVIDER is not configured"):
        get_default_llm_provider()


def test_mock_llm_permitted_in_test(monkeypatch):
    """In test environment, mock is permitted and serves as default if unset."""
    monkeypatch.setattr(settings, "env", "test")
    monkeypatch.setattr(settings, "llm_provider", "mock")
    provider = get_default_llm_provider()
    assert isinstance(provider, MockLLMProvider)

    # Empty provider also defaults to mock in test
    monkeypatch.setattr(settings, "llm_provider", "")
    provider_default = get_default_llm_provider()
    assert isinstance(provider_default, MockLLMProvider)


def test_startup_validation_refuses_mock_in_production(monkeypatch):
    """API startup fails closed if PENTESA_LLM_PROVIDER=mock in production."""
    monkeypatch.setenv("PENTESA_ENV", "production")
    monkeypatch.setenv("PENTESA_LLM_PROVIDER", "mock")
    monkeypatch.setenv("PENTESA_ENCRYPTION_KEY", "unique-super-strong-vault-key-32b-length!")
    monkeypatch.setenv("PENTESA_SECRET_KEY", "unique-jwt-signing-secret-key-32b-length!")
    monkeypatch.setenv("PENTESA_DATABASE_URL", "postgresql+asyncpg://p_user:strong_pwd_123!@db:5432/p_db")
    monkeypatch.setattr(settings, "env", "production")
    monkeypatch.setattr(settings, "llm_provider", "mock")

    with pytest.raises(RuntimeError, match="strictly restricted to PENTESA_ENV='test'"):
        validate_encryption_key_startup()


def test_startup_validation_refuses_unset_provider_in_production(monkeypatch):
    """API startup fails closed if PENTESA_LLM_PROVIDER is unset in production."""
    monkeypatch.setenv("PENTESA_ENV", "production")
    monkeypatch.delenv("PENTESA_LLM_PROVIDER", raising=False)
    monkeypatch.setenv("PENTESA_ENCRYPTION_KEY", "unique-super-strong-vault-key-32b-length!")
    monkeypatch.setenv("PENTESA_SECRET_KEY", "unique-jwt-signing-secret-key-32b-length!")
    monkeypatch.setenv("PENTESA_DATABASE_URL", "postgresql+asyncpg://p_user:strong_pwd_123!@db:5432/p_db")
    monkeypatch.setattr(settings, "env", "production")
    monkeypatch.setattr(settings, "llm_provider", "")

    with pytest.raises(RuntimeError, match="PENTESA_LLM_PROVIDER is not configured"):
        validate_encryption_key_startup()


@pytest.mark.asyncio
async def test_simulated_finding_tagged_and_excluded_from_report(db_session: AsyncSession, admin_user: User, monkeypatch):
    """Findings created under mock/simulation are tagged [SIMULATED] and excluded from reports."""
    from datetime import timedelta
    monkeypatch.setattr(settings, "llm_provider", "mock")

    now = datetime.now(timezone.utc)
    # Create test project
    project = Project(
        id=uuid.uuid4(),
        name="AGT-MOCK Test Project",
        description="Testing mock finding tagging",
        target_domains=["example.test"],
        allowed_cidrs=[],
        excluded_paths=[],
        allow_internal_networks=False,
        authorization_start=now,
        authorization_end=now + timedelta(days=7),
        created_by=admin_user.id
    )
    db_session.add(project)
    await db_session.commit()
    await db_session.refresh(project)

    # Create finding via FindingService
    finding_svc = FindingService(db_session)
    finding_payload = FindingCreate(
        title="SQL Injection in Login Form",
        description="Parameter 'user' is vulnerable to boolean-based SQL injection.",
        severity="High",
        status="Confirmed",
        confidence="High"
    )
    finding = await finding_svc.create_finding(project.id, finding_payload)
    await db_session.commit()

    # 1. Verify finding title and flag
    assert finding.title.startswith("[SIMULATED] ")
    assert finding.title == "[SIMULATED] SQL Injection in Login Form"
    assert finding.is_simulated is True

    # Also create a non-simulated finding directly in DB
    real_finding = Finding(
        id=uuid.uuid4(),
        project_id=project.id,
        title="Real Vulnerability Missing Security Headers",
        description="X-Frame-Options is missing.",
        severity="Low",
        status="Confirmed",
        confidence="High",
        detection_source="manual",
        is_simulated=False
    )
    db_session.add(real_finding)
    await db_session.commit()

    # 2. Build report context and assert simulated finding is excluded
    report_options = ReportGenerateRequest(
        project_id=project.id,
        format="HTML"
    )
    context = await build_report_context(db_session, project.id, report_options)

    # Assert only the non-simulated finding appears in report context
    report_finding_titles = [f.title for f in context.findings]
    assert "Real Vulnerability Missing Security Headers" in report_finding_titles
    assert not any("[SIMULATED]" in t for t in report_finding_titles)
    assert len(context.findings) == 1
