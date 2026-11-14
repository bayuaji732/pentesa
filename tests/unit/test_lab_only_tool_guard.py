"""Unit regression tests verifying the fail-closed lab-only tool execution guard (NI-03, V7)."""

import uuid
from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.project import Project
from database.models.scope import ScopeRule
from database.models.user import User
from integrations.nuclei.runner import NucleiRunner
from packages.common.exceptions import ScopeViolationError


@pytest.mark.asyncio
async def test_public_target_refused_when_layer2_proxy_disabled(db_session: AsyncSession, admin_user: User, monkeypatch):
    """When Layer-2 proxy is disabled, public targets must be refused immediately."""
    monkeypatch.delenv("PENTESA_LAYER2_EGRESS_ENABLED", raising=False)

    now = datetime.now(timezone.utc)
    proj = Project(
        id=uuid.uuid4(),
        name="Public Target Project",
        target_domains=["target.com"],
        allowed_cidrs=["93.184.216.34/32"],
        allow_internal_networks=False,
        authorization_document_ref="ROE-TEST",
        authorization_start=now,
        authorization_end=now + timedelta(days=7),
        created_by=admin_user.id
    )
    db_session.add(proj)
    await db_session.commit()

    runner = NucleiRunner()
    with pytest.raises(ScopeViolationError) as exc_info:
        await runner.validate_scope(db_session, proj.id, "https://target.com")

    assert "Layer-2 egress proxy not active" in str(exc_info.value)
    assert "refused with HTTP 403" in str(exc_info.value)


@pytest.mark.asyncio
async def test_lab_target_refused_if_allow_internal_networks_false(db_session: AsyncSession, admin_user: User, monkeypatch):
    """Private targets must still be refused if allow_internal_networks is False."""
    monkeypatch.delenv("PENTESA_LAYER2_EGRESS_ENABLED", raising=False)

    now = datetime.now(timezone.utc)
    proj = Project(
        id=uuid.uuid4(),
        name="Lab Target Without Internal Flag",
        target_domains=["target-juiceshop"],
        allowed_cidrs=["172.21.0.0/16"],
        allow_internal_networks=False,  # Disallowed
        authorization_document_ref="ROE-TEST",
        authorization_start=now,
        authorization_end=now + timedelta(days=7),
        created_by=admin_user.id
    )
    db_session.add(proj)
    await db_session.commit()

    runner = NucleiRunner()
    with pytest.raises(ScopeViolationError) as exc_info:
        await runner.validate_scope(db_session, proj.id, "http://target-juiceshop:3000")

    assert "Layer-2 egress proxy not active" in str(exc_info.value)


@pytest.mark.asyncio
async def test_lab_target_allowed_when_private_and_flag_enabled(db_session: AsyncSession, admin_user: User, monkeypatch):
    """Private lab targets are allowed when allow_internal_networks=True and in scope."""
    monkeypatch.delenv("PENTESA_LAYER2_EGRESS_ENABLED", raising=False)

    now = datetime.now(timezone.utc)
    proj = Project(
        id=uuid.uuid4(),
        name="Lab Target Authorized",
        target_domains=["target-juiceshop"],
        allowed_cidrs=["172.21.0.0/16"],
        allow_internal_networks=True,
        authorization_document_ref="ROE-TEST",
        authorization_start=now,
        authorization_end=now + timedelta(days=7),
        created_by=admin_user.id
    )
    db_session.add(proj)
    await db_session.flush()

    rule = ScopeRule(
        id=uuid.uuid4(),
        project_id=proj.id,
        rule_type="EXACT_DOMAIN",
        target_type="IN_SCOPE",
        pattern="target-juiceshop",
        protocol="http",
        port_range="3000"
    )
    db_session.add(rule)
    await db_session.commit()

    runner = NucleiRunner()
    # Should complete without error
    await runner.validate_scope(db_session, proj.id, "http://target-juiceshop:3000")


@pytest.mark.asyncio
async def test_layer2_proxy_enabled_bypasses_lab_only_restriction(db_session: AsyncSession, admin_user: User, monkeypatch):
    """When Layer-2 proxy is enabled, public targets proceed to standard scope check."""
    monkeypatch.setenv("PENTESA_LAYER2_EGRESS_ENABLED", "true")

    now = datetime.now(timezone.utc)
    proj = Project(
        id=uuid.uuid4(),
        name="Layer 2 Proxy Project",
        target_domains=["target.com"],
        allowed_cidrs=[],
        allow_internal_networks=False,
        authorization_document_ref="ROE-TEST",
        authorization_start=now,
        authorization_end=now + timedelta(days=7),
        created_by=admin_user.id
    )
    db_session.add(proj)
    await db_session.flush()

    rule = ScopeRule(
        id=uuid.uuid4(),
        project_id=proj.id,
        rule_type="EXACT_DOMAIN",
        target_type="IN_SCOPE",
        pattern="target.com",
        protocol="https",
        port_range="443"
    )
    db_session.add(rule)
    await db_session.commit()

    runner = NucleiRunner()
    # Should not raise "Layer-2 egress proxy not active" error
    await runner.validate_scope(db_session, proj.id, "https://target.com")
