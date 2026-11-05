"""Unit tests for WSTG test planner, applicability engine, and state transitions."""

import datetime
import uuid
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.discovery import Endpoint
from database.models.project import Project
from database.models.user import User
from database.models.wstg import WSTGTestCatalog, WSTGTestInstance
from packages.common.exceptions import BadRequestException
from services.execution_engine.planner import (
    initialize_project_wstg_instances,
    recalculate_project_test_plan,
    seed_wstg_catalog,
    validate_status_transition
)


def test_wstg_status_transitions():
    """Verify state transition rules adherence and rejection of illegal states."""
    # Valid transitions from Not Started
    validate_status_transition("Not Started", "Planned")
    validate_status_transition("Not Started", "Not Applicable", justification="Out of scope technology")

    # Invalid: Not Started -> Passed without running
    with pytest.raises(BadRequestException, match="Invalid WSTG status transition"):
        validate_status_transition("Not Started", "Passed")

    # Missing justification when setting Not Applicable
    with pytest.raises(BadRequestException, match="requires an explicit justification"):
        validate_status_transition("Planned", "Not Applicable", justification=None)

    # Valid running transitions
    validate_status_transition("Running", "Passed")
    validate_status_transition("Running", "Failed")
    validate_status_transition("Running", "Needs Manual Review")
    validate_status_transition("Running", "Blocked")
    validate_status_transition("Running", "Error")

    # Overriding terminal status requires justification
    validate_status_transition("Passed", "Failed", justification="Secondary inspection confirmed false positive clean")
    with pytest.raises(BadRequestException, match="requires an explicit justification"):
        validate_status_transition("Passed", "Failed", justification="")


@pytest.mark.asyncio
async def test_initialize_project_wstg_instances(db_session: AsyncSession, test_project: Project):
    """Verify that all 106 WSTG tests are initialized for a project in 'Not Started' state."""
    proj = test_project

    # Initialize instances
    created = await initialize_project_wstg_instances(db_session, proj.id)
    assert created == 106

    # Verify instances in DB
    result = await db_session.execute(
        select(WSTGTestInstance).where(WSTGTestInstance.project_id == proj.id)
    )
    instances = result.scalars().all()
    assert len(instances) == 106
    assert all(i.status == "Not Started" for i in instances)

    # Idempotent second call creates 0
    created2 = await initialize_project_wstg_instances(db_session, proj.id)
    assert created2 == 0


@pytest.mark.asyncio
async def test_recalculate_project_applicability(db_session: AsyncSession, test_project: Project):
    """Verify that discovering endpoints dynamically marks tests as Planned or Not Applicable."""
    proj = test_project

    # Add endpoints with parameters, auth, and API paths
    ep1 = Endpoint(
        project_id=proj.id,
        fqdn="app.acme.com",
        url_path="/api/v1/search",
        http_method="GET",
        parameter_schema={"query": ["q", "page"], "body": []},
        content_type="application/json",
        auth_required=False,
        discovery_source="CRAWLER"
    )
    ep2 = Endpoint(
        project_id=proj.id,
        fqdn="app.acme.com",
        url_path="/auth/login",
        http_method="POST",
        parameter_schema={"query": [], "body": ["username", "password"]},
        content_type="application/x-www-form-urlencoded",
        auth_required=False,
        discovery_source="CRAWLER"
    )
    db_session.add_all([ep1, ep2])
    await db_session.commit()

    # Recalculate plan
    summary = await recalculate_project_test_plan(db_session, proj.id)
    assert summary["total_instances"] == 106
    assert summary["planned_count"] > 0
    assert summary["not_applicable_count"] > 0

    # Verify SQL Injection (WSTG-INPV-05) is now Planned due to ep1 having query parameters
    sqli_stmt = select(WSTGTestInstance).where(
        WSTGTestInstance.project_id == proj.id,
        WSTGTestInstance.wstg_id == "WSTG-INPV-05"
    )
    sqli_inst = (await db_session.execute(sqli_stmt)).scalar_one()
    assert sqli_inst.status == "Planned"
    assert sqli_inst.applicable_endpoints_count >= 1

    # Verify Authentication test (WSTG-ATHN-01) is Planned due to ep2 (/auth/login)
    auth_stmt = select(WSTGTestInstance).where(
        WSTGTestInstance.project_id == proj.id,
        WSTGTestInstance.wstg_id == "WSTG-ATHN-01"
    )
    auth_inst = (await db_session.execute(auth_stmt)).scalar_one()
    assert auth_inst.status == "Planned"

    # Verify Legacy Flash (WSTG-CLNT-08) is marked Not Applicable with justification
    flash_stmt = select(WSTGTestInstance).where(
        WSTGTestInstance.project_id == proj.id,
        WSTGTestInstance.wstg_id == "WSTG-CLNT-08"
    )
    flash_inst = (await db_session.execute(flash_stmt)).scalar_one()
    assert flash_inst.status == "Not Applicable"
    assert "Flash" in flash_inst.justification
