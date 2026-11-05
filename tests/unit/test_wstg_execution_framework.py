"""Unit tests for WSTG test execution framework, runners, and scope validation."""

import datetime
import uuid
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.discovery import Endpoint
from database.models.project import Project
from database.models.scope import ScopeRule
from database.models.user import User
from database.models.wstg import TestExecution, TestExecutionLog, WSTGTestInstance
from packages.common.exceptions import ScopeViolationException
from services.execution_engine.planner import initialize_project_wstg_instances
from services.execution_engine.runners import (
    ExecutionContext,
    GenericProbeRunner,
    HttpMethodsRunner,
    MetafilesRunner,
    SecurityHeadersRunner,
    execute_wstg_test_run,
    get_runner_for_test
)
from services.scope_engine.service import ScopeEnforcementService


@pytest.mark.asyncio
async def test_scope_enforcement_blocks_out_of_scope_execution(
    db_session: AsyncSession,
    test_project: Project
):
    """Verify that runners refuse to probe out-of-scope destinations."""
    proj = test_project

    # Endpoint targeting unauthorized external host
    ep = Endpoint(
        project_id=proj.id,
        fqdn="malicious-third-party.com",
        url_path="/steal",
        http_method="GET",
        discovery_source="CRAWLER"
    )
    db_session.add(ep)
    await db_session.commit()
    await db_session.refresh(ep)

    # Initialize instances
    await initialize_project_wstg_instances(db_session, proj.id)

    # Fetch instance for HSTS test
    inst_stmt = select(WSTGTestInstance).where(
        WSTGTestInstance.project_id == proj.id,
        WSTGTestInstance.wstg_id == "WSTG-CONF-07"
    )
    instance = (await db_session.execute(inst_stmt)).scalar_one()

    # Create execution record
    exec_record = TestExecution(
        project_id=proj.id,
        wstg_instance_id=instance.id,
        endpoint_id=ep.id,
        status="QUEUED",
        runner_type="AUTOMATED"
    )
    db_session.add(exec_record)
    await db_session.commit()
    await db_session.refresh(exec_record)

    # Execute test run -> should be blocked by ScopeValidator
    executed = await execute_wstg_test_run(db_session, exec_record.id)
    assert executed.status == "FAILED"
    assert executed.exit_code == 1
    assert "Scope violation" in executed.summary
    assert instance.status == "Blocked"


@pytest.mark.asyncio
async def test_security_headers_runner_evaluation(
    db_session: AsyncSession,
    test_project: Project
):
    """Verify SecurityHeadersRunner correctly flags missing and present HSTS headers."""
    proj = test_project

    ep = Endpoint(
        project_id=proj.id,
        fqdn="target.com",
        url_path="/",
        http_method="GET",
        discovery_source="CRAWLER"
    )
    db_session.add(ep)
    await db_session.commit()
    await db_session.refresh(ep)

    await initialize_project_wstg_instances(db_session, proj.id)
    inst_stmt = select(WSTGTestInstance).where(
        WSTGTestInstance.project_id == proj.id,
        WSTGTestInstance.wstg_id == "WSTG-CONF-07"
    )
    instance = (await db_session.execute(inst_stmt)).scalar_one()

    exec_record = TestExecution(
        project_id=proj.id,
        wstg_instance_id=instance.id,
        endpoint_id=ep.id,
        status="QUEUED"
    )
    db_session.add(exec_record)
    await db_session.commit()
    await db_session.refresh(exec_record)

    # 1. Simulate response WITHOUT Strict-Transport-Security -> FAILED
    mock_resp_fail = httpx.Response(status_code=200, headers={"Content-Type": "text/html"})
    with patch("httpx.AsyncClient.get", return_value=mock_resp_fail):
        res1 = await execute_wstg_test_run(db_session, exec_record.id)
        assert res1.status == "FAILED"
        assert res1.exit_code == 1
        assert "Strict-Transport-Security (HSTS) header is missing" in res1.summary
        assert instance.status == "Failed"

    # 2. Simulate response WITH Strict-Transport-Security -> PASSED
    mock_resp_pass = httpx.Response(
        status_code=200,
        headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}
    )
    with patch("httpx.AsyncClient.get", return_value=mock_resp_pass):
        res2 = await execute_wstg_test_run(db_session, exec_record.id)
        assert res2.status == "PASSED"
        assert res2.exit_code == 0
        assert "properly configured" in res2.summary
        assert instance.status == "Passed"


@pytest.mark.asyncio
async def test_execution_log_streaming(db_session: AsyncSession, test_project: Project):
    """Verify test executions stream log messages into test_execution_logs table."""
    proj = test_project

    ep = Endpoint(
        project_id=proj.id,
        fqdn="target.com",
        url_path="/api/data",
        http_method="GET",
        discovery_source="CRAWLER"
    )
    db_session.add(ep)
    await db_session.commit()
    await db_session.refresh(ep)

    await initialize_project_wstg_instances(db_session, proj.id)
    inst_stmt = select(WSTGTestInstance).where(
        WSTGTestInstance.project_id == proj.id,
        WSTGTestInstance.wstg_id == "WSTG-INPV-05"
    )
    instance = (await db_session.execute(inst_stmt)).scalar_one()

    exec_record = TestExecution(
        project_id=proj.id,
        wstg_instance_id=instance.id,
        endpoint_id=ep.id,
        status="QUEUED"
    )
    db_session.add(exec_record)
    await db_session.commit()
    await db_session.refresh(exec_record)

    executed = await execute_wstg_test_run(db_session, exec_record.id)
    assert executed.status == "PASSED"

    # Query streamed logs
    logs_stmt = (
        select(TestExecutionLog)
        .where(TestExecutionLog.execution_id == exec_record.id)
        .order_by(TestExecutionLog.created_at)
    )
    logs = (await db_session.execute(logs_stmt)).scalars().all()
    assert len(logs) >= 2
    assert any("Starting automated execution" in log.message for log in logs)
    assert any("Validation completed cleanly" in log.message for log in logs)
