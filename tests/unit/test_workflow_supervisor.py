"""Unit tests for WorkflowSupervisor DAG orchestration, state checkpoints, and approval gates."""

from datetime import datetime, timedelta, timezone
import httpx
import pytest

from agents.base import BaseAgent
from database.models.agent import ApprovalRequest, WorkflowExecution
from packages.common.exceptions import BadRequestError, ProjectAuthorizationExpiredError
from services.execution_engine.runners import BaseTestRunner
from services.orchestrator.supervisor import WorkflowSupervisor


@pytest.fixture(autouse=True)
def offline_agent_http_transport():
    """Avoid external DNS waits in supervisor unit tests targeting mock domains."""
    transport = httpx.MockTransport(
        lambda req: httpx.Response(200, headers={"Content-Type": "text/html"}, text="<html><body>ok</body></html>")
    )
    BaseAgent.default_http_transport = transport
    BaseTestRunner.default_http_transport = transport
    try:
        yield
    finally:
        BaseAgent.default_http_transport = None
        BaseTestRunner.default_http_transport = None


@pytest.mark.asyncio
async def test_supervisor_full_workflow_execution(db_session, test_project, admin_user):
    """Verify end-to-end execution of the multi-agent DAG from PLANNING through COMPLETED."""
    supervisor = WorkflowSupervisor(db_session)

    workflow = await supervisor.start_workflow(
        project_id=test_project.id,
        user_id=admin_user.id
    )

    assert workflow.id is not None
    assert workflow.status == "COMPLETED"
    assert workflow.current_phase == "COMPLETED"
    assert workflow.completed_at is not None
    assert "endpoints_count" in workflow.state_data

    # Verify status query metrics
    status_resp = await supervisor.get_workflow_status(test_project.id)
    assert status_resp.status == "COMPLETED"
    assert len(status_resp.active_agents) >= 7
    phase_by_id = {a.agent_id: a.phase for a in status_resp.active_agents}
    assert phase_by_id["AGT-01"] == "PLANNING"
    assert phase_by_id["AGT-03"] == "RECON"
    assert phase_by_id["AGT-05"] == "WSTG_PLANNING"
    assert phase_by_id["AGT-09"] == "ACTIVE_ASSESSMENT"
    assert phase_by_id["AGT-11"] == "VALIDATION"
    assert phase_by_id["AGT-15"] == "REPORTING"
    assert all(a.prompt_tokens > 0 and a.completion_tokens > 0 for a in status_resp.active_agents)

    decisions = await supervisor.list_agent_decisions(test_project.id)
    assert len(decisions) >= 7
    assert all(d.agent_id and d.agent_name and d.phase and d.thought_trace for d in decisions)

    tool_calls = await supervisor.list_agent_tool_calls(test_project.id)
    assert len(tool_calls) >= 6
    assert all(tc.agent_id and tc.agent_name and tc.tool_name for tc in tool_calls)


@pytest.mark.asyncio
async def test_supervisor_blocks_expired_project_authorization(db_session, test_project, admin_user):
    """Verify supervisor halts workflow launch if engagement authorization window has expired."""
    supervisor = WorkflowSupervisor(db_session)

    # Artificially expire project authorization window
    test_project.authorization_end = datetime.now(timezone.utc) - timedelta(days=1)
    await db_session.commit()

    with pytest.raises(ProjectAuthorizationExpiredError) as exc_info:
        await supervisor.start_workflow(
            project_id=test_project.id,
            user_id=admin_user.id
        )
    assert "authorization window expired" in str(exc_info.value)


@pytest.mark.asyncio
async def test_supervisor_pause_and_resume(db_session, test_project, admin_user):
    """Verify pausing a workflow at its checkpoint and resuming execution."""
    supervisor = WorkflowSupervisor(db_session)

    # Create dummy running workflow
    wf = WorkflowExecution(
        project_id=test_project.id,
        current_phase="ACTIVE_ASSESSMENT",
        status="RUNNING",
        state_data={"endpoints_count": 5}
    )
    db_session.add(wf)
    await db_session.commit()
    await db_session.refresh(wf)

    # Pause
    paused_wf = await supervisor.pause_workflow(test_project.id, user_id=admin_user.id)
    assert paused_wf.status == "PAUSED"

    # Resume
    resumed_wf = await supervisor.resume_workflow(test_project.id, user_id=admin_user.id)
    assert resumed_wf.status == "RUNNING"


@pytest.mark.asyncio
async def test_supervisor_emergency_stop(db_session, test_project, admin_user):
    """Verify emergency stop sets status STOPPED and sets completed_at."""
    supervisor = WorkflowSupervisor(db_session)

    wf = WorkflowExecution(
        project_id=test_project.id,
        current_phase="ACTIVE_ASSESSMENT",
        status="RUNNING"
    )
    db_session.add(wf)
    await db_session.commit()
    await db_session.refresh(wf)

    stopped_wf = await supervisor.stop_workflow(test_project.id, user_id=admin_user.id)
    assert stopped_wf.status == "STOPPED"
    assert stopped_wf.completed_at is not None


@pytest.mark.asyncio
async def test_supervisor_handle_approval_decision(db_session, test_project, admin_user):
    """Verify processing operator authorization decisions on high-risk operations."""
    supervisor = WorkflowSupervisor(db_session)

    req = ApprovalRequest(
        project_id=test_project.id,
        agent_id="AGT-10",
        action="Run intensive directory fuzzing with 10,000 wordlist",
        target="https://target.com/api/FUZZ",
        risk_level="HIGH",
        status="PENDING"
    )
    db_session.add(req)
    await db_session.commit()
    await db_session.refresh(req)

    result = await supervisor.handle_approval(
        approval_id=req.id,
        project_id=test_project.id,
        decision="APPROVE",
        justification="Authorized by Lead Penetration Tester in approved change window",
        user_id=admin_user.id
    )

    assert result.status == "APPROVED"
    assert result.decided_by == admin_user.id
    assert result.decided_at is not None


@pytest.mark.asyncio
async def test_supervisor_hitl_approval_gate_full_profile(db_session, test_project, admin_user):
    """Verify FULL workflow with auto_approve_medium=False pauses at WAITING_APPROVAL and finishes after approval."""
    from agents.llm.provider import MockLLMProvider
    from sqlalchemy import select

    supervisor = WorkflowSupervisor(db_session, llm_provider=MockLLMProvider())
    wf = await supervisor.prepare_workflow(
        project_id=test_project.id,
        user_id=admin_user.id,
        scan_profile="FULL",
        auto_approve_medium=False
    )
    wf_after_pause = await supervisor.execute_workflow(wf.id)
    assert wf_after_pause.status == "WAITING_APPROVAL"

    req_stmt = select(ApprovalRequest).where(
        ApprovalRequest.project_id == test_project.id,
        ApprovalRequest.workflow_execution_id == wf.id,
        ApprovalRequest.status == "PENDING"
    )
    pending_req = (await db_session.execute(req_stmt)).scalar_one_or_none()
    assert pending_req is not None

    await supervisor.handle_approval(
        approval_id=pending_req.id,
        project_id=test_project.id,
        decision="APPROVE",
        justification="Approved medium risk scan during verification test",
        user_id=admin_user.id
    )
    wf_done = await supervisor.execute_workflow(wf.id)
    assert wf_done.status == "COMPLETED"
    assert wf_done.current_phase == "COMPLETED"


@pytest.mark.asyncio
async def test_supervisor_refuses_workflow_start_with_zero_scope_rules(db_session, test_project, admin_user):
    """Verify WorkflowSupervisor refuses to start workflow on a project with zero defined scope rules."""
    from database.models.scope import ScopeRule
    from sqlalchemy import delete

    # Remove all scope rules for the project
    await db_session.execute(delete(ScopeRule).where(ScopeRule.project_id == test_project.id))
    await db_session.commit()

    supervisor = WorkflowSupervisor(db_session)
    with pytest.raises(BadRequestError) as exc_info:
        await supervisor.prepare_workflow(
            project_id=test_project.id,
            user_id=admin_user.id
        )

    assert "zero defined scope rules" in str(exc_info.value)


