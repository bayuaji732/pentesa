"""Unit tests for WorkflowSupervisor DAG orchestration, state checkpoints, and approval gates."""

from datetime import datetime, timedelta, timezone
import pytest

from database.models.agent import ApprovalRequest, WorkflowExecution
from packages.common.exceptions import BadRequestError, ProjectAuthorizationExpiredError
from services.orchestrator.supervisor import WorkflowSupervisor


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
