"""Regression unit tests for G3 / NI-06: Workflow and agent execution restart recovery.

Ensures that any workflows and agent executions left RUNNING (or QUEUED) when the API
container or server restarts are fail-closed marked as FAILED with 'interrupted by restart'.
"""

import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy import select

from apps.api.main import recover_interrupted_workflows
from database.models.agent import AgentExecution, WorkflowExecution


@pytest.mark.asyncio
async def test_recover_interrupted_workflows_on_startup(db_session, test_project):
    """Verify workflows and agents left in RUNNING/QUEUED are marked FAILED on startup."""
    now = datetime.now(timezone.utc)

    # 1. Create an interrupted running workflow
    running_wf = WorkflowExecution(
        id=uuid.uuid4(),
        project_id=test_project.id,
        current_phase="ACTIVE_ASSESSMENT",
        status="RUNNING",
        state_data={"scan_profile": "QUICK"}
    )
    db_session.add(running_wf)

    # 2. Create an already completed workflow (should remain untouched)
    completed_wf = WorkflowExecution(
        id=uuid.uuid4(),
        project_id=test_project.id,
        current_phase="COMPLETED",
        status="COMPLETED",
        state_data={"scan_profile": "QUICK"},
        completed_at=now
    )
    db_session.add(completed_wf)

    # 3. Create running, queued, and completed agent executions
    running_agent = AgentExecution(
        id=uuid.uuid4(),
        project_id=test_project.id,
        agent_id="AGT-09",
        agent_name="Vulnerability Detection Agent",
        status="RUNNING"
    )
    queued_agent = AgentExecution(
        id=uuid.uuid4(),
        project_id=test_project.id,
        agent_id="AGT-11",
        agent_name="Validation Agent",
        status="QUEUED"
    )
    completed_agent = AgentExecution(
        id=uuid.uuid4(),
        project_id=test_project.id,
        agent_id="AGT-01",
        agent_name="Project Planning Agent",
        status="COMPLETED",
        completed_at=now
    )
    db_session.add_all([running_agent, queued_agent, completed_agent])
    await db_session.commit()

    # 4. Invoke restart recovery routine
    recovered_count = await recover_interrupted_workflows(db_session)
    assert recovered_count == 1

    # 5. Assertions on workflow
    await db_session.refresh(running_wf)
    await db_session.refresh(completed_wf)
    assert running_wf.status == "FAILED"
    assert running_wf.completed_at is not None
    assert running_wf.state_data.get("failure_reason") == "interrupted by restart"
    assert completed_wf.status == "COMPLETED"

    # 6. Assertions on agent executions
    await db_session.refresh(running_agent)
    await db_session.refresh(queued_agent)
    await db_session.refresh(completed_agent)
    assert running_agent.status == "FAILED"
    assert running_agent.error_message == "interrupted by restart"
    assert running_agent.completed_at is not None
    assert queued_agent.status == "FAILED"
    assert queued_agent.error_message == "interrupted by restart"
    assert completed_agent.status == "COMPLETED"
