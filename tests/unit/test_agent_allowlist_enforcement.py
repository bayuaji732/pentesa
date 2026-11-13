"""Runtime test for 8.2: Verify agent tool allowlist runtime enforcement and audit logging."""

import uuid
import pytest
from sqlalchemy import select

from sqlalchemy.ext.asyncio import AsyncSession

from agents.base import BaseAgent
from database.models.agent import AgentExecution
from database.models.audit import AuditLog
from database.models.project import Project
from database.models.user import User
from services.orchestrator.state import PentestWorkflowState

class DummyTestAgent(BaseAgent):
    def __init__(self, session):
        super().__init__(
            session=session,
            agent_id="AGT-TEST",
            agent_name="Dummy Allowlist Test Agent",
            phase="TESTING",
            allowed_tools=["http_client", "scope_validator"]
        )

    async def execute(self, state: PentestWorkflowState) -> PentestWorkflowState:
        return state

@pytest.mark.asyncio
async def test_agent_unauthorized_tool_call_refused_and_audit_logged(
    test_project: Project, admin_user: User, db_session: AsyncSession
):
    agent = DummyTestAgent(db_session)

    # Create execution record
    exec_record = AgentExecution(
        id=uuid.uuid4(),
        project_id=test_project.id,
        agent_id=agent.agent_id,
        agent_name=agent.agent_name,
        status="RUNNING"
    )
    db_session.add(exec_record)
    await db_session.commit()
    agent.current_execution = exec_record

    # Verify runtime refusal
    with pytest.raises(PermissionError) as exc_info:
        await agent.log_tool_call(
            tool_name="unauthorized_scanner",
            input_arguments={"target": "http://target.test"}
        )

    assert "is unauthorized to invoke tool 'unauthorized_scanner'" in str(exc_info.value)
    assert "Allowed tools: ['http_client', 'scope_validator']" in str(exc_info.value)

    # Verify audit log entry was written
    stmt = (
        select(AuditLog)
        .where(
            AuditLog.project_id == test_project.id,
            AuditLog.action == "AGENT_TOOL_CALL_BLOCKED"
        )
    )
    result = await db_session.execute(stmt)
    audit_entry = result.scalar_one_or_none()
    assert audit_entry is not None, "Audit log entry AGENT_TOOL_CALL_BLOCKED was not recorded!"
    assert audit_entry.details["unauthorized_tool"] == "unauthorized_scanner"
    assert audit_entry.details["agent_id"] == "AGT-TEST"
