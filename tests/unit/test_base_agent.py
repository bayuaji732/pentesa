"""Unit tests for BaseAgent safety boundaries, scope checking, tool permissions, and thought auditing."""

import uuid
import pytest
from sqlalchemy import select

from agents.base import BaseAgent
from database.models.agent import AgentDecision, AgentExecution, AgentToolCall
from services.orchestrator.state import PentestWorkflowState


class DummyTestAgent(BaseAgent):
    """Test agent implementation for base class verification."""

    def __init__(self, session):
        super().__init__(
            session=session,
            agent_id="AGT-TEST",
            agent_name="Test Verifier Agent",
            phase="TESTING",
            allowed_tools=["mock_prober", "data_analyzer"],
            risk_tier="Low"
        )

    async def execute(self, state: PentestWorkflowState) -> PentestWorkflowState:
        await self.log_decision(
            thought_trace="Analyzing test target for scope compliance",
            intent="Execute safe mock probe",
            confidence="High"
        )
        await self.log_tool_call(
            tool_name="mock_prober",
            input_arguments={"target": "https://target.com"},
            output_result={"status": 200}
        )
        state.add_log(self.agent_id, "Test execution successful.")
        return state


@pytest.mark.asyncio
async def test_base_agent_lifecycle_and_auditing(db_session, test_project):
    """Verify BaseAgent creates AgentExecution, logs thoughts, and records allowed tool calls."""
    agent = DummyTestAgent(db_session)
    state = PentestWorkflowState(
        project_id=test_project.id,
        current_phase="TESTING",
        status="RUNNING"
    )

    updated_state = await agent.run(state)
    assert len(updated_state.execution_logs) >= 2

    # Verify AgentExecution persisted
    exec_stmt = select(AgentExecution).where(
        AgentExecution.project_id == test_project.id,
        AgentExecution.agent_id == "AGT-TEST"
    )
    agent_exec = (await db_session.execute(exec_stmt)).scalar_one_or_none()
    assert agent_exec is not None
    assert agent_exec.status == "COMPLETED"

    # Verify AgentDecision persisted
    dec_stmt = select(AgentDecision).where(AgentDecision.agent_execution_id == agent_exec.id)
    decisions = (await db_session.execute(dec_stmt)).scalars().all()
    assert len(decisions) == 1
    assert "Analyzing test target" in decisions[0].thought_trace

    # Verify AgentToolCall persisted
    call_stmt = select(AgentToolCall).where(AgentToolCall.agent_execution_id == agent_exec.id)
    tool_calls = (await db_session.execute(call_stmt)).scalars().all()
    assert len(tool_calls) == 1
    assert tool_calls[0].tool_name == "mock_prober"


@pytest.mark.asyncio
async def test_base_agent_unauthorized_tool_prohibition(db_session, test_project):
    """Verify agents cannot invoke tools outside their declared allowed_tools set (zero shell invariant)."""
    agent = DummyTestAgent(db_session)
    state = PentestWorkflowState(project_id=test_project.id)

    # Initialize execution manually to test tool call permission check
    execution = AgentExecution(
        project_id=test_project.id,
        agent_id=agent.agent_id,
        agent_name=agent.agent_name,
        status="RUNNING"
    )
    db_session.add(execution)
    await db_session.commit()
    await db_session.refresh(execution)
    agent.current_execution = execution

    # Calling unauthorized tool should raise PermissionError
    with pytest.raises(PermissionError) as exc_info:
        await agent.log_tool_call(
            tool_name="unauthorized_bash_runner",
            input_arguments={"cmd": "whoami"}
        )
    assert "is unauthorized to invoke tool 'unauthorized_bash_runner'" in str(exc_info.value)


@pytest.mark.asyncio
async def test_base_agent_scope_enforcement(db_session, test_project):
    """Verify agents correctly query Layer 1 and 2 scope boundaries."""
    agent = DummyTestAgent(db_session)

    # In-scope URL
    assert await agent.check_scope(test_project.id, "https://api.target.com/v1/users") is True

    # Excluded path
    assert await agent.check_scope(test_project.id, "https://target.com/logout") is False

    # Out of scope domain
    assert await agent.check_scope(test_project.id, "https://malicious.org/attack") is False


@pytest.mark.asyncio
async def test_base_agent_human_approval_request(db_session, test_project):
    """Verify high-risk actions generate pending ApprovalRequest records."""
    agent = DummyTestAgent(db_session)
    approval = await agent.request_human_approval(
        project_id=test_project.id,
        action="High-volume directory fuzzing with 10,000 requests",
        target="https://target.com/admin/FUZZ",
        risk_level="HIGH",
        parameters={"rate_limit": 50, "wordlist_size": 10000}
    )

    assert approval.id is not None
    assert approval.status == "PENDING"
    assert approval.risk_level == "HIGH"
    assert approval.target == "https://target.com/admin/FUZZ"
