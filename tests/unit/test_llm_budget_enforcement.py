"""Unit tests for platform-wide LLM budget and token cap enforcement ($10 / 300k tokens)."""

import uuid
import pytest
from sqlalchemy import select

from agents.base import BaseAgent
from agents.llm.provider import BaseLLMProvider, LLMResponse
from database.models.agent import AgentExecution
from packages.common.config import settings
from packages.common.exceptions import LLMBudgetExceededError
from services.orchestrator.state import PentestWorkflowState


class MockBudgetProvider(BaseLLMProvider):
    """Mock provider with commercial model name to trigger budget evaluation."""
    def __init__(self, model_name: str = "gpt-4o"):
        self.model = model_name

    async def generate(self, prompt: str, **kwargs) -> LLMResponse:
        return LLMResponse(
            content="ok",
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
            model=self.model
        )


class BudgetTestAgent(BaseAgent):
    """Minimal agent for testing LLM budget guardrails."""

    def __init__(self, session, llm=None):
        super().__init__(
            session=session,
            agent_id="AGT-BUDGET",
            agent_name="Budget Testing Agent",
            phase="TESTING",
            allowed_tools=[],
            llm_provider=llm or MockBudgetProvider()
        )

    async def execute(self, state: PentestWorkflowState) -> PentestWorkflowState:
        await self.generate_llm_response("Test prompt")
        return state


@pytest.mark.asyncio
async def test_llm_budget_under_cap_succeeds(db_session, test_project):
    """Verify LLM calls succeed when total spend and tokens are below the cap."""
    agent = BudgetTestAgent(db_session)

    # Initialize execution under budget
    execution = AgentExecution(
        id=uuid.uuid4(),
        project_id=test_project.id,
        agent_id=agent.agent_id,
        agent_name=agent.agent_name,
        status="RUNNING",
        total_cost_usd=1.50,
        prompt_tokens=5000,
        completion_tokens=2000
    )
    db_session.add(execution)
    await db_session.commit()
    await db_session.refresh(execution)
    agent.current_execution = execution

    resp = await agent.generate_llm_response("Test prompt under budget")
    assert resp is not None
    assert resp.content == "ok"


@pytest.mark.asyncio
async def test_llm_budget_over_cost_cap_refuses_call(db_session, test_project):
    """Verify LLM calls are refused when total spend reaches or exceeds $10.00."""
    agent = BudgetTestAgent(db_session)

    # Seed execution with $10.50 accumulated cost
    over_budget_exec = AgentExecution(
        id=uuid.uuid4(),
        project_id=test_project.id,
        agent_id="AGT-PRIOR",
        agent_name="Prior Agent",
        status="COMPLETED",
        total_cost_usd=10.50,
        prompt_tokens=20000,
        completion_tokens=5000
    )
    db_session.add(over_budget_exec)

    execution = AgentExecution(
        id=uuid.uuid4(),
        project_id=test_project.id,
        agent_id=agent.agent_id,
        agent_name=agent.agent_name,
        status="RUNNING"
    )
    db_session.add(execution)
    await db_session.commit()
    await db_session.refresh(execution)
    agent.current_execution = execution

    with pytest.raises(LLMBudgetExceededError) as exc_info:
        await agent.generate_llm_response("Test prompt over cost cap")

    assert "Platform LLM budget cap exceeded" in str(exc_info.value)


@pytest.mark.asyncio
async def test_llm_budget_over_token_cap_refuses_call(db_session, test_project):
    """Verify LLM calls are refused when total tokens reach or exceed 300,000."""
    agent = BudgetTestAgent(db_session)

    # Seed execution with 350,000 tokens
    over_token_exec = AgentExecution(
        id=uuid.uuid4(),
        project_id=test_project.id,
        agent_id="AGT-PRIOR",
        agent_name="Prior Agent",
        status="COMPLETED",
        total_cost_usd=2.00,
        prompt_tokens=250000,
        completion_tokens=100000
    )
    db_session.add(over_token_exec)

    execution = AgentExecution(
        id=uuid.uuid4(),
        project_id=test_project.id,
        agent_id=agent.agent_id,
        agent_name=agent.agent_name,
        status="RUNNING"
    )
    db_session.add(execution)
    await db_session.commit()
    await db_session.refresh(execution)
    agent.current_execution = execution

    with pytest.raises(LLMBudgetExceededError) as exc_info:
        await agent.generate_llm_response("Test prompt over token cap")

    assert "Platform LLM budget cap exceeded" in str(exc_info.value)
