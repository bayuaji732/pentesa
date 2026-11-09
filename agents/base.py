"""Base Agent Framework enforcing zero shell execution, scope pre-validation, and decision auditing."""

import abc
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.llm.provider import BaseLLMProvider, get_default_llm_provider
from database.models.agent import (
    AgentDecision,
    AgentExecution,
    AgentToolCall,
    ApprovalRequest
)
from database.models.project import Project
from database.models.scope import ScopeRule
from packages.common.exceptions import ScopeViolationError
from services.orchestrator.state import PentestWorkflowState
from services.scope_engine.service import scope_service


class BaseAgent(abc.ABC):
    """Abstract base agent providing safety boundaries, scope enforcement, and decision auditing."""

    def __init__(
        self,
        session: AsyncSession,
        agent_id: str,
        agent_name: str,
        phase: str,
        allowed_tools: List[str],
        risk_tier: str = "Low",
        system_prompt: Optional[str] = None,
        llm_provider: Optional[BaseLLMProvider] = None
    ):
        self.session = session
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.phase = phase
        self.allowed_tools = allowed_tools
        self.risk_tier = risk_tier
        self.system_prompt = system_prompt or f"You are {agent_name} ({agent_id}) in Pentesa."
        self.llm = llm_provider or get_default_llm_provider()
        self.current_execution: Optional[AgentExecution] = None

    async def check_scope(self, project_id: uuid.UUID, target_url: str) -> bool:
        """Validate destination against project scope boundaries."""
        proj_stmt = select(Project).where(Project.id == project_id)
        proj = (await self.session.execute(proj_stmt)).scalar_one_or_none()
        if not proj:
            return False

        rules_stmt = select(ScopeRule).where(ScopeRule.project_id == project_id)
        rules = (await self.session.execute(rules_stmt)).scalars().all()

        check_res = scope_service.check_target(
            project=proj,
            target_url=target_url,
            rules=rules,
            resolve_dns=False
        )
        return check_res.is_in_scope

    async def log_decision(
        self,
        thought_trace: str,
        intent: str,
        context_summary: Optional[str] = None,
        confidence: Optional[str] = None
    ) -> AgentDecision:
        """Record an immutable thought trace and reasoning formulation in the database."""
        if not self.current_execution:
            raise RuntimeError("Cannot log decision without an active AgentExecution.")

        decision = AgentDecision(
            agent_execution_id=self.current_execution.id,
            thought_trace=thought_trace,
            intent=intent,
            context_summary=context_summary,
            confidence=confidence
        )
        self.session.add(decision)
        await self.session.commit()
        await self.session.refresh(decision)
        return decision

    async def log_tool_call(
        self,
        tool_name: str,
        input_arguments: Dict[str, Any],
        output_result: Optional[Dict[str, Any]] = None,
        status: str = "SUCCESS",
        duration_ms: Optional[int] = None
    ) -> AgentToolCall:
        """Log a structured tool invocation adhering to the zero-shell invariant."""
        if not self.current_execution:
            raise RuntimeError("Cannot log tool call without an active AgentExecution.")

        if tool_name not in self.allowed_tools:
            raise PermissionError(
                f"Agent {self.agent_id} ({self.agent_name}) is unauthorized to invoke tool '{tool_name}'. "
                f"Allowed tools: {self.allowed_tools}"
            )

        tool_call = AgentToolCall(
            agent_execution_id=self.current_execution.id,
            tool_name=tool_name,
            input_arguments=input_arguments,
            output_result=output_result,
            status=status,
            duration_ms=duration_ms
        )
        self.session.add(tool_call)
        await self.session.commit()
        await self.session.refresh(tool_call)
        return tool_call

    async def request_human_approval(
        self,
        project_id: uuid.UUID,
        action: str,
        target: str,
        risk_level: str = "HIGH",
        parameters: Optional[Dict[str, Any]] = None,
        workflow_id: Optional[uuid.UUID] = None
    ) -> ApprovalRequest:
        """Pause agent execution and solicit operator authorization for high-risk actions."""
        req = ApprovalRequest(
            project_id=project_id,
            workflow_execution_id=workflow_id,
            agent_id=self.agent_id,
            action=action,
            target=target,
            risk_level=risk_level,
            parameters=parameters,
            status="PENDING"
        )
        self.session.add(req)
        await self.session.commit()
        await self.session.refresh(req)
        return req

    async def run(self, state: PentestWorkflowState) -> PentestWorkflowState:
        """Lifecycle wrapper managing execution record persistence, timing, and error handling."""
        start_time = time.time()
        execution = AgentExecution(
            project_id=state.project_id,
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status="RUNNING"
        )
        self.session.add(execution)
        await self.session.commit()
        await self.session.refresh(execution)
        self.current_execution = execution

        state.add_log(self.agent_id, f"Agent {self.agent_name} started execution.")

        try:
            updated_state = await self.execute(state)
            execution.status = "COMPLETED"
            execution.completed_at = datetime.now(timezone.utc)
            await self.session.commit()
            state.add_log(self.agent_id, f"Agent {self.agent_name} completed execution successfully.")
            return updated_state
        except Exception as e:
            execution.status = "FAILED"
            execution.error_message = str(e)
            execution.completed_at = datetime.now(timezone.utc)
            await self.session.commit()
            state.add_log(self.agent_id, f"Agent {self.agent_name} failed: {e}", level="ERROR")
            raise e

    @abc.abstractmethod
    async def execute(self, state: PentestWorkflowState) -> PentestWorkflowState:
        """Core specialized reasoning and execution logic implemented by subclasses."""
        pass
