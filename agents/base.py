"""Base Agent Framework enforcing zero shell execution, scope pre-validation, and decision auditing."""

import abc
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.llm.provider import BaseLLMProvider, LLMResponse, get_default_llm_provider
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

    def _estimate_cost_usd(self, model: str, prompt_tokens: int, completion_tokens: int) -> float:
        """Estimate token cost in USD (mock providers incur zero real cost)."""
        if "mock" in (model or "").lower():
            return 0.0
        # Standard commercial LLM blend estimate ($2.50 / 1M input, $10.00 / 1M output)
        return round((prompt_tokens * 0.0000025) + (completion_tokens * 0.000010), 6)

    async def generate_llm_response(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_mode: bool = False,
        temperature: Optional[float] = None
    ) -> LLMResponse:
        """Invoke LLM provider and accumulate token & cost telemetry onto AgentExecution."""
        resp = await self.llm.generate(
            prompt=prompt,
            system_prompt=system_prompt if system_prompt is not None else self.system_prompt,
            json_mode=json_mode,
            temperature=temperature
        )
        if self.current_execution:
            p_tok = int(resp.prompt_tokens or 0)
            c_tok = int(resp.completion_tokens or 0)
            self.current_execution.prompt_tokens = int(self.current_execution.prompt_tokens or 0) + p_tok
            self.current_execution.completion_tokens = int(self.current_execution.completion_tokens or 0) + c_tok
            inc_cost = self._estimate_cost_usd(resp.model, p_tok, c_tok)
            self.current_execution.total_cost_usd = round(
                float(self.current_execution.total_cost_usd or 0.0) + inc_cost, 6
            )
            await self.session.commit()
        return resp

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

        clean_trace = (thought_trace or "").strip()
        if not clean_trace:
            clean_trace = f"[{self.agent_id}] Evaluated intent '{intent}' (empty provider output fallback)."

        decision = AgentDecision(
            agent_execution_id=self.current_execution.id,
            thought_trace=clean_trace,
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

    async def run(
        self,
        state: PentestWorkflowState,
        existing_execution: Optional[AgentExecution] = None
    ) -> PentestWorkflowState:
        """Lifecycle wrapper managing execution record persistence, timing, and error handling."""
        start_time = time.time()
        if existing_execution is not None:
            execution = existing_execution
            execution.status = "RUNNING"
            execution.started_at = datetime.now(timezone.utc)
            execution.error_message = None
            await self.session.commit()
            await self.session.refresh(execution)
        else:
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
            if updated_state.status == "WAITING_APPROVAL":
                execution.status = "WAITING_APPROVAL"
            elif updated_state.status == "STOPPED":
                execution.status = "STOPPED"
                execution.completed_at = datetime.now(timezone.utc)
            else:
                execution.status = "COMPLETED"
                execution.completed_at = datetime.now(timezone.utc)
            await self.session.commit()
            state.add_log(self.agent_id, f"Agent {self.agent_name} finished with status {execution.status}.")
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
