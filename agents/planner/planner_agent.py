"""AGT-01: Project Planning Agent.

Analyzes Rules of Engagement (RoE), scopes test plan DAG, and initializes WSTG instances.
"""

import json
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from agents.base import BaseAgent
from agents.llm.provider import BaseLLMProvider
from services.orchestrator.state import PentestWorkflowState
from services.execution_engine.planner import WSTGPlannerService


class ProjectPlanningAgent(BaseAgent):
    """Project Planning Agent responsible for strategic scoping, rate limiting, and WSTG plan initialization."""

    def __init__(self, session: AsyncSession, llm_provider: Optional[BaseLLMProvider] = None):
        super().__init__(
            session=session,
            agent_id="AGT-01",
            agent_name="Project Planning Agent",
            phase="PLANNING",
            allowed_tools=["db_query", "policy_evaluator", "wstg_planner"],
            risk_tier="Low",
            system_prompt=(
                "You are the Principal Project Planning Agent (AGT-01) for Pentesa. "
                "Analyze the target scope, determine optimal scan policies, and configure the WSTG test plan."
            ),
            llm_provider=llm_provider
        )

    async def execute(self, state: PentestWorkflowState) -> PentestWorkflowState:
        # 1. Thought Trace
        prompt = (
            f"Analyze target scope for project {state.project_id} using {state.scan_profile} scan profile. "
            f"Scope summary: {json.dumps(state.approved_scope)}. "
            f"Formulate assessment strategy, rate limits, and WSTG test phases in concise JSON."
        )
        llm_res = await self.generate_llm_response(prompt=prompt, system_prompt=self.system_prompt, json_mode=True)

        await self.log_decision(
            thought_trace=llm_res.content,
            intent=f"Formulate {state.scan_profile} engagement test plan and initialize WSTG matrix",
            confidence="High"
        )

        # 2. Initialize project WSTG test instances via WSTGPlannerService
        planner_service = WSTGPlannerService(self.session)
        instances = await planner_service.initialize_project_instances(state.project_id)

        # 3. Log Tool Call
        await self.log_tool_call(
            tool_name="wstg_planner",
            input_arguments={"project_id": str(state.project_id), "action": "initialize_instances"},
            output_result={"initialized_instances_count": len(instances)},
            status="SUCCESS"
        )

        # 4. Update workflow state
        state.wstg_matrix_state = {inst.wstg_id: inst.status for inst in instances}
        state.add_log(self.agent_id, f"Initialized {len(instances)} WSTG test instances.")
        state.transition_phase("RECON")

        return state
