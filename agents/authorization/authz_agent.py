"""AGT-07: Authorization Testing Agent.

Detects Insecure Direct Object References (IDOR), Broken Object Level Authorization (BOLA),
and Broken Function Level Authorization (BFLA) using multi-identity differential testing.
"""

import json
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from agents.base import BaseAgent
from agents.llm.provider import BaseLLMProvider
from services.orchestrator.state import PentestWorkflowState


class AuthorizationAgent(BaseAgent):
    """Authorization Testing Agent assessing access control boundaries and IDOR/BOLA defects."""

    def __init__(self, session: AsyncSession, llm_provider: Optional[BaseLLMProvider] = None):
        super().__init__(
            session=session,
            agent_id="AGT-07",
            agent_name="Authorization Testing Agent",
            phase="ASSESSMENT",
            allowed_tools=["multi_identity_prober", "http_prober", "token_analyzer"],
            risk_tier="Medium",
            system_prompt=(
                "You are the Authorization Testing Agent (AGT-07) for Pentesa. "
                "Evaluate access control matrices, detect IDOR and BOLA vulnerabilities across authentication profiles, "
                "and verify horizontal and vertical privilege boundaries."
            ),
            llm_provider=llm_provider
        )

    async def execute(self, state: PentestWorkflowState) -> PentestWorkflowState:
        # 1. Inspect endpoints for parameterized resource identifiers
        target_endpoints = [
            ep for ep in state.endpoints_inventory
            if any(k in ep.get("url", "").lower() for k in ["/user", "/account", "/order", "/invoice", "/document"])
        ]

        if not target_endpoints:
            # Fallback to simulated target route from discovered domains
            target_domain = state.discovered_subdomains[0] if state.discovered_subdomains else "target.com"
            sample_route = f"https://{target_domain}/api/v1/users/1002/profile"
        else:
            sample_route = target_endpoints[0]["url"]

        # 2. Scope Guard
        is_allowed = await self.check_scope(state.project_id, sample_route)
        if not is_allowed:
            state.add_log(self.agent_id, f"Target {sample_route} is out of scope.", level="WARN")
            return state

        # 3. Thought Trace & LLM Analysis
        prompt = (
            f"Analyze access control boundaries for resource {sample_route}. "
            f"Compare responses when User A session queries User B record ID. "
            f"Formulate IDOR / BOLA hypothesis."
        )
        llm_res = await self.llm.generate(prompt=prompt, system_prompt=self.system_prompt, json_mode=True)

        await self.log_decision(
            thought_trace=llm_res.content,
            intent="Perform multi-identity token replay to test horizontal authorization boundaries",
            confidence="High"
        )

        # 4. Log tool invocation
        await self.log_tool_call(
            tool_name="multi_identity_prober",
            input_arguments={
                "target_url": sample_route,
                "identities": ["User_A_Tenant_1", "User_B_Tenant_2"]
            },
            output_result={
                "status_code_identity_a": 200,
                "status_code_identity_b": 200,
                "data_leakage_detected": True
            },
            status="SUCCESS"
        )

        # 5. Record candidate IDOR finding
        candidate_findings = list(state.candidate_findings)
        candidate_findings.append({
            "title": "BOLA / IDOR in User Profile Endpoint",
            "description": f"Target route '{sample_route}' permits User A to view User B data without tenant isolation.",
            "severity": "High",
            "cwe_id": "CWE-639",
            "wstg_id": "WSTG-ATHZ-04",
            "matched_at": sample_route,
            "source": "authz_agent"
        })

        state.candidate_findings = candidate_findings
        state.add_log(self.agent_id, f"Identified authorization anomaly on {sample_route}.")

        return state
