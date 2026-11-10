"""AGT-15: PTES Reporting Agent.

Synthesizes confirmed findings, evidence artifacts, and WSTG coverage into executive and technical PTES deliverables.
"""

import json
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from agents.base import BaseAgent
from agents.llm.provider import BaseLLMProvider
from services.orchestrator.state import PentestWorkflowState


class ReportingAgent(BaseAgent):
    """PTES Reporting Agent generating structured security deliverables and executive summaries."""

    def __init__(self, session: AsyncSession, llm_provider: Optional[BaseLLMProvider] = None):
        super().__init__(
            session=session,
            agent_id="AGT-15",
            agent_name="PTES Reporting Agent",
            phase="REPORTING",
            allowed_tools=["report_compiler", "cvss_calculator", "markdown_generator"],
            risk_tier="Low",
            system_prompt=(
                "You are the PTES Reporting Agent (AGT-15) for Pentesa. "
                "Synthesize confirmed penetration testing findings into a professional, PTES-compliant deliverable. "
                "Include executive summaries, technical impact evaluations, and prioritized remediation roadmaps."
            ),
            llm_provider=llm_provider
        )

    async def execute(self, state: PentestWorkflowState) -> PentestWorkflowState:
        # 1. Thought Trace & LLM Executive Synthesis
        prompt = (
            f"Generate PTES Executive Summary and strategic recommendations for project {state.project_id} ({state.scan_profile} scan). "
            f"Confirmed findings: {json.dumps(state.confirmed_findings)}. "
            f"Discovered endpoints: {len(state.endpoints_inventory)}. "
            f"Formulate technical risk score and prioritized remediation roadmap in concise JSON."
        )
        llm_res = await self.generate_llm_response(prompt=prompt, system_prompt=self.system_prompt, json_mode=True)

        await self.log_decision(
            thought_trace=llm_res.content,
            intent="Compile comprehensive PTES penetration test report deliverable",
            confidence="High"
        )

        # 2. Compile report structure
        report_data = {
            "project_id": str(state.project_id),
            "scan_profile": state.scan_profile,
            "methodology": "OWASP WSTG v4.2 & Penetration Testing Execution Standard (PTES)",
            "executive_summary": llm_res.content,
            "total_endpoints_tested": len(state.endpoints_inventory),
            "confirmed_findings_count": len(state.confirmed_findings),
            "false_positives_filtered": len(state.false_positives),
            "status": "FINALIZED"
        }

        # 3. Log Tool Call
        await self.log_tool_call(
            tool_name="report_compiler",
            input_arguments={"project_id": str(state.project_id), "format": "JSON_PTES"},
            output_result=report_data,
            status="SUCCESS"
        )

        state.add_log(self.agent_id, f"PTES deliverable compiled with {len(state.confirmed_findings)} confirmed findings.")
        state.transition_phase("COMPLETED")
        state.status = "COMPLETED"

        return state
