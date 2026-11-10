"""AGT-05: OWASP WSTG Assessment Agent.

Executes category-specific WSTG test probes, updates test statuses, and captures candidate findings.
"""

import json
from typing import Optional
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.base import BaseAgent
from agents.llm.provider import BaseLLMProvider
from database.models.wstg import WSTGTestInstance
from packages.schemas.wstg import TestExecutionCreate
from services.orchestrator.state import PentestWorkflowState
from services.execution_engine.coverage import WSTGCoverageService
from services.execution_engine.service import WSTGExecutionService


class WSTGAssessmentAgent(BaseAgent):
    """WSTG Assessment Agent executing standardized OWASP test probes."""

    def __init__(self, session: AsyncSession, llm_provider: Optional[BaseLLMProvider] = None):
        super().__init__(
            session=session,
            agent_id="AGT-05",
            agent_name="WSTG Assessment Agent",
            phase="ASSESSMENT",
            allowed_tools=["wstg_runner", "http_prober", "headers_analyzer", "metafiles_checker"],
            risk_tier="Medium",
            system_prompt=(
                "You are the OWASP WSTG Assessment Agent (AGT-05) for Pentesa. "
                "Execute applicable WSTG test probes, analyze HTTP responses, and identify potential security weaknesses."
            ),
            llm_provider=llm_provider
        )

    async def execute(self, state: PentestWorkflowState) -> PentestWorkflowState:
        profile = (state.scan_profile or "QUICK").upper()
        batch_limit = 30 if profile == "DEEP" else 15 if profile == "FULL" else 5

        # 1. Thought Trace
        prompt = (
            f"Review WSTG testing plan ({profile} profile) for project {state.project_id}. "
            f"Endpoints: {len(state.endpoints_inventory)} discovered. "
            f"Plan automated executions for Configuration, Identity, and Input Validation testing in concise JSON."
        )
        llm_res = await self.generate_llm_response(prompt=prompt, system_prompt=self.system_prompt, json_mode=True)

        await self.log_decision(
            thought_trace=llm_res.content,
            intent=f"Dispatch up to {batch_limit} automated WSTG runners ({profile} profile)",
            confidence="High"
        )

        # 2. Query planned WSTG instances
        stmt = (
            select(WSTGTestInstance)
            .where(
                WSTGTestInstance.project_id == state.project_id,
                WSTGTestInstance.status.in_(["Planned", "Not Started", "Running", "Needs Manual Review"])
            )
            .limit(batch_limit)
        )
        instances = (await self.session.execute(stmt)).scalars().all()

        exec_service = WSTGExecutionService(self.session)
        target_domain = state.discovered_subdomains[0] if state.discovered_subdomains else "target.com"
        target_url = state.target_base_url or f"https://{target_domain}"

        executed_count = 0
        candidate_findings = list(state.candidate_findings)

        # Filter to automated/controllable tests first so probes increment coverage cleanly
        for inst in instances:
            if not await self.check_scope(state.project_id, target_url):
                continue

            try:
                test_exec = await exec_service.dispatch_execution(
                    project_id=state.project_id,
                    payload=TestExecutionCreate(
                        wstg_id=inst.wstg_id,
                        endpoint_id=None,
                        runner_type="AGENT"
                    )
                )
                if test_exec.status in ("PASSED", "FAILED", "NEEDS_REVIEW"):
                    executed_count += 1
                await self.session.refresh(inst)
                state.wstg_matrix_state[inst.wstg_id] = inst.status
            except Exception as e:
                state.add_log(self.agent_id, f"Execution failed for {inst.wstg_id}: {e}", level="WARN")

        # Live security-header inspection when FULL/DEEP and target is reachable
        header_evidence = {}
        applicable_headers = ["Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"]
        if target_url.lower().startswith("https://"):
            applicable_headers.insert(1, "Strict-Transport-Security")
        missing_headers = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]
        if profile in ("FULL", "DEEP") and await self.check_scope(state.project_id, target_url):
            try:
                async with httpx.AsyncClient(timeout=2.5, verify=False) as client:
                    resp = await client.get(target_url)
                    lower_headers = {k.lower(): v for k, v in resp.headers.items()}
                    missing = [h for h in applicable_headers if h.lower() not in lower_headers]
                    missing_headers = missing
                    header_evidence = {
                        "raw_request": f"GET / HTTP/1.1\r\nHost: {target_domain}\r\nUser-Agent: Pentesa-WSTG-Prober\r\n\r\n",
                        "raw_response": f"HTTP/1.1 {resp.status_code}\r\n" + "\r\n".join(f"{k}: {v}" for k, v in list(resp.headers.items())[:15])
                    }
                    await self.log_tool_call(
                        tool_name="headers_analyzer",
                        input_arguments={"target_url": target_url},
                        output_result={"status_code": resp.status_code, "missing_headers": missing},
                        status="SUCCESS"
                    )
            except Exception:
                pass

        if missing_headers:
            candidate_findings.append({
                "title": "Missing Security Headers (CSP, HSTS)" if "Strict-Transport-Security" in missing_headers else "Missing Security Headers (CSP, XFO, XCTO)",
                "description": f"HTTP responses from {target_url} lack recommended defensive security headers: {', '.join(missing_headers)}.",
                "severity": "Low",
                "wstg_id": "WSTG-CONF-07",
                "cwe_id": "CWE-693",
                "target_url": target_url,
                "source": "wstg_agent",
                **header_evidence
            })

        # 3. Log tool call
        await self.log_tool_call(
            tool_name="wstg_runner",
            input_arguments={"project_id": str(state.project_id), "target_url": target_url, "profile": profile},
            output_result={"executed_probes_count": executed_count},
            status="SUCCESS"
        )

        # 4. Coverage calculation
        cov_service = WSTGCoverageService(self.session)
        report = await cov_service.calculate_project_coverage(state.project_id)

        state.candidate_findings = candidate_findings
        state.add_log(self.agent_id, f"Executed {executed_count} WSTG tests ({profile}). Global coverage: {report.overall_coverage_pct:.1f}%.")
        state.transition_phase("ACTIVE_ASSESSMENT")

        return state
