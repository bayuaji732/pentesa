"""AGT-05: OWASP WSTG Assessment Agent.

Executes category-specific WSTG test probes, updates test statuses, and captures candidate findings.
"""

import asyncio
from typing import List, Optional
from urllib.parse import urlparse
import httpx
from sqlalchemy import case, select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.base import BaseAgent
from agents.llm.provider import BaseLLMProvider
from database.models.discovery import Endpoint
from database.models.wstg import WSTGTestCatalog, WSTGTestInstance
from packages.common.http_client import safe_request
from packages.schemas.wstg import TestExecutionCreate
from services.execution_engine.coverage import WSTGCoverageService
from services.execution_engine.planner import recalculate_project_test_plan
from services.execution_engine.service import WSTGExecutionService
from services.orchestrator.state import PentestWorkflowState


class WSTGAssessmentAgent(BaseAgent):
    """WSTG Assessment Agent executing standardized OWASP test probes."""

    def __init__(
        self,
        session: AsyncSession,
        llm_provider: Optional[BaseLLMProvider] = None,
        http_transport: Optional[httpx.AsyncBaseTransport] = None,
    ):
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
            llm_provider=llm_provider,
        )
        self.http_transport = http_transport

    async def execute(self, state: PentestWorkflowState) -> PentestWorkflowState:
        profile = (state.scan_profile or "QUICK").upper()
        batch_limit = 30 if profile == "DEEP" else 15 if profile == "FULL" else 5

        # 1. Thought Trace via real configured LLM
        prompt = (
            f"Review WSTG testing plan ({profile} profile) for project {state.project_id}. "
            f"Endpoints: {len(state.endpoints_inventory)} discovered. "
            f"Plan automated executions for Configuration, Identity, and Input Validation testing in concise JSON."
        )
        llm_res = await self.generate_llm_response(
            prompt=prompt,
            system_prompt=self.system_prompt,
            json_mode=True,
        )

        await self.log_decision(
            thought_trace=llm_res.content,
            intent=f"Dispatch up to {batch_limit} automated WSTG runners ({profile} profile)",
            confidence="High",
        )

        # 2. Recalculate applicability against latest surface, then query Planned tests
        await recalculate_project_test_plan(self.session, state.project_id)

        runnable_priority = case(
            (WSTGTestInstance.wstg_id.in_(["WSTG-INFO-03", "WSTG-CONF-06", "WSTG-CONF-07", "WSTG-CLNT-09"]), 0),
            (WSTGTestCatalog.automation_capability == "Full", 1),
            else_=2,
        )
        stmt = (
            select(WSTGTestInstance)
            .join(WSTGTestCatalog, WSTGTestInstance.wstg_id == WSTGTestCatalog.id)
            .where(
                WSTGTestInstance.project_id == state.project_id,
                WSTGTestInstance.status == "Planned",
            )
            .order_by(
                runnable_priority,
                WSTGTestInstance.applicable_endpoints_count.desc(),
                WSTGTestInstance.wstg_id,
            )
            .limit(batch_limit)
        )
        instances = (await self.session.execute(stmt)).scalars().all()

        ep_stmt = select(Endpoint).where(Endpoint.project_id == state.project_id)
        all_endpoints = list((await self.session.execute(ep_stmt)).scalars().all())
        first_endpoint_id = all_endpoints[0].id if all_endpoints else None

        def _pick_endpoint_id(wid: str):
            if not all_endpoints:
                return None
            if wid.startswith("WSTG-INPV"):
                param_ep = next((e for e in all_endpoints if e.parameter_schema), None)
                if param_ep:
                    return param_ep.id
            elif wid.startswith(("WSTG-ATHN", "WSTG-IDNT", "WSTG-SESS")):
                auth_ep = next(
                    (
                        e for e in all_endpoints
                        if e.auth_required or any(k in (e.url_path or "").lower() for k in ("login", "auth", "register", "session"))
                    ),
                    None,
                )
                if auth_ep:
                    return auth_ep.id
            elif wid.startswith("WSTG-APIT"):
                api_ep = next(
                    (e for e in all_endpoints if "/api" in (e.url_path or "").lower() or "json" in (e.content_type or "").lower()),
                    None,
                )
                if api_ep:
                    return api_ep.id
            elif wid in {"WSTG-CONF-07", "WSTG-CLNT-09", "WSTG-INFO-03"}:
                web_ep = next(
                    (e for e in all_endpoints if "html" in (e.content_type or "").lower() or e.url_path == "/"),
                    None,
                )
                if web_ep:
                    return web_ep.id
            return first_endpoint_id

        target_domain = state.discovered_subdomains[0] if state.discovered_subdomains else None
        target_url = state.target_base_url or (f"https://{target_domain}" if target_domain else None)

        exec_service = WSTGExecutionService(self.session)
        executed_count = 0
        candidate_findings = list(state.candidate_findings)

        if target_url:
            for inst in instances:
                if not await self.check_scope(state.project_id, target_url):
                    continue
                try:
                    test_exec = await exec_service.dispatch_execution(
                        project_id=state.project_id,
                        payload=TestExecutionCreate(
                            wstg_id=inst.wstg_id,
                            endpoint_id=_pick_endpoint_id(inst.wstg_id),
                            runner_type="AGENT",
                        ),
                        http_transport=self.get_http_transport(),
                    )
                    if test_exec.status in ("PASSED", "FAILED", "NEEDS_REVIEW"):
                        executed_count += 1
                    await self.session.refresh(inst)
                    state.wstg_matrix_state[inst.wstg_id] = inst.status
                except Exception as e:
                    state.add_log(self.agent_id, f"Execution failed for {inst.wstg_id}: {e}", level="WARN")

            # Live security-header inspection across ALL scan profiles when target is in-scope and reachable
            if await self.check_scope(state.project_id, target_url):
                parsed = urlparse(target_url)
                host_hdr = parsed.netloc or (target_domain or "")
                applicable_headers = ["Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"]
                if target_url.lower().startswith("https://"):
                    applicable_headers.insert(1, "Strict-Transport-Security")

                try:
                    async with httpx.AsyncClient(
                        timeout=httpx.Timeout(5.0, connect=3.0),
                        verify=False,
                        transport=self.get_http_transport(),
                    ) as client:
                        resp, _ = await safe_request(
                            client=client,
                            method="GET",
                            url=target_url,
                            project_id=state.project_id,
                            session=self.session,
                            follow_redirects=True,
                            resolve_dns=True,
                        )

                    lower_headers = {k.lower(): v for k, v in resp.headers.items()}
                    missing_headers: List[str] = [
                        h for h in applicable_headers if h.lower() not in lower_headers
                    ]
                    raw_headers = "\r\n".join(f"{k}: {v}" for k, v in list(resp.headers.items())[:20])

                    await self.log_tool_call(
                        tool_name="headers_analyzer",
                        input_arguments={"target_url": target_url},
                        output_result={
                            "status_code": resp.status_code,
                            "missing_headers": missing_headers,
                        },
                        status="SUCCESS",
                    )

                    if missing_headers:
                        header_wstg_id = (
                            "WSTG-CONF-07"
                            if "Strict-Transport-Security" in missing_headers
                            else ("WSTG-CLNT-09" if "X-Frame-Options" in missing_headers else "WSTG-CONF-02")
                        )
                        candidate_findings.append({
                            "title": (
                                "Missing Security Headers (CSP, HSTS)"
                                if "Strict-Transport-Security" in missing_headers
                                else "Missing Security Headers (CSP, XFO, XCTO)"
                            ),
                            "description": (
                                f"HTTP responses from {target_url} lack recommended defensive security headers: "
                                f"{', '.join(missing_headers)}."
                            ),
                            "severity": "Low",
                            "wstg_id": header_wstg_id,
                            "cwe_id": "CWE-693",
                            "target_url": target_url,
                            "source": "wstg_agent",
                            "status_code": resp.status_code,
                            "raw_request": (
                                f"GET {parsed.path or '/'} HTTP/1.1\r\n"
                                f"Host: {host_hdr}\r\n"
                                f"User-Agent: Pentesa-WSTG-Prober\r\n\r\n"
                            ),
                            "raw_response": f"HTTP/1.1 {resp.status_code}\r\n{raw_headers}",
                            "reproduction_curl": f"curl -i -s '{target_url}'",
                        })
                except Exception as exc:
                    await self.log_tool_call(
                        tool_name="headers_analyzer",
                        input_arguments={"target_url": target_url},
                        output_result={"reachable": False, "error": str(exc)},
                        status="FAILED",
                    )

        # 3. Log tool call
        await self.log_tool_call(
            tool_name="wstg_runner",
            input_arguments={
                "project_id": str(state.project_id),
                "target_url": target_url,
                "profile": profile,
            },
            output_result={"executed_probes_count": executed_count},
            status="SUCCESS",
        )

        # 4. Sync state matrix & coverage calculation
        all_insts = (
            await self.session.execute(
                select(WSTGTestInstance).where(WSTGTestInstance.project_id == state.project_id)
            )
        ).scalars().all()
        state.wstg_matrix_state = {i.wstg_id: i.status for i in all_insts}

        cov_service = WSTGCoverageService(self.session)
        report = await cov_service.calculate_project_coverage(state.project_id)

        state.candidate_findings = candidate_findings
        state.add_log(
            self.agent_id,
            f"Executed {executed_count} WSTG tests ({profile}). Global coverage: {report.overall_coverage_pct:.1f}%.",
        )
        state.transition_phase("ACTIVE_ASSESSMENT")

        return state
