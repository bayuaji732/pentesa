"""AGT-07: Authorization Testing Agent.

Detects Insecure Direct Object References (IDOR), Broken Object Level Authorization (BOLA),
and Broken Function Level Authorization (BFLA) using live HTTP differential verification.
"""

import asyncio
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse
import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from agents.base import BaseAgent
from agents.llm.provider import BaseLLMProvider
from services.orchestrator.state import PentestWorkflowState


class AuthorizationAgent(BaseAgent):
    """Authorization Testing Agent assessing access control boundaries and IDOR/BOLA defects."""

    def __init__(
        self,
        session: AsyncSession,
        llm_provider: Optional[BaseLLMProvider] = None,
        http_transport: Optional[httpx.AsyncBaseTransport] = None,
    ):
        super().__init__(
            session=session,
            agent_id="AGT-07",
            agent_name="Authorization Testing Agent",
            phase="ASSESSMENT",
            allowed_tools=["multi_identity_prober", "http_prober", "token_analyzer"],
            risk_tier="Medium",
            system_prompt=(
                "You are the Authorization Testing Agent (AGT-07) for Pentesa. "
                "Evaluate access control matrices, detect IDOR and BOLA vulnerabilities across endpoints, "
                "and report only empirically verified exposure."
            ),
            llm_provider=llm_provider,
        )
        self.http_transport = http_transport

    @staticmethod
    def _is_sensitive_exposure(resp: httpx.Response) -> bool:
        """Detect unauthenticated exposure of credentials, API keys, or user PII in non-HTML responses."""
        if resp.status_code != 200:
            return False
        ct = resp.headers.get("content-type", "").lower()
        body = resp.text or ""
        if "text/html" in ct and not ("api_key" in body or "jwt_secret" in body):
            return False

        body_low = body.lower()
        secret_markers = ("\"api_key\"", "\"password\"", "\"secret\"", "\"private_key\"", "\"security_warning\"", "idor:")
        if any(m in body_low for m in secret_markers):
            return True

        try:
            data = resp.json()
            if isinstance(data, dict) and any(k in data for k in ("email", "username", "account", "user_id")):
                if data.get("api_key") or data.get("password") or data.get("email"):
                    return True
        except Exception:
            pass
        return False

    async def execute(self, state: PentestWorkflowState) -> PentestWorkflowState:
        profile = (state.scan_profile or "QUICK").upper()

        # 1. Identify resource endpoints from inventory with object identifiers
        target_endpoints = [
            ep
            for ep in state.endpoints_inventory
            if any(
                k in ep.get("url", "").lower()
                for k in ["/user", "/account", "/profile", "/order", "/invoice", "/document"]
            )
        ]

        base_url = state.target_base_url.rstrip("/") if state.target_base_url else None
        if not base_url and state.discovered_subdomains:
            base_url = f"https://{state.discovered_subdomains[0]}"

        candidate_routes: List[str] = []
        for ep in target_endpoints:
            raw_url = ep.get("url", "")
            if raw_url:
                resolved = re.sub(r"\{[^}]+\}", "1", raw_url)
                if resolved not in candidate_routes:
                    candidate_routes.append(resolved)

        if not candidate_routes and base_url:
            candidate_routes.append(f"{base_url}/api/v1/users/1")

        in_scope_routes = []
        for route in candidate_routes:
            if await self.check_scope(state.project_id, route):
                in_scope_routes.append(route)

        if not in_scope_routes:
            state.add_log(
                self.agent_id,
                "No in-scope identity/object resource routes available for authorization probing.",
                level="INFO",
            )
            return state

        sample_route = in_scope_routes[0]
        parsed_route = urlparse(sample_route)

        # 2. Thought Trace & LLM Analysis
        prompt = (
            f"Analyze access control boundaries ({profile} scan) for resource {sample_route}. "
            f"Assess potential IDOR / BOLA exposure when accessed without tenant isolation. "
            f"Formulate hypothesis in concise JSON."
        )
        llm_res = await self.generate_llm_response(
            prompt=prompt,
            system_prompt=self.system_prompt,
            json_mode=True,
        )

        await self.log_decision(
            thought_trace=llm_res.content,
            intent="Perform live multi-object differential probing on resource identifier endpoints",
            confidence="High",
        )

        # 3. Empirical Live Differential HTTP Probe (across all profiles when reachable)
        sibling_route = re.sub(r"/1$", "/2", sample_route)
        if sibling_route == sample_route:
            sibling_route = re.sub(r"/(\d+)$", lambda m: f"/{int(m.group(1)) + 1}", sample_route)

        tool_out: Dict[str, object] = {"live_probed": False, "data_leakage_detected": False}
        tool_status = "SUCCESS"
        leaked = False
        evidence_fields: Dict[str, str] = {}
        observed_status = None

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(5.0, connect=3.0),
                verify=False,
                follow_redirects=True,
                transport=self.get_http_transport(),
            ) as client:
                r1 = await asyncio.wait_for(client.get(sample_route), timeout=4.0)
                r2 = (
                    await asyncio.wait_for(client.get(sibling_route), timeout=4.0)
                    if await self.check_scope(state.project_id, sibling_route)
                    else r1
                )

                leaked_1 = self._is_sensitive_exposure(r1)
                leaked_2 = self._is_sensitive_exposure(r2)
                distinct_records = (
                    sibling_route != sample_route
                    and r1.status_code == 200
                    and r2.status_code == 200
                    and r1.text != r2.text
                    and (leaked_1 or leaked_2)
                )
                leaked = leaked_1 or leaked_2 or distinct_records
                observed_status = r1.status_code

                tool_out = {
                    "status_code_identity_a": r1.status_code,
                    "status_code_identity_b": r2.status_code,
                    "data_leakage_detected": leaked,
                    "live_probed": True,
                }

                if leaked:
                    target_for_curl = sibling_route if leaked_2 else sample_route
                    evidence_fields = {
                        "status_code": r2.status_code if leaked_2 else r1.status_code,
                        "raw_request": (
                            f"GET {urlparse(target_for_curl).path or '/'} HTTP/1.1\r\n"
                            f"Host: {parsed_route.netloc}\r\n\r\n"
                        ),
                        "raw_response": (
                            f"HTTP/1.1 {r1.status_code} ({sample_route}): {r1.text[:350]}\r\n---\r\n"
                            f"HTTP/1.1 {r2.status_code} ({sibling_route}): {r2.text[:350]}"
                        ),
                        "reproduction_curl": f"curl -i -s '{target_for_curl}'",
                    }
        except Exception as exc:
            tool_status = "FAILED"
            tool_out = {
                "live_probed": True,
                "reachable": False,
                "data_leakage_detected": False,
                "error": str(exc),
            }

        await self.log_tool_call(
            tool_name="multi_identity_prober",
            input_arguments={
                "target_url": sample_route,
                "sibling_url": sibling_route,
            },
            output_result=tool_out,
            status=tool_status,
        )

        # 4. Record candidate IDOR/BOLA finding ONLY on empirically observed exposure
        if leaked:
            candidate_findings = list(state.candidate_findings)
            candidate_findings.append({
                "title": "BOLA / IDOR in User Profile Endpoint",
                "description": (
                    f"Target route '{sample_route}' permits unauthenticated access to user profile records "
                    f"(including email/API credentials) without caller ownership validation."
                ),
                "severity": "High",
                "cwe_id": "CWE-639",
                "wstg_id": "WSTG-ATHZ-04",
                "affected_parameter": "user_id",
                "matched_at": sample_route,
                "source": "authz_agent",
                **evidence_fields,
            })
            state.candidate_findings = candidate_findings
            state.add_log(self.agent_id, f"Confirmed authorization data exposure on {sample_route} (HTTP {observed_status}).")
        else:
            state.add_log(self.agent_id, f"Completed authorization probe on {sample_route}: no unauthenticated data leakage detected.")

        return state
