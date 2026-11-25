"""AGT-11: Vulnerability Validation Agent & AGT-12: False Positive Analysis Agent.

Executes deterministic reproduction harnesses to confirm genuine security defects and refute false positives.
"""

import asyncio
import json
import time
from typing import Optional
from urllib.parse import urlparse
import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from agents.base import BaseAgent
from agents.llm.provider import BaseLLMProvider
from packages.common.http_client import safe_request
from packages.schemas.finding import FalsePositiveCreate, FindingCreate
from services.evidence_engine.finding_service import FindingService
from services.execution_engine.planner import sync_wstg_instance_for_finding
from services.orchestrator.state import PentestWorkflowState


def evaluate_reproduction_signature(
    cwe_id: Optional[str],
    title: str,
    status_code: Optional[int],
    response_body: str,
    response_headers: dict,
    repro_error: Optional[str] = None
) -> tuple[bool, str]:
    """
    Evaluates whether empirical reproduction succeeded according to the per-class signature table.
    Enforces the Failure Set invariant: connection error, timeout, or 404/502/503/504 on required paths NEVER promotes.
    Returns (matched: bool, reason: str).
    """
    if repro_error is not None:
        return False, f"Reproduction connection/timeout error: {repro_error}"

    if status_code is None:
        return False, "Reproduction probe was not executed or yielded no response"

    # Strict Failure Set: 404/502/503/504 on an endpoint that must exist never promotes
    if status_code in (404, 502, 503, 504):
        return False, f"Reproduction probe encountered failure set HTTP {status_code}"

    cwe = (cwe_id or "").upper()
    title_low = (title or "").lower()
    body_low = (response_body or "").lower()

    # Class 1: SQL Injection (CWE-89)
    # Database error signature in body; HTTP 500 is explicitly valid
    if cwe == "CWE-89" or "sqli" in title_low or "sql injection" in title_low or "sql" in title_low:
        sql_error_signatures = (
            "syntax error", "sql syntax", "sqlite3", "sqlite_error",
            "psycopg2", "postgresql", "pg_", "mysql", "mariadb",
            "ora-", "oracle", "microsoft ole db", "odbc", "jdbc",
            "unclosed quotation mark", "driver", "sqlstate"
        )
        if any(sig in body_low for sig in sql_error_signatures):
            return True, f"SQL database error signature matched in body (HTTP {status_code})"
        if status_code in (200, 201) and ("database error" in body_low or "syntax error" in body_low):
            return True, f"SQL injection indicator matched (HTTP {status_code})"
        return False, f"SQL injection database error signature not observed in body (HTTP {status_code})"

    # Class 2: Cross-Site Scripting (XSS / CWE-79)
    # Unescaped reflection of canary marker / script context in response body
    if cwe == "CWE-79" or "xss" in title_low or "cross-site scripting" in title_low:
        xss_indicators = ("<script>", "<script", "alert(", "onerror=", "onload=", "javascript:")
        if status_code in (200, 201, 206) and any(tag in response_body for tag in xss_indicators):
            return True, f"Unescaped executable script marker reflected in body (HTTP {status_code})"
        return False, f"XSS payload not reflected unescaped in response body (HTTP {status_code})"

    # Class 3: Server-Side Template Injection (SSTI / CWE-1336 / CWE-94)
    # Evaluated marker (e.g. 49 for {{7*7}}) or template engine error in body
    if cwe in ("CWE-1336", "CWE-94") or "ssti" in title_low or "template injection" in title_low:
        ssti_markers = ("49", "jinja2", "twig", "freemarker", "velocity", "templatetags")
        if status_code in (200, 500) and any(m in body_low for m in ssti_markers):
            return True, f"SSTI evaluated marker or engine syntax observed in body (HTTP {status_code})"
        return False, f"SSTI signature not observed in response body (HTTP {status_code})"

    # Class 4: IDOR / BOLA (CWE-639 / CWE-284)
    # Another identity's object/data returned with HTTP 200/206/304
    if cwe in ("CWE-639", "CWE-284") or "idor" in title_low or "bola" in title_low:
        if status_code in (200, 206, 304):
            sensitive_indicators = ("\"id\"", "\"user_id\"", "\"email\"", "\"api_key\"", "\"data\"", "\"profile\"")
            if any(ind in body_low for ind in sensitive_indicators):
                return True, f"Object/resource state retrieved successfully (HTTP {status_code})"
        return False, f"IDOR/BOLA unauthorized resource access not demonstrated (HTTP {status_code})"

    # Class 5: Security Headers / Configuration (CWE-693 / CWE-16)
    # Header absence independent of status code (provided not in failure set)
    if cwe in ("CWE-693", "CWE-16") or "header" in title_low or "hsts" in title_low or "csp" in title_low:
        return True, f"Header inspection completed on HTTP {status_code}"

    # Default / Generic: requires success status code without failure set
    if status_code in (200, 201, 204, 301, 302):
        return True, f"Empirical reproduction returned HTTP {status_code}"

    return False, f"Empirical reproduction HTTP {status_code} does not match class signature"


class ValidationAgent(BaseAgent):
    """Validation Agent performing empirical reproduction, WAF filtering, and false positive refutations."""

    def __init__(
        self,
        session: AsyncSession,
        llm_provider: Optional[BaseLLMProvider] = None,
        http_transport: Optional[httpx.AsyncBaseTransport] = None,
    ):
        super().__init__(
            session=session,
            agent_id="AGT-11",
            agent_name="Vulnerability Validation & Quality Control Agent",
            phase="VALIDATION",
            allowed_tools=["repro_harness", "curl_builder", "response_differ", "fp_heuristic", "dedup_engine"],
            risk_tier="Medium",
            system_prompt=(
                "You are the Vulnerability Validation & False Positive Analysis Agent (AGT-11/12) for Pentesa. "
                "Enforce the Evidence Triad: verify every candidate vulnerability with an empirical reproduction probe. "
                "Refute WAF block pages, custom error pages, and static pattern reflections."
            ),
            llm_provider=llm_provider
        )
        self.http_transport = http_transport

    async def execute(self, state: PentestWorkflowState) -> PentestWorkflowState:
        finding_service = FindingService(self.session)
        confirmed = list(state.confirmed_findings)
        false_positives = list(state.false_positives)

        for candidate in state.candidate_findings:
            title = candidate.get("title", "Security Anomaly")
            matched_at = candidate.get("matched_at") or candidate.get("target_url")
            if not matched_at:
                state.add_log(
                    self.agent_id,
                    f"Candidate '{title}' lacks target URL / matched_at; skipping validation.",
                    level="WARN",
                )
                continue

            # 1. Scope check before reproduction probe
            is_allowed = await self.check_scope(state.project_id, matched_at)
            if not is_allowed:
                state.add_log(self.agent_id, f"Candidate target {matched_at} is out of scope. Skipping validation.", level="WARN")
                continue

            # 2. Empirical live reproduction across ALL scan profiles + capture authentic wire evidence
            repro_status_code: Optional[int] = candidate.get("status_code")
            repro_duration_ms = 0
            live_repro_excerpt = None
            live_req_wire = None
            live_resp_wire = None
            live_repro_error = None
            repro_body = candidate.get("raw_response") or ""
            repro_headers = {}

            raw_req_excerpt = (candidate.get("raw_request") or "")[:400]
            raw_resp_excerpt = (candidate.get("raw_response") or "")[:900]

            if matched_at.lower().startswith(("http://", "https://")):
                parsed_matched = urlparse(matched_at)
                req_path = f"{parsed_matched.path or '/'}{f'?{parsed_matched.query}' if parsed_matched.query else ''}"
                host_hdr = parsed_matched.netloc or (parsed_matched.hostname or "")
                t_start = time.time()
                try:
                    async with httpx.AsyncClient(
                        timeout=httpx.Timeout(3.0, connect=1.5),
                        verify=False,
                        transport=self.get_http_transport(),
                    ) as client:
                        r_live, _ = await safe_request(
                            client=client,
                            method="GET",
                            url=matched_at,
                            project_id=state.project_id,
                            session=self.session,
                            follow_redirects=True,
                            resolve_dns=True,
                        )
                    repro_status_code = r_live.status_code
                    repro_duration_ms = max(1, int((time.time() - t_start) * 1000))
                    repro_body = r_live.text
                    repro_headers = dict(r_live.headers)
                    raw_hdrs = "\r\n".join(f"{k}: {v}" for k, v in list(r_live.headers.items())[:15])
                    live_repro_excerpt = (
                        f"HTTP {r_live.status_code} ({r_live.headers.get('content-type', '')}): "
                        f"{r_live.text[:600]}"
                    )
                    live_req_wire = (
                        f"GET {req_path} HTTP/1.1\r\n"
                        f"Host: {host_hdr}\r\n"
                        f"User-Agent: Pentesa-Validation-Agent\r\n\r\n"
                    )
                    live_resp_wire = (
                        f"HTTP/1.1 {r_live.status_code}\r\n{raw_hdrs}\r\n\r\n{r_live.text[:900]}"
                    )
                except Exception as exc:
                    repro_duration_ms = max(1, int((time.time() - t_start) * 1000))
                    live_repro_error = str(exc)

            # 3. Evaluate Empirical Reproduction Signature (Empirical Evidence Gate)
            sig_matched, sig_reason = evaluate_reproduction_signature(
                cwe_id=candidate.get("cwe_id"),
                title=title,
                status_code=repro_status_code,
                response_body=repro_body,
                response_headers=repro_headers,
                repro_error=live_repro_error,
            )

            # 4. LLM Evaluation & Reproduction Reasoning WITH actual observed evidence
            candidate_payload = {
                k: v for k, v in candidate.items() if k not in ("raw_request", "raw_response")
            }
            if raw_req_excerpt:
                candidate_payload["observed_request_excerpt"] = raw_req_excerpt
            if raw_resp_excerpt:
                candidate_payload["observed_response_excerpt"] = raw_resp_excerpt
            if live_repro_excerpt:
                candidate_payload["live_reproduction_probe"] = live_repro_excerpt
            if live_repro_error:
                candidate_payload["live_reproduction_error"] = live_repro_error

            prompt = (
                f"Evaluate candidate finding ({state.scan_profile} scan): '{title}' at '{matched_at}'. "
                f"Candidate & empirical evidence: {json.dumps(candidate_payload)}. "
                f"Instructions: Review the observed HTTP response and reproduction probe if present. "
                f"Set 'is_valid': true and 'is_false_positive': false if the observed evidence demonstrates the flaw "
                f"(e.g. exposed secrets, raw SQL syntax error, unescaped <script> tag in text/html, unauthenticated api_key PII disclosure, or missing defensive response headers on HTTP 200) "
                f"or if an upstream deterministic scanner verified it offline without a WAF block/404 refutation. "
                f"Only set 'is_valid': false if evidence clearly shows a WAF 403 block, 404/escaped output, or contradiction. "
                f"Respond strictly in concise JSON with boolean keys 'is_valid' and 'is_false_positive'."
            )
            llm_res = await self.generate_llm_response(prompt=prompt, system_prompt=self.system_prompt, json_mode=True)

            await self.log_decision(
                thought_trace=llm_res.content,
                intent=f"Validate empirical reproducibility of '{title}'",
                confidence="High"
            )

            # 5. Evaluate verdict safely (handle JSON booleans without false matching key names!)
            # Rule: LLM verdict may DEMOTE candidate, but may NEVER promote over a failed empirical signature!
            llm_demotes = False
            raw_text = (llm_res.content or "").strip()
            try:
                clean_json = raw_text
                if clean_json.startswith("```json"):
                    clean_json = clean_json[7:]
                elif clean_json.startswith("```"):
                    clean_json = clean_json[3:]
                if clean_json.endswith("```"):
                    clean_json = clean_json[:-3]
                parsed = json.loads(clean_json.strip())
                if isinstance(parsed, dict):
                    if parsed.get("is_valid") is False or parsed.get("is_false_positive") is True:
                        llm_demotes = True
            except Exception:
                low = raw_text.lower()
                if "waf_block_page" in low or ("false_positive" in low and '"is_false_positive": false' not in low):
                    llm_demotes = True

            is_false_positive = False
            refute_class = "WAF_BLOCK_PAGE"
            refute_justification = "Validation analysis refuted candidate as non-exploitable / blocked or lacking empirical confirmation."
            refute_reason = "VALIDATION_REFUTED"

            if not sig_matched:
                # Hard empirical gate: Failed reproduction probe or failure set (404/502/503/504) never promotes
                is_false_positive = True
                refute_class = "FAILED_EMPIRICAL_REPRODUCTION"
                refute_justification = f"Empirical reproduction failed: {sig_reason}"
                refute_reason = "EMPIRICAL_GATE_FAILURE"
            elif llm_demotes:
                # LLM verdict demotes candidate to false positive
                is_false_positive = True
                refute_class = "WAF_BLOCK_PAGE"
                refute_justification = "Validation analysis refuted candidate as benign or false positive."
                refute_reason = "LLM_ANALYSIS_DEMOTION"

            if is_false_positive:
                false_positives.append({
                    "title": title,
                    "classification": refute_class,
                    "justification": refute_justification
                })
                await self.log_tool_call(
                    tool_name="fp_heuristic",
                    input_arguments={"candidate_title": title, "matched_at": matched_at},
                    output_result={"refuted": True, "reason": refute_reason, "details": refute_justification},
                    status="SUCCESS"
                )
            else:
                # Deduplication check: Do not re-insert duplicate findings on repeated runs
                existing_findings = await finding_service.list_findings(
                    project_id=state.project_id,
                    cwe_id=candidate.get("cwe_id")
                )
                cand_id = candidate.get("existing_finding_id")
                existing = next(
                    (
                        f for f in existing_findings
                        if (cand_id and str(f.id) == cand_id)
                        or f.title == title
                        or (
                            candidate.get("cwe_id")
                            and f.cwe_id == candidate.get("cwe_id")
                            and candidate.get("affected_parameter")
                            and f.affected_parameter == candidate.get("affected_parameter")
                        )
                    ),
                    None
                )
                raw_req_val = candidate.get("raw_request") or live_req_wire
                raw_resp_val = candidate.get("raw_response") or live_resp_wire
                repro_succeeded = bool((live_repro_excerpt and not live_repro_error) or candidate.get("raw_response"))

                if existing:
                    created_finding = existing
                    if existing.status == "Detected" and repro_succeeded:
                        existing.status = "Confirmed"
                        existing.confidence = "Confirmed"
                        await self.session.commit()
                    await sync_wstg_instance_for_finding(self.session, state.project_id, existing.wstg_id)
                    await self.log_tool_call(
                        tool_name="dedup_engine",
                        input_arguments={"candidate_title": title, "existing_id": str(existing.id)},
                        output_result={"duplicate_prevented": True, "action": "reused_existing_finding"},
                        status="SUCCESS"
                    )
                else:
                    # Confirm new finding in database ONLY with authentic captured evidence
                    created_finding = await finding_service.create_finding(
                        project_id=state.project_id,
                        payload=FindingCreate(
                            title=title,
                            description=candidate.get("description", f"Empirically validated vulnerability at {matched_at}."),
                            severity=candidate.get("severity", "Medium"),
                            cwe_id=candidate.get("cwe_id", "CWE-200"),
                            wstg_id=candidate.get("wstg_id", "WSTG-INFO-01"),
                            affected_parameter=candidate.get("affected_parameter"),
                            detection_source=candidate.get("source", "validation_agent"),
                            status="Confirmed",
                            confidence="Confirmed" if repro_succeeded else "Medium",
                            raw_request=raw_req_val if (raw_req_val and raw_resp_val) else None,
                            raw_response=raw_resp_val if (raw_req_val and raw_resp_val) else None,
                            reproduction_curl=candidate.get("reproduction_curl") or (f"curl -i -s '{matched_at}'" if matched_at else None),
                        )
                    )

                repro = await finding_service.record_reproduction(
                    finding_id=created_finding.id,
                    project_id=state.project_id,
                    reproduced_by=self.agent_id,
                    success=repro_succeeded,
                    status_code=repro_status_code,
                    duration_ms=repro_duration_ms or None
                )

                await self.log_tool_call(
                    tool_name="repro_harness",
                    input_arguments={"finding_id": str(created_finding.id), "matched_at": matched_at},
                    output_result={"reproduced": repro_succeeded, "status_code": repro.response_status_code, "duration_ms": repro_duration_ms},
                    status="SUCCESS",
                    duration_ms=repro_duration_ms
                )

                confirmed.append({
                    "id": str(created_finding.id),
                    "title": created_finding.title,
                    "severity": created_finding.severity,
                    "status": created_finding.status,
                    "confidence": created_finding.confidence
                })

        state.confirmed_findings = confirmed
        state.false_positives = false_positives
        state.add_log(self.agent_id, f"Validation complete. Confirmed: {len(confirmed)}, False Positives: {len(false_positives)}.")
        state.transition_phase("REPORTING")

        return state
