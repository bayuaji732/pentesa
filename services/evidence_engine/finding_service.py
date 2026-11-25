"""Findings management, status transition lifecycle, and false positive service."""

import asyncio
import datetime
import hashlib
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlparse, urlunparse
import httpx
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from apps.api.dependencies import record_audit_log
from database.models.discovery import Endpoint
from database.models.finding import (
    FalsePositive,
    Finding,
    FindingEvidence,
    FindingReproduction,
    FindingStatusHistory
)
from database.models.project import Project
from database.models.scope import ScopeRule
from packages.common.exceptions import BadRequestError, ConflictError, ResourceNotFoundError
from packages.common.http_client import safe_request
from packages.schemas.finding import (
    FalsePositiveCreate,
    FindingBatchUpdate,
    FindingCreate,
    FindingEvidenceCreate,
    FindingRetestRequest,
    FindingRetestResponse,
    FindingStatusUpdate
)
from services.evidence_engine.curl_generator import generate_reproduction_curl
from services.evidence_engine.hasher import compute_stream_hash
from services.evidence_engine.redactor import redact_raw_stream
from services.execution_engine.planner import sync_wstg_instance_for_finding
from services.execution_engine.runners import resolve_project_origin
from services.scope_engine.service import scope_service

# 10-Step Lifecycle Allowed Transitions
VALID_FINDING_TRANSITIONS: Dict[str, List[str]] = {
    "Detected": ["Triaged", "Validating", "Confirmed", "False Positive", "Needs Manual Review"],
    "Triaged": ["Validating", "Confirmed", "False Positive", "Needs Manual Review"],
    "Validating": ["Confirmed", "False Positive", "Needs Manual Review"],
    "Needs Manual Review": ["Confirmed", "False Positive"],
    "Confirmed": ["Remediated", "Accepted Risk", "False Positive"],
    "Remediated": ["Retested", "Confirmed"],
    "Retested": ["Confirmed", "Remediated"],
    "False Positive": ["Detected", "Confirmed"],
    "Accepted Risk": ["Confirmed", "Remediated"]
}


def _parse_raw_http_request(raw_request: str) -> Tuple[str, str, Dict[str, str], Optional[str]]:
    """Extract (method, target, headers, body) from a raw RFC 7230 HTTP request string."""
    normalized = raw_request or ""
    if "\r\n\r\n" in normalized:
        head_block, body = normalized.split("\r\n\r\n", 1)
    elif "\n\n" in normalized:
        head_block, body = normalized.split("\n\n", 1)
    else:
        head_block, body = normalized, ""

    lines = [line.rstrip("\r") for line in head_block.splitlines() if line.strip()]
    method = "GET"
    req_target = ""
    headers: Dict[str, str] = {}

    if lines:
        req_match = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+(\S+)", lines[0], re.IGNORECASE)
        if req_match:
            method = req_match.group(1).upper()
            req_target = req_match.group(2)
            header_lines = lines[1:]
        else:
            header_lines = lines
        for line in header_lines:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

    clean_body = body.strip() if body and body.strip() else None
    return method, req_target, headers, clean_body


class FindingService:
    """Service layer managing findings, evidence, status lifecycle, and false positives."""

    default_http_transport: Optional[httpx.AsyncBaseTransport] = None

    def __init__(
        self,
        session: AsyncSession,
        http_transport: Optional[httpx.AsyncBaseTransport] = None,
    ):
        self.session = session
        self.http_transport = http_transport

    async def _resolve_scheme_for_host(
        self,
        project_id: uuid.UUID,
        host_with_port: str,
        fallback_scheme: str = "https",
    ) -> str:
        """Infer http vs https from project metadata, port, or private/container hostname."""
        hostname = host_with_port.split(":")[0].strip("[]").lower()
        origin = await resolve_project_origin(self.session, project_id, hostname)
        if origin:
            parsed_orig = urlparse(origin)
            if parsed_orig.scheme:
                return parsed_orig.scheme

        if ":" in host_with_port:
            try:
                port = int(host_with_port.rsplit(":", 1)[1])
                if port in (80, 3000, 5000, 8000, 8080, 8888, 9000):
                    return "http"
                if port in (443, 8443, 4433):
                    return "https"
            except ValueError:
                pass

        if (
            hostname in ("localhost", "127.0.0.1", "::1", "host.docker.internal", "juice-shop", "dvwa")
            or hostname.startswith(("10.", "192.168.", "172."))
            or "." not in hostname
        ):
            return "http"
        return fallback_scheme

    async def _resolve_finding_request_target(
        self,
        finding: Finding,
        override_payload: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Derive concrete HTTP request parameters from captured evidence or linked Endpoint."""
        method: Optional[str] = None
        url: Optional[str] = None
        headers: Dict[str, str] = {}
        body: Optional[str] = None

        for ev in (finding.evidence or []):
            if ev.raw_request:
                parsed_method, req_target, parsed_hdrs, parsed_body = _parse_raw_http_request(ev.raw_request)
                if req_target.lower().startswith(("http://", "https://")):
                    url = req_target
                    method = parsed_method
                    headers = parsed_hdrs
                    body = parsed_body
                    break
                host_hdr = next((v for k, v in parsed_hdrs.items() if k.lower() == "host"), None)
                if host_hdr:
                    scheme = await self._resolve_scheme_for_host(finding.project_id, host_hdr)
                    clean_path = req_target if req_target.startswith("/") else f"/{req_target}"
                    url = f"{scheme}://{host_hdr}{clean_path}"
                    method = parsed_method
                    headers = parsed_hdrs
                    body = parsed_body
                    break

            if not url and ev.reproduction_curl:
                url_match = re.search(r"['\"]?(https?://[^\s'\"\\]+)['\"]?", ev.reproduction_curl)
                if url_match:
                    url = url_match.group(1)
                    meth_match = re.search(r"-X\s+([A-Z]+)", ev.reproduction_curl)
                    method = meth_match.group(1).upper() if meth_match else (method or "GET")
                    break

        if not url and finding.endpoint:
            origin = await resolve_project_origin(self.session, finding.project_id, finding.endpoint.fqdn)
            scheme = await self._resolve_scheme_for_host(finding.project_id, finding.endpoint.fqdn)
            base_origin = origin or f"{scheme}://{finding.endpoint.fqdn}"
            url = f"{base_origin}{finding.endpoint.url_path}"
            method = method or finding.endpoint.http_method or "GET"

        if not url:
            return None

        method = method or "GET"

        if override_payload:
            if override_payload.lower().startswith(("http://", "https://")):
                url = override_payload
            elif finding.affected_parameter:
                parsed = urlparse(url)
                qs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k != finding.affected_parameter]
                qs.append((finding.affected_parameter, override_payload))
                url = urlunparse(parsed._replace(query=urlencode(qs)))

        # Strip hop-by-hop headers so httpx manages framing cleanly
        forwarded_headers = {
            k: v
            for k, v in headers.items()
            if k.lower() not in {"host", "content-length", "connection", "accept-encoding"}
        }
        return {
            "method": method,
            "url": url,
            "headers": forwarded_headers,
            "body": body,
        }

    @staticmethod
    def _evaluate_retest_response(
        finding: Finding,
        target_url: str,
        resp: httpx.Response,
        expected_status_code: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """Empirically classify HTTP retest outcome against finding vulnerability class."""
        status_code = resp.status_code
        body = resp.text or ""
        body_low = body.lower()
        ct_low = resp.headers.get("content-type", "").lower()
        hdrs_low = {k.lower(): v for k, v in resp.headers.items()}
        cwe = (finding.cwe_id or "").upper()
        title_low = (finding.title or "").lower()

        if expected_status_code is not None:
            if status_code == expected_status_code:
                return (
                    True,
                    f"Empirical probe to {target_url} received HTTP {status_code} matching expected patched behavior.",
                )
            if expected_status_code in (400, 401, 403, 404, 410, 422):
                return (
                    False,
                    f"Empirical probe to {target_url} returned HTTP {status_code} instead of expected HTTP {expected_status_code}.",
                )

        if status_code in (400, 401, 403, 404, 410, 422, 429):
            return (
                True,
                f"Empirical probe to {target_url} rejected with defensive HTTP {status_code}. Remediation confirmed.",
            )

        # 1. SQL Injection (CWE-89)
        if cwe == "CWE-89" or "sql" in title_low:
            sqli_errors = (
                "sqlite3",
                "sqlite_error",
                "sql syntax",
                "mysql",
                "mariadb",
                "postgresql",
                "sequelizedatabaseerror",
                "operationalerror",
                "unterminated quoted",
                "unsanitized sql",
                "you have an error in your sql",
            )
            if status_code >= 500 or any(err in body_low for err in sqli_errors):
                return (
                    False,
                    f"Empirical probe to {target_url} triggered SQL error / HTTP {status_code}. SQL injection remains active.",
                )
            return (
                True,
                f"Empirical probe to {target_url} returned HTTP {status_code} without SQL syntax errors or injection leakage. Remediation confirmed.",
            )

        # 2. Reflected XSS (CWE-79)
        if cwe == "CWE-79" or "xss" in title_low or "cross-site scripting" in title_low:
            parsed_u = urlparse(target_url)
            xss_markers = [
                v
                for _, v in parse_qsl(parsed_u.query, keep_blank_values=True)
                if "<script" in v.lower() or "onerror=" in v.lower() or "onload=" in v.lower()
            ]
            raw_script_hit = any(m in body or unquote(m) in body for m in xss_markers)
            if not xss_markers and ("<script>alert" in body_low or "onerror=" in body_low):
                raw_script_hit = True

            if status_code == 200 and "text/html" in ct_low and raw_script_hit:
                return (
                    False,
                    f"Empirical probe to {target_url} reflected unescaped executable script markup in HTML response. XSS remains active.",
                )
            return (
                True,
                f"Empirical probe to {target_url} returned HTTP {status_code} with script payload neutralized/escaped. Remediation confirmed.",
            )

        # 3. Missing Security Headers (CWE-693)
        if cwe == "CWE-693" or "security header" in title_low or "hsts" in title_low:
            required = ["content-security-policy", "x-content-type-options", "x-frame-options"]
            if target_url.lower().startswith("https://"):
                required.append("strict-transport-security")
            missing = [h for h in required if h not in hdrs_low]
            if missing:
                return (
                    False,
                    f"Empirical probe to {target_url} (HTTP {status_code}) still lacks defensive headers: {', '.join(missing)}.",
                )
            return (
                True,
                f"Empirical probe to {target_url} confirmed all checked defensive security headers are present.",
            )

        # 4. BOLA / IDOR (CWE-639)
        if cwe == "CWE-639" or "idor" in title_low or "bola" in title_low:
            idor_markers = (
                "\"api_key\"",
                "\"password\"",
                "\"jwt_secret\"",
                "\"secret_access_key\"",
                "\"security_warning\"",
                "idor:",
                "\"transferred\"",
            )
            if status_code == 200 and any(m in body_low for m in idor_markers):
                return (
                    False,
                    f"Empirical probe to {target_url} returned HTTP 200 exposing sensitive credentials or object state without caller authorization.",
                )
            return (
                True,
                f"Empirical probe to {target_url} returned HTTP {status_code} without unredacted sensitive exposure. Remediation confirmed.",
            )

        # 5. Sensitive Information / Config Disclosure (CWE-200 / CWE-538)
        if cwe in ("CWE-200", "CWE-538") or any(w in title_low for w in ("debug", ".git", ".env", "disclosure", "exposure")):
            leak_markers = (
                "jwt_secret",
                "connection_string",
                "secret_access_key",
                "debug_mode",
                "[core]",
                "db_password=",
                "aws_access_key_id=",
            )
            if status_code == 200 and any(m in body_low for m in leak_markers):
                return (
                    False,
                    f"Empirical probe to {target_url} (HTTP {status_code}) still exposes sensitive secrets/configuration artifacts.",
                )
            return (
                True,
                f"Empirical probe to {target_url} returned HTTP {status_code} without exposed secrets or config markers. Remediation confirmed.",
            )

        # 6. General finding fallback when HTTP 2xx/5xx returned without expected rejection
        return (
            False,
            f"Empirical probe to {target_url} received HTTP {status_code} matching unpatched response conditions.",
        )

    async def list_findings(
        self,
        project_id: uuid.UUID,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        cwe_id: Optional[str] = None,
        wstg_id: Optional[str] = None,
        search: Optional[str] = None
    ) -> List[Finding]:
        """Query project findings with multi-dimensional filtering."""
        stmt = (
            select(Finding)
            .options(
                selectinload(Finding.evidence),
                selectinload(Finding.endpoint)
            )
            .where(Finding.project_id == project_id)
        )

        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if status:
            stmt = stmt.where(Finding.status == status)
        if cwe_id:
            stmt = stmt.where(Finding.cwe_id == cwe_id)
        if wstg_id:
            stmt = stmt.where(Finding.wstg_id == wstg_id)
        if search:
            pattern = f"%{search}%"
            stmt = stmt.where(
                (Finding.title.ilike(pattern)) |
                (Finding.description.ilike(pattern))
            )

        stmt = stmt.order_by(desc(Finding.created_at))
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_finding(
        self,
        finding_id: Union[uuid.UUID, str],
        project_id: Optional[Union[uuid.UUID, str]] = None,
    ) -> Finding:
        """Fetch finding by ID with eager evidence loading."""
        try:
            normalized_finding_id = uuid.UUID(finding_id) if isinstance(finding_id, str) else finding_id
            normalized_project_id = uuid.UUID(project_id) if isinstance(project_id, str) else project_id
        except ValueError as e:
            raise BadRequestError(f"Invalid UUID format: {e}")

        stmt = (
            select(Finding)
            .execution_options(populate_existing=True)
            .options(
                selectinload(Finding.evidence),
                selectinload(Finding.endpoint),
                selectinload(Finding.reproductions),
                selectinload(Finding.false_positives),
                selectinload(Finding.status_history)
            )
            .where(Finding.id == normalized_finding_id)
        )
        if normalized_project_id:
            stmt = stmt.where(Finding.project_id == normalized_project_id)

        result = await self.session.execute(stmt)
        finding = result.scalar_one_or_none()
        if not finding:
            raise ResourceNotFoundError(f"Finding with ID {finding_id} not found.")
        return finding

    async def get_project_custom_secrets(self, project_id: uuid.UUID) -> List[str]:
        """Fetch active AuthProfile credentials and decrypt strictly in memory for redaction."""
        from database.models.auth_profile import AuthProfile
        stmt = select(AuthProfile).where(
            AuthProfile.project_id == project_id,
            AuthProfile.is_active.is_(True)
        )
        profiles = list((await self.session.execute(stmt)).scalars().all())
        secrets: List[str] = []
        for prof in profiles:
            try:
                creds = prof.get_credentials()
                if isinstance(creds, dict):
                    for v in creds.values():
                        if isinstance(v, str) and len(v.strip()) >= 4:
                            secrets.append(v.strip())
            except Exception as e:
                import logging
                logging.getLogger("pentesa.redactor").warning(
                    f"Fail-closed: unable to decrypt AuthProfile {prof.id} credentials: {e}"
                )
        return secrets

    async def create_finding(
        self,
        project_id: uuid.UUID,
        payload: FindingCreate,
        user_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Finding:
        """Create finding and attach initial forensic evidence if provided."""
        # Endpoint validation if provided
        ep_obj: Optional[Endpoint] = None
        if payload.endpoint_id:
            ep_stmt = select(Endpoint).where(
                Endpoint.id == payload.endpoint_id,
                Endpoint.project_id == project_id
            )
            ep_obj = (await self.session.execute(ep_stmt)).scalar_one_or_none()
            if not ep_obj:
                raise ResourceNotFoundError(f"Endpoint {payload.endpoint_id} not found in project.")

        # In-memory custom secrets resolution from AuthProfile
        custom_secrets = await self.get_project_custom_secrets(project_id)

        # AGT-MOCK-01: Auto-tag findings created under simulation or mock detection
        from packages.common.config import settings
        is_mock_active = (getattr(settings, "llm_provider", "") or "").lower() == "mock"
        is_sim = bool(
            payload.is_simulated
            or payload.title.startswith("[SIMULATED]")
            or (is_mock_active and (payload.detection_source or "").lower() in ("mock", "simulated", "mock_llm"))
        )
        finding_title = payload.title
        if is_sim and not finding_title.startswith("[SIMULATED]"):
            finding_title = f"[SIMULATED] {finding_title}"

        # DEFECT-REDACT-01: Redact narrative text fields
        clean_title = redact_raw_stream(finding_title, custom_secrets=custom_secrets)
        clean_desc = redact_raw_stream(payload.description, custom_secrets=custom_secrets)
        clean_remed = (
            redact_raw_stream(payload.remediation_guidance, custom_secrets=custom_secrets)
            if payload.remediation_guidance
            else None
        )
        clean_impact = (
            redact_raw_stream(payload.business_impact, custom_secrets=custom_secrets)
            if payload.business_impact
            else None
        )

        finding = Finding(
            project_id=project_id,
            endpoint_id=payload.endpoint_id,
            wstg_id=payload.wstg_id,
            title=clean_title,
            description=clean_desc,
            severity=payload.severity,
            status=payload.status,
            confidence=payload.confidence,
            cwe_id=payload.cwe_id,
            owasp_category=payload.owasp_category,
            cvss_score=payload.cvss_score,
            cvss_vector=payload.cvss_vector,
            affected_parameter=payload.affected_parameter,
            detection_source=payload.detection_source,
            remediation_guidance=clean_remed,
            business_impact=clean_impact,
            is_simulated=is_sim
        )
        self.session.add(finding)
        await self.session.flush()

        # If raw request/response were supplied, attach authentic forensic evidence
        if payload.raw_request and payload.raw_response:
            sanitized_req = redact_raw_stream(payload.raw_request, custom_secrets=custom_secrets)
            sanitized_resp = redact_raw_stream(payload.raw_response, custom_secrets=custom_secrets)
            parsed_method, parsed_target, parsed_hdrs, parsed_body = _parse_raw_http_request(sanitized_req)
            resolved_url = ""
            if parsed_target.lower().startswith(("http://", "https://")):
                resolved_url = parsed_target
            else:
                host_hdr = next((v for k, v in parsed_hdrs.items() if k.lower() == "host"), None)
                if host_hdr:
                    scheme = await self._resolve_scheme_for_host(project_id, host_hdr)
                    clean_path = parsed_target if parsed_target.startswith("/") else f"/{parsed_target}"
                    resolved_url = f"{scheme}://{host_hdr}{clean_path}"
                elif ep_obj:
                    ep_origin = await resolve_project_origin(self.session, project_id, ep_obj.fqdn)
                    scheme = await self._resolve_scheme_for_host(project_id, ep_obj.fqdn)
                    resolved_url = f"{ep_origin or f'{scheme}://{ep_obj.fqdn}'}{ep_obj.url_path}"

            method_for_curl = parsed_method or (ep_obj.http_method if ep_obj else "GET")
            if payload.reproduction_curl:
                repro_curl = redact_raw_stream(payload.reproduction_curl, custom_secrets=custom_secrets)
            elif resolved_url:
                repro_curl = generate_reproduction_curl(
                    method=method_for_curl,
                    url=resolved_url,
                    headers=parsed_hdrs,
                    body=parsed_body,
                    redact_auth=True,
                )
            else:
                repro_curl = "N/A"
            repro_curl = redact_raw_stream(repro_curl, custom_secrets=custom_secrets)
            evidence = FindingEvidence(
                finding_id=finding.id,
                raw_request=sanitized_req,
                raw_response=sanitized_resp,
                reproduction_curl=repro_curl,
                request_hash_sha256=compute_stream_hash(sanitized_req),
                response_hash_sha256=compute_stream_hash(sanitized_resp),
            )
            self.session.add(evidence)

        # Record initial status in history
        history = FindingStatusHistory(
            finding_id=finding.id,
            previous_status="None",
            new_status=finding.status,
            changed_by=user_id,
            justification="Initial detection registration"
        )
        self.session.add(history)
        await self.session.commit()
        await self.session.refresh(finding)

        # Audit log creation
        await record_audit_log(
            session=self.session,
            action="FINDING_CREATED",
            resource_type="Finding",
            resource_id=str(finding.id),
            details={
                "title": finding.title,
                "severity": finding.severity,
                "status": finding.status,
                "cwe_id": finding.cwe_id,
                "wstg_id": finding.wstg_id
            },
            project_id=project_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        await self.session.commit()
        await sync_wstg_instance_for_finding(self.session, project_id, finding.wstg_id)

        return await self.get_finding(finding.id, project_id)

    async def update_status(
        self,
        finding_id: uuid.UUID,
        project_id: uuid.UUID,
        payload: FindingStatusUpdate,
        user_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Finding:
        """Update finding status enforcing lifecycle transition rules with mandatory justification."""
        finding = await self.get_finding(finding_id, project_id)
        current_status = finding.status
        new_status = payload.status

        if current_status != new_status:
            allowed = VALID_FINDING_TRANSITIONS.get(current_status, [])
            if new_status not in allowed:
                raise BadRequestError(
                    f"Illegal finding status transition from '{current_status}' to '{new_status}'. "
                    f"Allowed transitions: {allowed}"
                )

            # Record history
            history = FindingStatusHistory(
                finding_id=finding.id,
                previous_status=current_status,
                new_status=new_status,
                changed_by=user_id,
                justification=payload.justification
            )
            self.session.add(history)
            finding.status = new_status
            await self.session.commit()
            await self.session.refresh(finding)

            # Audit log transition
            await record_audit_log(
                session=self.session,
                action="FINDING_STATUS_UPDATED",
                resource_type="Finding",
                resource_id=str(finding.id),
                details={
                    "old_status": current_status,
                    "new_status": new_status,
                    "justification": payload.justification
                },
                project_id=project_id,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent
            )
            await self.session.commit()
            await sync_wstg_instance_for_finding(self.session, project_id, finding.wstg_id)
            await self.session.refresh(finding)

        return finding

    async def register_false_positive(
        self,
        finding_id: uuid.UUID,
        project_id: uuid.UUID,
        payload: FalsePositiveCreate,
        user_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> FalsePositive:
        """Refute candidate finding as false positive and transition status."""
        finding = await self.get_finding(finding_id, project_id)

        # Transition status to False Positive
        old_status = finding.status
        finding.status = "False Positive"

        fp_entry = FalsePositive(
            finding_id=finding.id,
            classification=payload.classification,
            justification=payload.justification
        )
        self.session.add(fp_entry)

        history = FindingStatusHistory(
            finding_id=finding.id,
            previous_status=old_status,
            new_status="False Positive",
            changed_by=user_id,
            justification=f"Refuted as False Positive ({payload.classification}): {payload.justification}"
        )
        self.session.add(history)
        await self.session.commit()
        await self.session.refresh(fp_entry)

        # Audit log refutation
        await record_audit_log(
            session=self.session,
            action="FINDING_FALSE_POSITIVE_REFUTED",
            resource_type="Finding",
            resource_id=str(finding.id),
            details={
                "classification": payload.classification,
                "justification": payload.justification
            },
            project_id=project_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        await self.session.commit()
        await sync_wstg_instance_for_finding(self.session, project_id, finding.wstg_id)

        return fp_entry

    async def record_reproduction(
        self,
        finding_id: uuid.UUID,
        project_id: uuid.UUID,
        reproduced_by: str,
        success: bool,
        status_code: Optional[int] = None,
        duration_ms: Optional[int] = None
    ) -> FindingReproduction:
        """Record an empirical reproduction outcome."""
        finding = await self.get_finding(finding_id, project_id)

        repro = FindingReproduction(
            finding_id=finding.id,
            reproduced_by=reproduced_by,
            success=success,
            response_status_code=status_code,
            duration_ms=duration_ms
        )
        self.session.add(repro)

        if success:
            finding.confidence = "Confirmed"

        await self.session.commit()
        await self.session.refresh(repro)
        return repro

    async def retest_finding(
        self,
        finding_id: uuid.UUID,
        project_id: uuid.UUID,
        payload: FindingRetestRequest,
        user_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        http_transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> FindingRetestResponse:
        """Execute one-click empirical HTTP verification retest to confirm remediation or persistence."""
        finding = await self.get_finding(finding_id, project_id)
        previous_status = finding.status

        target_spec = await self._resolve_finding_request_target(
            finding,
            override_payload=payload.verification_payload,
        )
        if not target_spec or not target_spec.get("url"):
            raise BadRequestError(
                "Cannot run empirical retest: finding has no linked endpoint URL or HTTP reproduction evidence."
            )

        target_url: str = target_spec["url"]
        method: str = target_spec["method"]
        req_headers: Dict[str, str] = target_spec.get("headers") or {}
        req_body: Optional[str] = target_spec.get("body")

        # Strict Scope Enforcement prior to live HTTP probe
        proj = (await self.session.execute(select(Project).where(Project.id == project_id))).scalar_one()
        rules = (await self.session.execute(select(ScopeRule).where(ScopeRule.project_id == project_id))).scalars().all()
        scope_res = scope_service.check_target(
            project=proj,
            target_url=target_url,
            rules=rules,
            resolve_dns=False,
        )
        if not scope_res.is_in_scope:
            raise BadRequestError(f"Retest target '{target_url}' is blocked by scope engine: {scope_res.reason}")

        effective_transport = (
            http_transport
            if http_transport is not None
            else (self.http_transport if self.http_transport is not None else self.default_http_transport)
        )

        status_code: Optional[int] = None
        is_remediated = False
        repro_success = False
        t0 = time.monotonic()

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(5.0, connect=2.0),
                verify=False,
                transport=effective_transport,
            ) as client:
                body_bytes = req_body.encode("utf-8") if isinstance(req_body, str) else req_body
                resp, _ = await safe_request(
                    client=client,
                    method=method,
                    url=target_url,
                    project_id=finding.project_id,
                    session=self.session,
                    headers=req_headers,
                    content=body_bytes,
                    follow_redirects=True,
                    resolve_dns=False,
                )

            duration_ms = max(1, int((time.monotonic() - t0) * 1000))
            status_code = resp.status_code
            is_remediated, notes = self._evaluate_retest_response(
                finding=finding,
                target_url=target_url,
                resp=resp,
                expected_status_code=payload.expected_status_code,
            )
            repro_success = not is_remediated
            new_status = "Remediated" if is_remediated else "Confirmed"
        except (httpx.RequestError, asyncio.TimeoutError) as exc:
            duration_ms = max(1, int((time.monotonic() - t0) * 1000))
            status_code = None
            is_remediated = False
            repro_success = False
            new_status = previous_status
            notes = (
                f"Empirical retest failed to connect to '{target_url}': {exc}. "
                f"Remediation unverified; status retained as '{previous_status}'."
            )

        finding.status = new_status
        if is_remediated or repro_success:
            finding.confidence = "Confirmed"

        repro = FindingReproduction(
            finding_id=finding.id,
            reproduced_by=str(user_id) if user_id else "RETEST_WORKER",
            success=repro_success,
            response_status_code=status_code,
            duration_ms=duration_ms
        )
        self.session.add(repro)

        history = FindingStatusHistory(
            finding_id=finding.id,
            previous_status=previous_status,
            new_status=new_status,
            changed_by=user_id,
            justification=f"Automated retest outcome: {notes}"
        )
        self.session.add(history)
        await self.session.commit()
        await self.session.refresh(finding)

        await record_audit_log(
            session=self.session,
            action="FINDING_RETEST_EXECUTED",
            resource_type="Finding",
            resource_id=str(finding.id),
            details={
                "target_url": target_url,
                "previous_status": previous_status,
                "new_status": new_status,
                "is_remediated": is_remediated,
                "status_code": status_code,
                "duration_ms": duration_ms,
            },
            project_id=project_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        await self.session.commit()
        await sync_wstg_instance_for_finding(self.session, project_id, finding.wstg_id)

        now_utc = datetime.datetime.now(datetime.timezone.utc)
        return FindingRetestResponse(
            finding_id=finding.id,
            previous_status=previous_status,
            new_status=new_status,
            is_remediated=is_remediated,
            reproduction_success=repro_success,
            http_status_code=status_code,
            verification_notes=notes,
            tested_at=now_utc
        )

    async def batch_update_status(
        self,
        project_id: uuid.UUID,
        payload: FindingBatchUpdate,
        user_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> List[Finding]:
        """Perform batch status transitions across multiple findings enforcing lifecycle state machine."""
        updated_findings = []
        new_status = payload.status

        for finding_id in payload.finding_ids:
            finding = await self.get_finding(finding_id, project_id)
            current_status = finding.status

            if current_status != new_status:
                allowed = VALID_FINDING_TRANSITIONS.get(current_status, [])
                if new_status not in allowed:
                    raise BadRequestError(
                        f"Cannot transition finding {finding_id} from '{current_status}' to '{new_status}'."
                    )

                history = FindingStatusHistory(
                    finding_id=finding.id,
                    previous_status=current_status,
                    new_status=new_status,
                    changed_by=user_id,
                    justification=payload.justification
                )
                self.session.add(history)
                finding.status = new_status
                updated_findings.append(finding)

        await self.session.commit()

        # Audit log batch triage
        await record_audit_log(
            session=self.session,
            action="FINDINGS_BATCH_UPDATED",
            resource_type="Finding",
            resource_id=str(project_id),
            details={
                "count": len(updated_findings),
                "target_status": new_status,
                "justification": payload.justification
            },
            project_id=project_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        await self.session.commit()
        for wid in {f.wstg_id for f in updated_findings if f.wstg_id}:
            await sync_wstg_instance_for_finding(self.session, project_id, wid)

        return updated_findings

    async def deduplicate_findings(self, project_id: uuid.UUID) -> Dict[str, Any]:
        """Cluster findings by signature: SHA256(project_id || path || method || parameter || cwe)."""
        findings = await self.list_findings(project_id)
        signature_map: Dict[str, List[Finding]] = {}

        for f in findings:
            path = f.endpoint.url_path if f.endpoint else "global"
            method = f.endpoint.http_method if f.endpoint else "ANY"
            param = f.affected_parameter or ""
            cwe = f.cwe_id or ""

            sig_raw = f"{project_id}|{path}|{method}|{param}|{cwe}".lower()
            sig = hashlib.sha256(sig_raw.encode("utf-8")).hexdigest()

            if sig not in signature_map:
                signature_map[sig] = []
            signature_map[sig].append(f)

        duplicates_found = 0
        clusters = []

        for sig, group in signature_map.items():
            if len(group) > 1:
                duplicates_found += len(group) - 1
                clusters.append({
                    "signature": sig,
                    "primary_finding_id": str(group[0].id),
                    "primary_title": group[0].title,
                    "duplicate_count": len(group) - 1,
                    "duplicate_ids": [str(item.id) for item in group[1:]]
                })

        return {
            "total_findings": len(findings),
            "unique_clusters": len(signature_map),
            "duplicates_detected": duplicates_found,
            "clusters": clusters
        }
