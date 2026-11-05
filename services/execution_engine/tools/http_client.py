"""Scope-enforced raw HTTP testing and request mutation engine."""

import time
import uuid
from typing import Dict, Optional
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.project import Project
from database.models.scope import ScopeRule
from packages.common.exceptions import ScopeViolationError
from packages.schemas.tool import HttpTestRequest, HttpTestResponse
from services.evidence_engine.collector import build_forensic_evidence
from services.scope_engine.service import scope_service


class RawHttpClient:
    """Dispatches raw, parameterized, or mutated HTTP requests within scope boundaries."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def execute_request(
        self,
        project_id: uuid.UUID,
        payload: HttpTestRequest
    ) -> HttpTestResponse:
        """Validate target scope and execute HTTP test with forensic artifact serialization."""
        # 1. Pre-flight Scope Check
        proj_stmt = select(Project).where(Project.id == project_id)
        proj = (await self.session.execute(proj_stmt)).scalar_one_or_none()
        if not proj:
            raise ScopeViolationError(f"Project {project_id} not found.")

        rules_stmt = select(ScopeRule).where(ScopeRule.project_id == project_id)
        rules = (await self.session.execute(rules_stmt)).scalars().all()

        scope_res = scope_service.check_target(
            project=proj,
            target_url=payload.url,
            rules=rules,
            resolve_dns=False
        )
        if not scope_res.is_in_scope:
            raise ScopeViolationError(
                f"HTTP test target '{payload.url}' blocked by scope engine: {scope_res.reason}"
            )

        start_time = time.time()

        # 2. Dispatch request
        async with httpx.AsyncClient(
            timeout=payload.timeout_seconds,
            follow_redirects=payload.follow_redirects,
            verify=False
        ) as client:
            resp = await client.request(
                method=payload.method.upper(),
                url=payload.url,
                headers=payload.headers,
                content=payload.body.encode("utf-8") if payload.body else None
            )

        duration_ms = int((time.time() - start_time) * 1000)
        resp_headers = {k: v for k, v in resp.headers.items()}
        resp_body = resp.text

        # 3. Build forensic evidence and compute hashes
        evidence = build_forensic_evidence(
            method=payload.method,
            url=payload.url,
            request_headers=payload.headers,
            request_body=payload.body,
            response_status=resp.status_code,
            response_headers=resp_headers,
            response_body=resp_body
        )

        return HttpTestResponse(
            status_code=resp.status_code,
            headers=resp_headers,
            body=resp_body,
            duration_ms=duration_ms,
            raw_request=evidence["raw_request"],
            raw_response=evidence["raw_response"],
            request_hash_sha256=evidence["request_hash_sha256"],
            response_hash_sha256=evidence["response_hash_sha256"],
            reproduction_curl=evidence["reproduction_curl"]
        )

