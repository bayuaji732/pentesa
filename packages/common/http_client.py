"""
Scope-enforced HTTP client utilities with bounded redirect evaluation,
per-hop scope checking, credential stripping, and cryptographic audit logging.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.project import Project
from database.models.scope import ScopeRule
from packages.common.exceptions import ScopeViolationError
from services.scope_engine.service import scope_service

logger = logging.getLogger(__name__)

MAX_REDIRECT_HOPS = 5


async def safe_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    project: Optional[Project] = None,
    project_id: Optional[uuid.UUID] = None,
    session: Optional[AsyncSession] = None,
    rules: Optional[List[ScopeRule]] = None,
    headers: Optional[Dict[str, str]] = None,
    content: Optional[bytes] = None,
    follow_redirects: bool = True,
    max_redirects: int = MAX_REDIRECT_HOPS,
    resolve_dns: bool = True,
    user_id: Optional[uuid.UUID] = None,
    ip_address: Optional[str] = None,
) -> Tuple[httpx.Response, Optional[str]]:
    """
    Execute an HTTP request adhering to SEC-RED-01:
    - Bounded manual redirect loop (max 5 hops by default)
    - Per-hop scope validation including DNS resolution and anti-rebinding
    - Stripping of sensitive Authorization and Cookie headers across host boundaries
    - Fail-closed stoppage on out-of-scope redirect targets returning the 3xx response
    - Cryptographically chained audit logging for blocked redirect attempts

    Returns:
        Tuple of (response, redirect_note) where redirect_note is None or a string explanation.
    """
    # 1. Resolve project and rules if not pre-supplied
    if project is None and project_id is not None and session is not None:
        p_res = await session.execute(select(Project).where(Project.id == project_id))
        project = p_res.scalar_one_or_none()

    if rules is None and project is not None and session is not None:
        r_res = await session.execute(select(ScopeRule).where(ScopeRule.project_id == project.id))
        rules = list(r_res.scalars().all())

    # 2. Initial scope check on root URL
    if project is not None:
        scope_res = scope_service.check_target(
            project=project,
            target_url=url,
            rules=rules or [],
            resolve_dns=resolve_dns,
        )
        if not scope_res.is_in_scope:
            raise ScopeViolationError(
                f"HTTP test target '{url}' blocked by scope engine: {scope_res.reason}"
            )

    current_url = str(url)
    current_method = method.upper()
    current_headers = dict(headers or {})
    current_content = content

    # 3. If redirect following is disabled, make a single non-following request
    if not follow_redirects:
        resp = await client.request(
            method=current_method,
            url=current_url,
            headers=current_headers,
            content=current_content,
            follow_redirects=False,
        )
        return resp, None

    # 4. Bounded redirect evaluation loop
    redirect_note: Optional[str] = None
    last_resp: Optional[httpx.Response] = None

    for hop in range(max_redirects + 1):
        resp = await client.request(
            method=current_method,
            url=current_url,
            headers=current_headers,
            content=current_content,
            follow_redirects=False,
        )
        last_resp = resp

        # Check if response is a redirect (301, 302, 303, 307, 308)
        if not resp.is_redirect:
            return resp, redirect_note

        if hop >= max_redirects:
            redirect_note = f"redirect blocked: maximum redirect hops ({max_redirects}) exceeded"
            logger.warning(f"Max redirects ({max_redirects}) exceeded for {url}")
            return resp, redirect_note

        location = resp.headers.get("location")
        if not location:
            # Redirect response without Location header
            return resp, redirect_note

        # Resolve next hop URL (handles relative paths, protocol-relative, and full URLs)
        next_url = str(httpx.URL(current_url).join(location))

        # Check for authority change (host, port, or scheme)
        orig_parsed = httpx.URL(current_url)
        next_parsed = httpx.URL(next_url)
        is_cross_host = (
            orig_parsed.host != next_parsed.host
            or orig_parsed.port != next_parsed.port
            or orig_parsed.scheme != next_parsed.scheme
        )

        if is_cross_host:
            # Strip credentials and session cookies when leaving the origin
            keys_to_strip = [k for k in current_headers.keys() if k.lower() in ("authorization", "cookie")]
            for k in keys_to_strip:
                del current_headers[k]

        # Re-evaluate scope on the next hop target
        if project is not None:
            hop_scope = scope_service.check_target(
                project=project,
                target_url=next_url,
                rules=rules or [],
                resolve_dns=resolve_dns,
            )
            if not hop_scope.is_in_scope:
                redirect_note = f"redirect blocked: out of scope ({hop_scope.reason or 'target host not permitted'})"
                logger.warning(
                    f"[SEC-RED-01] Redirect to '{next_url}' blocked at hop {hop + 1}: {hop_scope.reason}"
                )

                if session is not None:
                    try:
                        from packages.common.audit_writer import record_audit_log

                        await record_audit_log(
                            session=session,
                            action="REDIRECT_BLOCKED_OUT_OF_SCOPE",
                            resource_type="HTTP_REDIRECT",
                            resource_id=next_url,
                            details={
                                "source_url": current_url,
                                "target_url": next_url,
                                "status_code": resp.status_code,
                                "hop_number": hop + 1,
                                "reason": hop_scope.reason or "Target host is out of scope",
                                "headers_stripped": is_cross_host,
                            },
                            project_id=project.id,
                            user_id=user_id,
                            ip_address=ip_address,
                        )
                    except Exception as log_err:
                        logger.error(f"Failed to record redirect audit log: {log_err}")

                return resp, redirect_note

        # Prepare for next hop
        if resp.status_code == 303 or (resp.status_code in (301, 302) and current_method == "POST"):
            current_method = "GET"
            current_content = None

        current_url = next_url

    return last_resp or resp, redirect_note
