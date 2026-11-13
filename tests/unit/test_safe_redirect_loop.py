"""Regression and unit tests for FIX-01 (SEC-RED-01): Bounded safe redirect loops."""

import uuid
import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.audit import AuditLog
from database.models.project import Project
from database.models.scope import ScopeRule
from packages.common.http_client import MAX_REDIRECT_HOPS, safe_request


@pytest.fixture(autouse=True)
async def setup_target_domain_rule(db_session: AsyncSession, test_project: Project):
    """Ensure apex domain target.com is in scope alongside *.target.com."""
    r_apex = ScopeRule(
        id=uuid.uuid4(),
        project_id=test_project.id,
        rule_type="DOMAIN",
        target_type="IN_SCOPE",
        pattern="target.com",
        protocol="https,http",
        port_range="80,443"
    )
    db_session.add(r_apex)
    await db_session.commit()
    return r_apex


@pytest.mark.asyncio
async def test_redirect_to_out_of_scope_blocked_and_audit_logged(db_session: AsyncSession, test_project: Project):
    """Verify that an HTTP redirect to an out-of-scope target stops at the 3xx response and logs audit entry."""
    out_of_scope_called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal out_of_scope_called
        if request.url.path == "/start-redirect":
            return httpx.Response(
                302,
                headers={"Location": "https://malicious-evil.com/canary-trap"},
                text="Redirecting to evil"
            )
        elif "malicious-evil.com" in str(request.url):
            out_of_scope_called = True
            return httpx.Response(200, text="Evil payload reached!")
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(transport=transport) as client:
        resp, note = await safe_request(
            client=client,
            method="GET",
            url="https://target.com/start-redirect",
            project=test_project,
            session=db_session,
            follow_redirects=True,
            resolve_dns=False,
        )

    # 1. Out of scope destination was NEVER called
    assert not out_of_scope_called, "BREACH: Out-of-scope target was called!"

    # 2. Response stopped at 302 with note
    assert resp.status_code == 302
    assert note is not None
    assert "redirect blocked: out of scope" in note

    # 3. Audit log entry was recorded
    stmt = (
        select(AuditLog)
        .where(
            AuditLog.project_id == test_project.id,
            AuditLog.action == "REDIRECT_BLOCKED_OUT_OF_SCOPE"
        )
    )
    result = await db_session.execute(stmt)
    entry = result.scalar_one_or_none()
    assert entry is not None, "Audit log REDIRECT_BLOCKED_OUT_OF_SCOPE was not recorded!"
    assert "malicious-evil.com" in entry.resource_id
    assert entry.details["status_code"] == 302


@pytest.mark.asyncio
async def test_in_scope_redirect_followed_successfully(db_session: AsyncSession, test_project: Project):
    """Verify in-scope redirects are followed up to final destination."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/step1":
            return httpx.Response(302, headers={"Location": "/step2"})
        elif request.url.path == "/step2":
            return httpx.Response(301, headers={"Location": "/final"})
        elif request.url.path == "/final":
            return httpx.Response(200, text="In-scope final landing page")
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(transport=transport) as client:
        resp, note = await safe_request(
            client=client,
            method="GET",
            url="https://target.com/step1",
            project=test_project,
            session=db_session,
            follow_redirects=True,
            resolve_dns=False,
        )

    assert resp.status_code == 200
    assert resp.text == "In-scope final landing page"
    assert note is None


@pytest.mark.asyncio
async def test_cross_host_redirect_strips_auth_and_cookie_headers(db_session: AsyncSession, test_project: Project):
    """Verify cross-host redirects strip Authorization and Cookie headers."""
    # Add subdomain to scope so redirect is allowed within scope
    rule = ScopeRule(
        id=uuid.uuid4(),
        project_id=test_project.id,
        rule_type="DOMAIN",
        target_type="IN_SCOPE",
        pattern="api.target.com",
        protocol="https,http",
        port_range="80,443"
    )
    db_session.add(rule)
    await db_session.commit()

    captured_headers: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "target.com":
            return httpx.Response(302, headers={"Location": "https://api.target.com/data"})
        elif request.url.host == "api.target.com":
            captured_headers.update(dict(request.headers))
            return httpx.Response(200, text="API data")
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(transport=transport) as client:
        resp, note = await safe_request(
            client=client,
            method="GET",
            url="https://target.com/login-redirect",
            project=test_project,
            session=db_session,
            headers={
                "Authorization": "Bearer sensitive-token-12345",
                "Cookie": "session=sensitive-session-cookie",
                "X-Custom-Header": "KeepThis"
            },
            follow_redirects=True,
            resolve_dns=False,
        )

    assert resp.status_code == 200
    assert "authorization" not in captured_headers
    assert "cookie" not in captured_headers
    assert captured_headers.get("x-custom-header") == "KeepThis"


@pytest.mark.asyncio
async def test_max_redirects_exceeded_bounded_stop(db_session: AsyncSession, test_project: Project):
    """Verify redirect loop is bounded at MAX_REDIRECT_HOPS (5)."""
    hops_called = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal hops_called
        hops_called += 1
        return httpx.Response(302, headers={"Location": f"/loop-{hops_called}"})

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(transport=transport) as client:
        resp, note = await safe_request(
            client=client,
            method="GET",
            url="https://target.com/loop-0",
            project=test_project,
            session=db_session,
            follow_redirects=True,
            max_redirects=MAX_REDIRECT_HOPS,
            resolve_dns=False,
        )

    assert resp.status_code == 302
    assert note is not None
    assert f"maximum redirect hops ({MAX_REDIRECT_HOPS}) exceeded" in note
    assert hops_called == MAX_REDIRECT_HOPS + 1
