"""Regression tests for P1-AGENT-01: ValidationAgent empirical evidence gate and per-class signatures."""

import uuid
from datetime import datetime, timedelta, timezone
import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from agents.validation.validation_agent import ValidationAgent
from database.models.project import Project
from database.models.scope import ScopeRule
from database.models.user import User
from database.models.wstg import WSTGTestCatalog, WSTGTestInstance
from services.orchestrator.state import PentestWorkflowState


class FakeMockLLMProvider:
    """Mock LLM Provider that blindly returns is_valid=True (hallucination simulation)."""
    def __init__(self, response_text: str = '{"is_valid": true, "is_false_positive": false, "reason": "Looks vulnerable"}'):
        self.response_text = response_text
        self.call_count = 0

    async def generate(self, prompt: str, system_prompt: str = "", json_mode: bool = False, **kwargs):
        self.call_count += 1
        class Res:
            content = self.response_text
            model = "mock-model"
            prompt_tokens = 10
            completion_tokens = 10
            total_tokens = 20
        return Res()


@pytest.mark.asyncio
async def test_validation_agent_refuses_404_hallucination(db_session: AsyncSession, admin_user: User):
    """P5-TC-HALLUC-01: Verify 404 response on /admin/super-exec NEVER promotes, even if LLM claims valid."""
    now = datetime.now(timezone.utc)
    project = Project(
        id=uuid.uuid4(),
        name="Scope Test Project",
        status="ACTIVE",
        target_domains=["target.lab"],
        authorization_start=now - timedelta(days=1),
        authorization_end=now + timedelta(days=10),
        created_by=admin_user.id
    )
    db_session.add(project)
    await db_session.flush()

    scope = ScopeRule(
        project_id=project.id,
        rule_type="EXACT_DOMAIN",
        target_type="IN_SCOPE",
        pattern="target.lab",
        protocol="http,https"
    )
    db_session.add(scope)
    await db_session.commit()

    candidate = {
        "title": "Remote Code Execution via Super Exec",
        "matched_at": "http://target.lab/admin/super-exec",
        "cwe_id": "CWE-78",
        "severity": "Critical",
        "description": "Hallucinated endpoint should not promote",
        "raw_request": "GET /admin/super-exec HTTP/1.1\r\nHost: target.lab\r\n\r\n",
        "raw_response": "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found"
    }

    state = PentestWorkflowState(
        project_id=project.id,
        user_id=admin_user.id,
        scan_profile="ACTIVE_FULL",
        target_domains=["target.lab"],
        candidate_findings=[candidate],
        confirmed_findings=[],
        false_positives=[]
    )

    # Wire 404 transport
    transport_404 = httpx.MockTransport(
        lambda req: httpx.Response(404, text="404 Page Not Found")
    )

    # Blindly trusting LLM says valid
    agent = ValidationAgent(
        session=db_session,
        llm_provider=FakeMockLLMProvider('{"is_valid": true, "is_false_positive": false}'),
        http_transport=transport_404
    )

    out_state = await agent.run(state)

    # Invariant: 404 must NEVER promote to confirmed findings
    assert len(out_state.confirmed_findings) == 0, "404 endpoint was hallucinated into confirmed findings!"
    assert len(out_state.false_positives) == 1, "404 endpoint must be recorded as a refuted false positive"
    assert out_state.false_positives[0]["title"] == candidate["title"]


@pytest.mark.asyncio
async def test_validation_agent_confirms_sqli_http_500_with_db_error(db_session: AsyncSession, admin_user: User):
    """Phase 3 Regression: SQLi /sqli/search returning HTTP 500 with SQL syntax error MUST confirm."""
    now = datetime.now(timezone.utc)
    project = Project(
        id=uuid.uuid4(),
        name="SQLi Test Project",
        status="ACTIVE",
        target_domains=["target.lab"],
        authorization_start=now - timedelta(days=1),
        authorization_end=now + timedelta(days=10),
        created_by=admin_user.id
    )
    db_session.add(project)
    await db_session.flush()

    scope = ScopeRule(
        project_id=project.id,
        rule_type="EXACT_DOMAIN",
        target_type="IN_SCOPE",
        pattern="target.lab",
        protocol="http,https"
    )
    db_session.add(scope)
    await db_session.commit()

    candidate = {
        "title": "SQL Injection in Search Query",
        "matched_at": "http://target.lab/sqli/search?q='",
        "cwe_id": "CWE-89",
        "wstg_id": "WSTG-INPV-05",
        "severity": "High",
        "description": "SQL injection triggers database syntax error on 500",
        "raw_request": "GET /sqli/search?q=' HTTP/1.1\r\nHost: target.lab\r\n\r\n",
        "raw_response": "HTTP/1.1 500 Internal Server Error\r\n\r\nsqlite3.OperationalError: near syntax error"
    }

    state = PentestWorkflowState(
        project_id=project.id,
        user_id=admin_user.id,
        scan_profile="ACTIVE_FULL",
        target_domains=["target.lab"],
        candidate_findings=[candidate],
        confirmed_findings=[],
        false_positives=[]
    )

    # Transport returns HTTP 500 with SQL error signature
    transport_500_sqli = httpx.MockTransport(
        lambda req: httpx.Response(500, text="Internal Server Error: psycopg2.errors.SyntaxError: syntax error at or near 'LIMIT'")
    )

    agent = ValidationAgent(
        session=db_session,
        llm_provider=FakeMockLLMProvider('{"is_valid": true, "is_false_positive": false}'),
        http_transport=transport_500_sqli
    )

    out_state = await agent.run(state)

    # Invariant: SQLi with database error on HTTP 500 MUST confirm
    assert len(out_state.confirmed_findings) == 1, "SQLi with valid DB error signature on 500 failed to confirm!"
    assert out_state.confirmed_findings[0]["title"] == candidate["title"]
    assert len(out_state.false_positives) == 0


@pytest.mark.asyncio
async def test_validation_agent_demotes_when_llm_classifies_fp_despite_status(db_session: AsyncSession, admin_user: User):
    """Verify LLM verdict may DEMOTE a candidate even if HTTP 200 is received."""
    now = datetime.now(timezone.utc)
    project = Project(
        id=uuid.uuid4(),
        name="FP Demote Test Project",
        status="ACTIVE",
        target_domains=["target.lab"],
        authorization_start=now - timedelta(days=1),
        authorization_end=now + timedelta(days=10),
        created_by=admin_user.id
    )
    db_session.add(project)
    await db_session.flush()

    scope = ScopeRule(
        project_id=project.id,
        rule_type="EXACT_DOMAIN",
        target_type="IN_SCOPE",
        pattern="target.lab",
        protocol="http,https"
    )
    db_session.add(scope)
    await db_session.commit()

    candidate = {
        "title": "Reflected XSS in Search",
        "matched_at": "http://target.lab/search?q=hello",
        "cwe_id": "CWE-79",
        "severity": "Medium",
        "description": "Benign search reflection",
        "raw_request": "GET /search?q=hello HTTP/1.1\r\nHost: target.lab\r\n\r\n",
        "raw_response": "HTTP/1.1 200 OK\r\n\r\nSearch results for hello"
    }

    state = PentestWorkflowState(
        project_id=project.id,
        user_id=admin_user.id,
        scan_profile="ACTIVE_FULL",
        target_domains=["target.lab"],
        candidate_findings=[candidate],
        confirmed_findings=[],
        false_positives=[]
    )

    transport_200 = httpx.MockTransport(
        lambda req: httpx.Response(200, text="Search results for hello")
    )

    # LLM correctly classifies this as benign false positive
    agent = ValidationAgent(
        session=db_session,
        llm_provider=FakeMockLLMProvider('{"is_valid": false, "is_false_positive": true, "reason": "No executable script reflection"}'),
        http_transport=transport_200
    )

    out_state = await agent.run(state)

    # Invariant: LLM demotion is respected
    assert len(out_state.confirmed_findings) == 0
    assert len(out_state.false_positives) == 1


@pytest.mark.asyncio
async def test_validation_agent_confirms_cmdi_shell_syntax_error(db_session: AsyncSession, admin_user: User):
    """A3 Refinement: CMDi on /cmd/ping returning shell error markers (/bin/sh: syntax error) MUST confirm."""
    now = datetime.now(timezone.utc)
    project = Project(
        id=uuid.uuid4(),
        name="CMDi Test Project",
        status="ACTIVE",
        target_domains=["target.lab"],
        authorization_start=now - timedelta(days=1),
        authorization_end=now + timedelta(days=10),
        created_by=admin_user.id
    )
    db_session.add(project)
    await db_session.flush()

    scope = ScopeRule(
        project_id=project.id,
        rule_type="EXACT_DOMAIN",
        target_type="IN_SCOPE",
        pattern="target.lab",
        protocol="http,https"
    )
    db_session.add(scope)
    await db_session.commit()

    candidate = {
        "title": "Command Injection in 'host' Parameter (/cmd/ping)",
        "matched_at": "http://target.lab/cmd/ping?host=%27%29%29",
        "cwe_id": "CWE-78",
        "wstg_id": "WSTG-INPV-12",
        "severity": "Critical",
        "description": "Shell execution error demonstrates command injection",
        "raw_request": "GET /cmd/ping?host=%27%29%29 HTTP/1.1\r\nHost: target.lab\r\n\r\n",
        "raw_response": "HTTP/1.1 200 OK\r\n\r\n/bin/sh: 1: Syntax error: Unterminated quoted string\n"
    }

    state = PentestWorkflowState(
        project_id=project.id,
        user_id=admin_user.id,
        scan_profile="ACTIVE_FULL",
        target_domains=["target.lab"],
        candidate_findings=[candidate],
        confirmed_findings=[],
        false_positives=[]
    )

    transport_cmdi = httpx.MockTransport(
        lambda req: httpx.Response(200, text="/bin/sh: 1: Syntax error: Unterminated quoted string\n")
    )

    agent = ValidationAgent(
        session=db_session,
        llm_provider=FakeMockLLMProvider('{"is_valid": true, "is_false_positive": false}'),
        http_transport=transport_cmdi
    )

    out_state = await agent.run(state)
    assert len(out_state.confirmed_findings) == 1, "CMDi with shell error markers failed to confirm!"
    assert out_state.confirmed_findings[0]["title"] == candidate["title"]


@pytest.mark.asyncio
async def test_validation_agent_confirms_ssrf_with_outbound_error_evidence(db_session: AsyncSession, admin_user: User):
    """A3 Refinement: SSRF on /ssrf/fetch returning 502 with outbound fetch error evidence MUST confirm."""
    now = datetime.now(timezone.utc)
    project = Project(
        id=uuid.uuid4(),
        name="SSRF Test Project",
        status="ACTIVE",
        target_domains=["target.lab"],
        authorization_start=now - timedelta(days=1),
        authorization_end=now + timedelta(days=10),
        created_by=admin_user.id
    )
    db_session.add(project)
    await db_session.flush()

    scope = ScopeRule(
        project_id=project.id,
        rule_type="EXACT_DOMAIN",
        target_type="IN_SCOPE",
        pattern="target.lab",
        protocol="http,https"
    )
    db_session.add(scope)
    await db_session.commit()

    candidate = {
        "title": "Server-Side Request Forgery in 'url' Parameter (/ssrf/fetch)",
        "matched_at": "http://target.lab/ssrf/fetch?url=http://127.0.0.1:9099",
        "cwe_id": "CWE-918",
        "wstg_id": "WSTG-INPV-19",
        "severity": "Critical",
        "description": "SSRF outbound prober error",
        "raw_request": "GET /ssrf/fetch?url=http://127.0.0.1:9099 HTTP/1.1\r\nHost: target.lab\r\n\r\n",
        "raw_response": "HTTP/1.1 502 Bad Gateway\r\n\r\n{\"detail\":\"SSRF request failed: connection refused to 127.0.0.1:9099\"}"
    }

    state = PentestWorkflowState(
        project_id=project.id,
        user_id=admin_user.id,
        scan_profile="ACTIVE_FULL",
        target_domains=["target.lab"],
        candidate_findings=[candidate],
        confirmed_findings=[],
        false_positives=[]
    )

    transport_ssrf = httpx.MockTransport(
        lambda req: httpx.Response(502, text='{"detail":"SSRF request failed: connection refused to 127.0.0.1:9099"}')
    )

    agent = ValidationAgent(
        session=db_session,
        llm_provider=FakeMockLLMProvider('{"is_valid": true, "is_false_positive": false}'),
        http_transport=transport_ssrf
    )

    out_state = await agent.run(state)
    assert len(out_state.confirmed_findings) == 1, "SSRF with outbound error evidence on 502 failed to confirm!"


@pytest.mark.asyncio
async def test_validation_agent_rejects_ssrf_bare_502_without_evidence(db_session: AsyncSession, admin_user: User):
    """A3 Refinement: SSRF on bare 502 Bad Gateway without injected evidence MUST NOT promote."""
    now = datetime.now(timezone.utc)
    project = Project(
        id=uuid.uuid4(),
        name="SSRF Bare 502 Project",
        status="ACTIVE",
        target_domains=["target.lab"],
        authorization_start=now - timedelta(days=1),
        authorization_end=now + timedelta(days=10),
        created_by=admin_user.id
    )
    db_session.add(project)
    await db_session.flush()

    scope = ScopeRule(
        project_id=project.id,
        rule_type="EXACT_DOMAIN",
        target_type="IN_SCOPE",
        pattern="target.lab",
        protocol="http,https"
    )
    db_session.add(scope)
    await db_session.commit()

    candidate = {
        "title": "Server-Side Request Forgery in 'url' Parameter",
        "matched_at": "http://target.lab/ssrf/fetch?url=http://example.com",
        "cwe_id": "CWE-918",
        "wstg_id": "WSTG-INPV-19",
        "severity": "Critical",
        "description": "SSRF bare 502 gateway error",
        "raw_request": "GET /ssrf/fetch HTTP/1.1\r\nHost: target.lab\r\n\r\n",
        "raw_response": "HTTP/1.1 502 Bad Gateway\r\n\r\n<html><body>502 Bad Gateway</body></html>"
    }

    state = PentestWorkflowState(
        project_id=project.id,
        user_id=admin_user.id,
        scan_profile="ACTIVE_FULL",
        target_domains=["target.lab"],
        candidate_findings=[candidate],
        confirmed_findings=[],
        false_positives=[]
    )

    transport_bare_502 = httpx.MockTransport(
        lambda req: httpx.Response(502, text="<html><body>502 Bad Gateway</body></html>")
    )

    agent = ValidationAgent(
        session=db_session,
        llm_provider=FakeMockLLMProvider('{"is_valid": true, "is_false_positive": false}'),
        http_transport=transport_bare_502
    )

    out_state = await agent.run(state)
    assert len(out_state.confirmed_findings) == 0, "Bare 502 without evidence must NOT promote!"
    assert len(out_state.false_positives) == 1


@pytest.mark.asyncio
async def test_validation_agent_rejects_headers_on_404(db_session: AsyncSession, admin_user: User):
    """A3 Refinement: Missing security headers on HTTP 404 (unmapped route) MUST be refuted."""
    now = datetime.now(timezone.utc)
    project = Project(
        id=uuid.uuid4(),
        name="Headers 404 Project",
        status="ACTIVE",
        target_domains=["target.lab"],
        authorization_start=now - timedelta(days=1),
        authorization_end=now + timedelta(days=10),
        created_by=admin_user.id
    )
    db_session.add(project)
    await db_session.flush()

    scope = ScopeRule(
        project_id=project.id,
        rule_type="EXACT_DOMAIN",
        target_type="IN_SCOPE",
        pattern="target.lab",
        protocol="http,https"
    )
    db_session.add(scope)
    await db_session.commit()

    candidate = {
        "title": "Missing Security Headers (CSP, XFO, XCTO)",
        "matched_at": "http://target.lab/",
        "cwe_id": "CWE-693",
        "wstg_id": "WSTG-CLNT-09",
        "severity": "Low",
        "description": "Missing defensive security headers",
        "raw_request": "GET / HTTP/1.1\r\nHost: target.lab\r\n\r\n",
        "raw_response": "HTTP/1.1 404 Not Found\r\n\r\n{\"detail\":\"Not Found\"}"
    }

    state = PentestWorkflowState(
        project_id=project.id,
        user_id=admin_user.id,
        scan_profile="ACTIVE_FULL",
        target_domains=["target.lab"],
        candidate_findings=[candidate],
        confirmed_findings=[],
        false_positives=[]
    )

    transport_404 = httpx.MockTransport(
        lambda req: httpx.Response(404, text='{"detail":"Not Found"}')
    )

    agent = ValidationAgent(
        session=db_session,
        llm_provider=FakeMockLLMProvider('{"is_valid": true, "is_false_positive": false}'),
        http_transport=transport_404
    )

    out_state = await agent.run(state)
    assert len(out_state.confirmed_findings) == 0, "Missing security headers on 404 must NOT promote!"
    assert len(out_state.false_positives) == 1
    assert "404" in out_state.false_positives[0]["justification"]


@pytest.mark.asyncio
async def test_validation_agent_confirms_cmdi_shell_error_on_500(db_session: AsyncSession, admin_user: User):
    """A3 Refinement: CMDi returning HTTP 500 with shell error markers MUST promote."""
    now = datetime.now(timezone.utc)
    project = Project(
        id=uuid.uuid4(),
        name="CMDi 500 Project",
        status="ACTIVE",
        target_domains=["target.lab"],
        authorization_start=now - timedelta(days=1),
        authorization_end=now + timedelta(days=10),
        created_by=admin_user.id
    )
    db_session.add(project)
    await db_session.flush()

    scope = ScopeRule(
        project_id=project.id,
        rule_type="EXACT_DOMAIN",
        target_type="IN_SCOPE",
        pattern="target.lab",
        protocol="http,https"
    )
    db_session.add(scope)
    await db_session.commit()

    candidate = {
        "title": "Command Injection in 'host' Parameter (/cmd/ping)",
        "matched_at": "http://target.lab/cmd/ping?host=%27%29%29",
        "cwe_id": "CWE-78",
        "wstg_id": "WSTG-INPV-12",
        "severity": "Critical",
        "description": "Shell execution error demonstrates command injection",
        "raw_request": "GET /cmd/ping?host=%27%29%29 HTTP/1.1\r\nHost: target.lab\r\n\r\n",
        "raw_response": "HTTP/1.1 500 Internal Server Error\r\n\r\n/bin/sh: 1: Syntax error: Unterminated quoted string\n"
    }

    state = PentestWorkflowState(
        project_id=project.id,
        user_id=admin_user.id,
        scan_profile="ACTIVE_FULL",
        target_domains=["target.lab"],
        candidate_findings=[candidate],
        confirmed_findings=[],
        false_positives=[]
    )

    transport_cmdi_500 = httpx.MockTransport(
        lambda req: httpx.Response(500, text="/bin/sh: 1: Syntax error: Unterminated quoted string\n")
    )

    agent = ValidationAgent(
        session=db_session,
        llm_provider=FakeMockLLMProvider('{"is_valid": true, "is_false_positive": false}'),
        http_transport=transport_cmdi_500
    )

    out_state = await agent.run(state)
    assert len(out_state.confirmed_findings) == 1, "CMDi on HTTP 500 with shell error markers must confirm!"


