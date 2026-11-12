"""Unit tests for the specialized penetration testing agents."""

import httpx
import pytest
from agents.authorization.authz_agent import AuthorizationAgent
from agents.planner.planner_agent import ProjectPlanningAgent
from agents.recon.recon_agent import ReconnaissanceAgent
from agents.reporting.reporting_agent import ReportingAgent
from agents.validation.validation_agent import ValidationAgent
from agents.vulnerability.vuln_agent import VulnerabilityAgent
from agents.wstg.wstg_agent import WSTGAssessmentAgent
from database.models.discovery import Endpoint
from services.orchestrator.state import PentestWorkflowState


@pytest.mark.asyncio
async def test_project_planning_agent(db_session, test_project):
    """Verify AGT-01 initializes WSTG instances and transitions phase to RECON."""
    agent = ProjectPlanningAgent(db_session)
    state = PentestWorkflowState(
        project_id=test_project.id,
        current_phase="PLANNING",
        approved_scope={"target_domains": test_project.target_domains}
    )

    updated = await agent.run(state)
    assert updated.current_phase == "RECON"
    assert len(updated.wstg_matrix_state) > 0


@pytest.mark.asyncio
async def test_reconnaissance_agent(db_session, test_project):
    """Verify AGT-03/04 maps subdomains and endpoints from approved scope."""
    # Seed an endpoint in database for project
    ep = Endpoint(
        project_id=test_project.id,
        fqdn="api.target.com",
        url_path="/v1/users",
        http_method="GET",
        parameter_schema={"query": ["id"]},
        auth_required=True
    )
    db_session.add(ep)
    await db_session.commit()

    agent = ReconnaissanceAgent(db_session)
    state = PentestWorkflowState(
        project_id=test_project.id,
        current_phase="RECON",
        approved_scope={"target_domains": test_project.target_domains}
    )

    updated = await agent.run(state)
    assert updated.current_phase == "WSTG_PLANNING"
    assert len(updated.discovered_subdomains) >= 1
    assert len(updated.endpoints_inventory) >= 1


@pytest.mark.asyncio
async def test_wstg_assessment_agent(db_session, test_project):
    """Verify AGT-05 dispatches real WSTG runners cleanly and tracks coverage metrics."""
    from sqlalchemy import select
    from database.models.agent import AgentToolCall
    from database.models.wstg import TestExecution, WSTGTestInstance

    # First initialize WSTG instances using planning agent
    planning_agent = ProjectPlanningAgent(db_session)
    state = PentestWorkflowState(
        project_id=test_project.id,
        current_phase="PLANNING",
        approved_scope={"target_domains": test_project.target_domains}
    )
    state = await planning_agent.run(state)

    transport = httpx.MockTransport(
        lambda req: httpx.Response(200, headers={"Content-Type": "text/html"}, text="<html>ok</html>")
    )
    agent = WSTGAssessmentAgent(db_session, http_transport=transport)
    state.discovered_subdomains = ["target.com"]
    updated = await agent.run(state)
    assert updated.current_phase == "ACTIVE_ASSESSMENT"
    assert len(updated.candidate_findings) >= 1
    assert not any("Execution failed" in entry.get("message", "") for entry in updated.execution_logs)

    execs = (await db_session.execute(select(TestExecution).where(TestExecution.project_id == test_project.id))).scalars().all()
    assert len(execs) >= 1

    tc_stmt = select(AgentToolCall).where(
        AgentToolCall.tool_name == "wstg_runner"
    )
    tc = (await db_session.execute(tc_stmt)).scalars().first()
    assert tc is not None and (tc.output_result or {}).get("executed_probes_count", 0) > 0

    executed_instances = (await db_session.execute(
        select(WSTGTestInstance).where(
            WSTGTestInstance.project_id == test_project.id,
            WSTGTestInstance.status.in_(["Passed", "Failed", "Needs Manual Review"])
        )
    )).scalars().all()
    assert len(executed_instances) >= 1


@pytest.mark.asyncio
async def test_wstg_assessment_agent_http_target_excludes_hsts(db_session, test_project):
    """Verify plain HTTP targets do not emit HSTS missing-header false positives."""
    planning_agent = ProjectPlanningAgent(db_session)
    state = PentestWorkflowState(
        project_id=test_project.id,
        current_phase="PLANNING",
        approved_scope={"target_domains": test_project.target_domains},
        target_base_url="http://target.com",
    )
    state = await planning_agent.run(state)

    transport = httpx.MockTransport(
        lambda req: httpx.Response(200, headers={"Content-Type": "text/html"}, text="<html>ok</html>")
    )
    agent = WSTGAssessmentAgent(db_session, http_transport=transport)
    state.discovered_subdomains = ["target.com"]
    updated = await agent.run(state)
    assert len(updated.candidate_findings) >= 1
    header_finding = updated.candidate_findings[0]
    assert "HSTS" not in header_finding["title"]
    assert "Strict-Transport-Security" not in header_finding["description"]
    assert header_finding["wstg_id"] != "WSTG-CONF-07"


@pytest.mark.asyncio
async def test_vulnerability_agent(db_session, test_project):
    """Verify AGT-09 dispatches scoped tool scans and captures genuine candidate detections."""
    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/debug/config":
            return httpx.Response(200, json={"jwt_secret": "exposed_test_secret_123"})
        return httpx.Response(404, text="Not Found")

    agent = VulnerabilityAgent(db_session, http_transport=httpx.MockTransport(_handler))
    state = PentestWorkflowState(
        project_id=test_project.id,
        current_phase="ACTIVE_ASSESSMENT",
        approved_scope={"target_domains": test_project.target_domains},
        discovered_subdomains=["target.com"]
    )

    updated = await agent.run(state)
    assert updated.current_phase == "VALIDATION"
    assert any(c.get("cwe_id") == "CWE-200" for c in updated.candidate_findings)


@pytest.mark.asyncio
async def test_authorization_agent(db_session, test_project):
    """Verify AGT-07 evaluates multi-tenant authorization boundaries and detects IDOR empirically."""
    def _authz_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"id": 1002, "email": "alice@target.com", "api_key": "ak_live_test_secret"},
        )

    agent = AuthorizationAgent(db_session, http_transport=httpx.MockTransport(_authz_handler))
    state = PentestWorkflowState(
        project_id=test_project.id,
        current_phase="ACTIVE_ASSESSMENT",
        approved_scope={"target_domains": test_project.target_domains},
        discovered_subdomains=["target.com"],
        endpoints_inventory=[{
            "url": "https://target.com/api/v1/users/1002/profile",
            "http_method": "GET"
        }]
    )

    updated = await agent.run(state)
    assert any("IDOR" in f.get("title", "") for f in updated.candidate_findings)


@pytest.mark.asyncio
async def test_validation_and_false_positive_agent(db_session, test_project):
    """Verify AGT-11/12 confirms genuine vulnerabilities with authentic HTTP evidence and refutes false positives."""
    from services.evidence_engine.finding_service import FindingService

    transport = httpx.MockTransport(
        lambda req: httpx.Response(500, text="SQLite3 OperationalError: near syntax error")
    )
    agent = ValidationAgent(db_session, http_transport=transport)
    state = PentestWorkflowState(
        project_id=test_project.id,
        current_phase="VALIDATION",
        approved_scope={"target_domains": test_project.target_domains},
        candidate_findings=[
            {
                "title": "SQL Injection in Login Parameter",
                "severity": "Critical",
                "cwe_id": "CWE-89",
                "wstg_id": "WSTG-INPV-05",
                "matched_at": "https://target.com/api/login"
            }
        ]
    )

    updated = await agent.run(state)
    assert updated.current_phase == "REPORTING"
    assert len(updated.confirmed_findings) == 1
    assert updated.confirmed_findings[0]["title"] == "SQL Injection in Login Parameter"

    finding = await FindingService(db_session).get_finding(updated.confirmed_findings[0]["id"], test_project.id)
    assert len(finding.evidence) == 1
    assert "[Verified Anomaly]" not in finding.evidence[0].raw_response
    assert finding.reproductions[0].response_status_code == 500


@pytest.mark.asyncio
async def test_validation_agent_handles_is_false_positive_false_json(db_session, test_project):
    """Verify JSON containing {\"is_false_positive\": false, \"is_valid\": true} is confirmed, not refuted."""
    from agents.llm.provider import MockLLMProvider

    mock_llm = MockLLMProvider()
    mock_llm.register_response(
        "SQL Injection Check",
        '{"is_false_positive": false, "is_valid": true, "confidence": "Confirmed"}'
    )
    transport = httpx.MockTransport(
        lambda req: httpx.Response(500, text="SQLite3 OperationalError")
    )
    agent = ValidationAgent(db_session, llm_provider=mock_llm, http_transport=transport)
    state = PentestWorkflowState(
        project_id=test_project.id,
        current_phase="VALIDATION",
        approved_scope={"target_domains": test_project.target_domains},
        candidate_findings=[
            {
                "title": "SQL Injection Check",
                "severity": "Critical",
                "cwe_id": "CWE-89",
                "wstg_id": "WSTG-INPV-05",
                "matched_at": "https://target.com/products?search=test"
            }
        ]
    )

    updated = await agent.run(state)
    assert len(updated.confirmed_findings) == 1
    assert len(updated.false_positives) == 0


@pytest.mark.asyncio
async def test_reporting_agent(db_session, test_project):
    """Verify AGT-15 compiles PTES deliverables and finalizes workflow."""
    agent = ReportingAgent(db_session)
    state = PentestWorkflowState(
        project_id=test_project.id,
        current_phase="REPORTING",
        approved_scope={"target_domains": test_project.target_domains},
        confirmed_findings=[
            {
                "id": "mock_id",
                "title": "SQL Injection in Login Parameter",
                "severity": "Critical",
                "status": "Confirmed"
            }
        ]
    )

    updated = await agent.run(state)
    assert updated.current_phase == "COMPLETED"
    assert updated.status == "COMPLETED"
