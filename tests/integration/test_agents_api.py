"""Integration tests for AI Agents & Workflow REST API endpoints."""

import httpx
import pytest
from sqlalchemy import select
from agents.base import BaseAgent
from database.models.agent import ApprovalRequest
from database.models.audit import AuditLog
from services.execution_engine.runners import BaseTestRunner


@pytest.fixture(autouse=True)
def offline_agent_http_transport():
    """Keep offline test runs deterministic without external DNS/network waits."""
    transport = httpx.MockTransport(
        lambda req: httpx.Response(200, headers={"Content-Type": "text/html"}, text="<html><body>ok</body></html>")
    )
    BaseAgent.default_http_transport = transport
    BaseTestRunner.default_http_transport = transport
    try:
        yield
    finally:
        BaseAgent.default_http_transport = None
        BaseTestRunner.default_http_transport = None


@pytest.mark.asyncio
async def test_workflow_start_and_status_api(client, admin_token, test_project):
    """Verify starting autonomous workflow and querying real-time agent status."""
    start_resp = await client.post(
        f"/api/v1/projects/{test_project.id}/agents/workflow/start",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"auto_approve_medium": True}
    )
    assert start_resp.status_code == 201
    wf_data = start_resp.json()
    assert wf_data["status"] == "COMPLETED"
    assert len(wf_data["active_agents"]) >= 7

    # Query Status API
    status_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/agents/status",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert status_resp.status_code == 200
    status_json = status_resp.json()
    assert status_json["id"] == wf_data["id"]
    assert all(a["prompt_tokens"] > 0 and a["completion_tokens"] > 0 for a in status_json["active_agents"])
    assert status_json["active_agents"][0]["phase"] == "PLANNING"

    # Query Decisions API
    dec_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/agents/decisions",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert dec_resp.status_code == 200
    decisions = dec_resp.json()
    assert len(decisions) >= 7
    assert "thought_trace" in decisions[0]
    assert decisions[0]["agent_id"] is not None
    assert decisions[0]["agent_name"] is not None
    assert decisions[0]["phase"] is not None

    # Query Tool Calls API
    tools_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/agents/tool-calls",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert tools_resp.status_code == 200
    tools = tools_resp.json()
    assert len(tools) >= 6
    assert tools[0]["agent_id"] is not None
    assert tools[0]["tool_name"] is not None


@pytest.mark.asyncio
async def test_workflow_pause_resume_stop_lifecycle_api(client, admin_token, test_project, db_session):
    """Verify pause, resume, and stop controls via API endpoints."""
    # Seed a running workflow
    from database.models.agent import WorkflowExecution
    wf = WorkflowExecution(
        project_id=test_project.id,
        current_phase="ACTIVE_ASSESSMENT",
        status="RUNNING"
    )
    db_session.add(wf)
    await db_session.commit()

    # 1. Pause
    pause_resp = await client.post(
        f"/api/v1/projects/{test_project.id}/agents/workflow/pause",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert pause_resp.status_code == 200
    assert pause_resp.json()["status"] == "PAUSED"

    # 2. Resume
    resume_resp = await client.post(
        f"/api/v1/projects/{test_project.id}/agents/workflow/resume",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resume_resp.status_code == 200
    assert resume_resp.json()["status"] == "RUNNING"

    # 3. Stop
    stop_resp = await client.post(
        f"/api/v1/projects/{test_project.id}/agents/workflow/stop",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert stop_resp.status_code == 200
    assert stop_resp.json()["status"] == "STOPPED"


@pytest.mark.asyncio
async def test_approval_request_workflow_api(client, admin_token, test_project, db_session):
    """Verify listing and approving human-in-the-loop authorization requests."""
    # Seed an approval request
    req = ApprovalRequest(
        project_id=test_project.id,
        agent_id="AGT-10",
        action="High-volume directory fuzzing with wordlist size 10,000",
        target="https://target.com/api/FUZZ",
        risk_level="HIGH",
        status="PENDING"
    )
    db_session.add(req)
    await db_session.commit()
    await db_session.refresh(req)

    # 1. List approvals
    list_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/agents/approvals",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert list_resp.status_code == 200
    approvals = list_resp.json()
    assert len(approvals) >= 1
    assert approvals[0]["id"] == str(req.id)

    # 2. Submit decision
    decide_resp = await client.post(
        f"/api/v1/projects/{test_project.id}/agents/approvals/{req.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "decision": "APPROVE",
            "justification": "Approved during authorized testing change window"
        }
    )
    assert decide_resp.status_code == 200
    assert decide_resp.json()["status"] == "APPROVED"

    # 3. Verify audit log entry
    audit_stmt = select(AuditLog).where(
        AuditLog.resource_id == str(req.id),
        AuditLog.action == "APPROVAL_APPROVED"
    )
    audit = (await db_session.execute(audit_stmt)).scalar_one_or_none()
    assert audit is not None
