"""End-to-End (E2E) integration test executing the complete autonomous penetration testing lifecycle.

Tests the unbroken chain from project initialization to final sealed report delivery:
1. Authentication & Project Onboarding
2. Scope Definition & Validation
3. Attack Surface Discovery (Domains, Endpoints, Technologies)
4. WSTG Assessment Plan & Instance Seeding
5. Security Tool Invocation & Forensic Evidence Ingestion
6. Multi-Agent Autonomous Assessment & Decision Audit
7. Finding Confirmation, Deduplication & One-Click Retest
8. Cryptographic PTES Formal Report Generation & Seal Verification
9. Comprehensive Audit Trail Verification
"""

import datetime
import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.discovery import Technology
from database.models.user import User


@pytest.mark.asyncio
async def test_full_autonomous_pentest_lifecycle_e2e(
    client: AsyncClient,
    admin_token: str,
    admin_user: User,
    db_session: AsyncSession
):
    """Execute complete end-to-end autonomous penetration test workflow."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    now = datetime.datetime.now(datetime.timezone.utc)

    # -------------------------------------------------------------------------
    # 1. Project Creation
    # -------------------------------------------------------------------------
    project_payload = {
        "name": "Global Financial Services Core Portal",
        "description": "Production banking portal and customer API assessment",
        "target_domains": ["api.globalfin.local", "portal.globalfin.local"],
        "allowed_cidrs": ["192.168.10.0/24"],
        "excluded_paths": ["/logout", "/api/v1/auth/reset-totp"],
        "allow_internal_networks": False,
        "authorization_document_ref": "AUTH-DOC-2026-GLOBALFIN-001",
        "authorization_start": (now - datetime.timedelta(days=1)).isoformat(),
        "authorization_end": (now + datetime.timedelta(days=30)).isoformat()
    }
    create_proj_resp = await client.post("/api/v1/projects", json=project_payload, headers=headers)
    assert create_proj_resp.status_code == 201
    project_data = create_proj_resp.json()
    project_id = project_data["id"]

    # -------------------------------------------------------------------------
    # 2. Scope Definition & Verification
    # -------------------------------------------------------------------------
    scope_rule_payload = {
        "rule_type": "EXACT_DOMAIN",
        "target_type": "IN_SCOPE",
        "pattern": "api.globalfin.local",
        "protocol": "https,http",
        "is_critical": True,
        "notes": "Core REST transaction API"
    }
    scope_resp = await client.post(f"/api/v1/projects/{project_id}/scope", json=scope_rule_payload, headers=headers)
    assert scope_resp.status_code == 201

    # Verify Scope Check Engine
    scope_check_resp = await client.post(
        f"/api/v1/projects/{project_id}/scope/check",
        json={"url": "https://api.globalfin.local/api/v1/payments"},
        headers=headers
    )
    assert scope_check_resp.status_code == 200
    assert scope_check_resp.json()["is_in_scope"] is True

    # -------------------------------------------------------------------------
    # 3. Attack Surface Discovery (Endpoints & Technologies)
    # -------------------------------------------------------------------------
    endpoint_payload = {
        "fqdn": "api.globalfin.local",
        "url_path": "/api/v1/accounts/transfers",
        "http_method": "POST",
        "parameter_schema": {"recipient_account": "string", "amount": "number"},
        "auth_required": True
    }
    ep_resp = await client.post(f"/api/v1/projects/{project_id}/endpoints", json=endpoint_payload, headers=headers)
    assert ep_resp.status_code == 201
    endpoint_id = ep_resp.json()["id"]

    tech = Technology(
        id=uuid.uuid4(),
        project_id=uuid.UUID(project_id),
        name="Nginx",
        version="1.24.0",
        category="Web Server",
        confidence=100
    )
    db_session.add(tech)
    await db_session.commit()

    tech_resp = await client.get(f"/api/v1/projects/{project_id}/technologies", headers=headers)
    assert tech_resp.status_code == 200
    assert any(t["name"] == "Nginx" for t in tech_resp.json())

    # -------------------------------------------------------------------------
    # 4. WSTG Assessment Initialization & Coverage Verification
    # -------------------------------------------------------------------------
    plan_resp = await client.get(f"/api/v1/projects/{project_id}/wstg/plan", headers=headers)
    assert plan_resp.status_code == 200
    assert len(plan_resp.json()) == 106

    recalc_resp = await client.post(f"/api/v1/projects/{project_id}/wstg/recalculate", headers=headers)
    assert recalc_resp.status_code == 200
    assert recalc_resp.json()["total_instances"] == 106

    coverage_resp = await client.get(f"/api/v1/projects/{project_id}/wstg/coverage", headers=headers)
    assert coverage_resp.status_code == 200
    assert "overall_coverage_pct" in coverage_resp.json()

    # -------------------------------------------------------------------------
    # 5. Security Tool Ingestion & Evidence Collection
    # -------------------------------------------------------------------------
    finding_payload = {
        "endpoint_id": endpoint_id,
        "wstg_id": "WSTG-ATHZ-04",
        "title": "BOLA / IDOR in Account Transfer Authorization",
        "description": "Authenticated user can initiate transfer on behalf of other accounts by altering payload recipient.",
        "severity": "Critical",
        "status": "Confirmed",
        "confidence": "Confirmed",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-639",
        "owasp_category": "A01:2021-Broken Access Control",
        "affected_parameter": "recipient_account",
        "detection_source": "authorization_agent",
        "remediation_guidance": "Implement server-side session-to-account authorization checks.",
        "business_impact": "Direct financial fraud and unauthorized fund exfiltration.",
        "raw_request": "POST /api/v1/accounts/transfers HTTP/1.1\nHost: api.globalfin.local\nAuthorization: Bearer secret-token\n\n{\"account\": 9001}",
        "raw_response": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"status\":\"SUCCESS\",\"transferred\":50000}"
    }
    finding_resp = await client.post(f"/api/v1/projects/{project_id}/findings", json=finding_payload, headers=headers)
    assert finding_resp.status_code == 201
    finding_id = finding_resp.json()["id"]

    # Verify Evidence Attachments & Cryptographic Checksums
    evidence_resp = await client.get(f"/api/v1/projects/{project_id}/findings/{finding_id}/evidence", headers=headers)
    assert evidence_resp.status_code == 200
    evidence_list = evidence_resp.json()
    assert len(evidence_list) == 1
    assert len(evidence_list[0]["request_hash_sha256"]) == 64
    assert len(evidence_list[0]["response_hash_sha256"]) == 64

    # -------------------------------------------------------------------------
    # 6. Multi-Agent Autonomous Assessment Execution & Observability
    # -------------------------------------------------------------------------
    start_wf_resp = await client.post(
        f"/api/v1/projects/{project_id}/agents/workflow/start",
        json={"auto_approve_medium": True},
        headers=headers
    )
    assert start_wf_resp.status_code == 201
    wf_data = start_wf_resp.json()
    assert len(wf_data["active_agents"]) >= 7

    agent_status_resp = await client.get(f"/api/v1/projects/{project_id}/agents/status", headers=headers)
    assert agent_status_resp.status_code == 200
    agent_data = agent_status_resp.json()
    assert "active_agents" in agent_data
    assert len(agent_data["active_agents"]) >= 7

    # -------------------------------------------------------------------------
    # 7. Finding Deduplication & One-Click Retesting
    # -------------------------------------------------------------------------
    dedup_resp = await client.get(f"/api/v1/projects/{project_id}/findings/deduplicate", headers=headers)
    assert dedup_resp.status_code == 200
    assert dedup_resp.json()["total_findings"] >= 1

    # Simulate Developer Patch Verification (Expecting 403 Forbidden after patch)
    retest_resp = await client.post(
        f"/api/v1/projects/{project_id}/findings/{finding_id}/retest",
        json={"expected_status_code": 403},
        headers=headers
    )
    assert retest_resp.status_code == 200
    retest_result = retest_resp.json()
    assert retest_result["is_remediated"] is True
    assert retest_result["new_status"] == "Remediated"

    # -------------------------------------------------------------------------
    # 8. Formal PTES Report Compilation & Cryptographic Verification
    # -------------------------------------------------------------------------
    report_gen_resp = await client.post(
        f"/api/v1/projects/{project_id}/reports/generate",
        json={
            "format": "PDF",
            "title": "PTES Official Assessment Report — Global Financial Services",
            "include_raw_evidence": True
        },
        headers=headers
    )
    assert report_gen_resp.status_code == 201
    report_data = report_gen_resp.json()
    report_id = report_data["id"]
    report_sha256 = report_data["file_hash_sha256"]
    assert len(report_sha256) == 64

    # Stream Report Binary File
    download_resp = await client.get(f"/api/v1/reports/{report_id}/download", headers=headers)
    assert download_resp.status_code == 200
    assert download_resp.headers["content-type"] == "application/pdf"
    assert download_resp.headers["X-Report-SHA256"] == report_sha256
    assert len(download_resp.content) > 500

    # Cryptographically Verify Report Authenticity
    verify_resp = await client.post(
        "/api/v1/reports/verify",
        json={"file_hash_sha256": report_sha256}
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["verified"] is True
    assert verify_resp.json()["project_name"] == "Global Financial Services Core Portal"

    # -------------------------------------------------------------------------
    # 9. Audit Trail Verification
    # -------------------------------------------------------------------------
    audit_resp = await client.get(f"/api/v1/audit-logs?project_id={project_id}", headers=headers)
    assert audit_resp.status_code == 200
    audit_events = audit_resp.json()
    assert len(audit_events) >= 5

    action_names = [e["action"] for e in audit_events]
    assert "PROJECT_CREATED" in action_names
    assert "SCOPE_RULE_ADDED" in action_names
    assert "FINDING_CREATED" in action_names
    assert "FINDING_RETEST_EXECUTED" in action_names
    assert "REPORT_GENERATED" in action_names

    # Cryptographically verify tamper-evident audit hash chain
    chain_resp = await client.get("/api/v1/audit-logs/verify", headers=headers)
    assert chain_resp.status_code == 200
    assert chain_resp.json()["is_valid"] is True
