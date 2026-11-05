"""Integration tests for Findings, Evidence, Reproductions, and False Positives API."""

import pytest
from sqlalchemy import select
from database.models.audit import AuditLog


@pytest.mark.asyncio
async def test_create_and_query_finding(client, admin_token, test_project, db_session):
    """Verify creating a finding with forensic evidence and querying via REST API."""
    create_resp = await client.post(
        f"/api/v1/projects/{test_project.id}/findings",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "title": "Cross-Site Scripting (XSS) in Comment Box",
            "description": "Stored XSS via comment field without HTML entity encoding.",
            "severity": "High",
            "cwe_id": "CWE-79",
            "wstg_id": "WSTG-INPV-02",
            "owasp_category": "A03:2021-Injection",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "affected_parameter": "comment",
            "detection_source": "manual",
            "raw_request": "POST /api/comments HTTP/1.1\r\nHost: target.com\r\n\r\ncomment=<script>alert(1)</script>",
            "raw_response": "HTTP/1.1 200 OK\r\n\r\n<div><script>alert(1)</script></div>"
        }
    )
    assert create_resp.status_code == 201
    finding = create_resp.json()
    assert finding["title"] == "Cross-Site Scripting (XSS) in Comment Box"
    assert finding["severity"] == "High"
    assert finding["status"] == "Detected"

    finding_id = finding["id"]

    # Query finding by ID
    get_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/findings/{finding_id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == finding_id

    # Filter findings list
    list_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/findings?severity=High",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert list_resp.status_code == 200
    assert any(f["id"] == finding_id for f in list_resp.json())

    # Get evidence
    ev_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/findings/{finding_id}/evidence",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert ev_resp.status_code == 200
    ev_list = ev_resp.json()
    assert len(ev_list) >= 1
    assert "alert(1)" in ev_list[0]["raw_request"]
    assert len(ev_list[0]["request_hash_sha256"]) == 64


@pytest.mark.asyncio
async def test_finding_status_lifecycle_and_audit(client, admin_token, test_project, db_session):
    """Verify status transitions through the API and resulting audit log events."""
    create_resp = await client.post(
        f"/api/v1/projects/{test_project.id}/findings",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "title": "Insecure Direct Object Reference (IDOR)",
            "description": "User ID parameter can be manipulated to view other records.",
            "severity": "Critical",
            "cwe_id": "CWE-639",
            "wstg_id": "WSTG-ATHZ-04"
        }
    )
    assert create_resp.status_code == 201
    finding_id = create_resp.json()["id"]

    # Illegal transition: Detected -> Remediated (400 Bad Request)
    bad_resp = await client.patch(
        f"/api/v1/projects/{test_project.id}/findings/{finding_id}/status",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "status": "Remediated",
            "justification": "Attempting jump directly to Remediated"
        }
    )
    assert bad_resp.status_code == 400
    assert "Illegal finding status transition" in bad_resp.json()["detail"]

    # Legal transition: Detected -> Triaged
    good_resp = await client.patch(
        f"/api/v1/projects/{test_project.id}/findings/{finding_id}/status",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "status": "Triaged",
            "justification": "Confirmed by Lead Penetration Tester"
        }
    )
    assert good_resp.status_code == 200
    assert good_resp.json()["status"] == "Triaged"

    # Verify audit logs in database
    audit_stmt = select(AuditLog).where(
        AuditLog.resource_id == finding_id
    )
    audits = (await db_session.execute(audit_stmt)).scalars().all()
    actions = [a.action for a in audits]
    assert "FINDING_CREATED" in actions
    assert "FINDING_STATUS_UPDATED" in actions


@pytest.mark.asyncio
async def test_refute_false_positive_and_reproduce(client, admin_token, test_project):
    """Verify false positive refutation endpoint and reproduction logging."""
    create_resp = await client.post(
        f"/api/v1/projects/{test_project.id}/findings",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "title": "Directory Listing Enabled",
            "description": "Apparent directory listing on /images/",
            "severity": "Low",
            "cwe_id": "CWE-548",
            "wstg_id": "WSTG-CONF-04"
        }
    )
    assert create_resp.status_code == 201
    finding_id = create_resp.json()["id"]

    # 1. Record reproduction attempt
    repro_resp = await client.post(
        f"/api/v1/projects/{test_project.id}/findings/{finding_id}/reproduce",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "reproduced_by": "Automated Tester Agent"
        }
    )
    assert repro_resp.status_code == 201
    assert repro_resp.json()["success"] is True

    # 2. Refute finding as false positive
    fp_resp = await client.post(
        f"/api/v1/projects/{test_project.id}/findings/{finding_id}/false-positive",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "classification": "STATIC_PAGE_REFLECTION",
            "justification": "The returned HTML was a custom static index page designed to look like Apache directory listing, no actual filesystem access exists."
        }
    )
    assert fp_resp.status_code == 201
    assert fp_resp.json()["classification"] == "STATIC_PAGE_REFLECTION"

    # Verify status is now False Positive
    check_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/findings/{finding_id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert check_resp.status_code == 200
    assert check_resp.json()["status"] == "False Positive"

