"""Integration tests for PTES Report Generation and Finding Triage API Endpoints."""

import datetime
import uuid
import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.discovery import Endpoint
from database.models.finding import Finding
from database.models.project import Project, ProjectMember
from database.models.scope import ScopeRule
from database.models.user import User
from services.evidence_engine.finding_service import FindingService


@pytest.fixture
async def report_test_project(db_session: AsyncSession, admin_user: User) -> Project:
    """Fixture providing a project with findings ready for report generation."""
    now = datetime.datetime.now(datetime.timezone.utc)
    project = Project(
        id=uuid.uuid4(),
        name="Apollo Banking Web App",
        status="ACTIVE",
        target_domains=["apollo-bank.local"],
        authorization_start=now - datetime.timedelta(days=2),
        authorization_end=now + datetime.timedelta(days=20),
        created_by=admin_user.id
    )
    db_session.add(project)

    member = ProjectMember(project_id=project.id, user_id=admin_user.id, role="Lead_Tester")
    db_session.add(member)

    scope = ScopeRule(
        project_id=project.id,
        rule_type="EXACT_DOMAIN",
        target_type="IN_SCOPE",
        pattern="apollo-bank.local",
        protocol="https,http",
    )
    db_session.add(scope)

    ep = Endpoint(
        project_id=project.id,
        fqdn="apollo-bank.local",
        url_path="/api/v1/transfers/9001",
        http_method="POST",
    )
    db_session.add(ep)
    await db_session.flush()

    finding = Finding(
        project_id=project.id,
        endpoint_id=ep.id,
        title="BOLA in Fund Transfer API",
        description="Object level authorization flaw allows transferring funds from arbitrary accounts.",
        severity="Critical",
        status="Confirmed",
        confidence="Confirmed",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        cwe_id="CWE-639",
        wstg_id="WSTG-ATHZ-04",
        detection_source="manual"
    )
    db_session.add(finding)
    await db_session.commit()
    await db_session.refresh(project)
    return project


@pytest.mark.asyncio
async def test_report_generation_and_download_flow(
    client: AsyncClient,
    admin_token: str,
    report_test_project: Project
):
    """Verify end-to-end report generation (PDF & HTML), listing, download, and hash verification."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    project_id = str(report_test_project.id)

    # 1. Generate PDF Report
    gen_pdf_resp = await client.post(
        f"/api/v1/projects/{project_id}/reports/generate",
        json={"format": "PDF", "title": "Comprehensive PTES Audit - Apollo Banking"},
        headers=headers
    )
    assert gen_pdf_resp.status_code == 201
    pdf_data = gen_pdf_resp.json()
    assert pdf_data["format"] == "PDF"
    assert "id" in pdf_data
    assert len(pdf_data["file_hash_sha256"]) == 64
    report_id = pdf_data["id"]
    pdf_hash = pdf_data["file_hash_sha256"]

    # 2. Generate HTML Report
    gen_html_resp = await client.post(
        f"/api/v1/projects/{project_id}/reports/generate",
        json={"format": "HTML", "title": "Interactive PTES Report"},
        headers=headers
    )
    assert gen_html_resp.status_code == 201
    html_data = gen_html_resp.json()
    assert html_data["format"] == "HTML"

    # 3. List Reports
    list_resp = await client.get(
        f"/api/v1/projects/{project_id}/reports",
        headers=headers
    )
    assert list_resp.status_code == 200
    reports = list_resp.json()
    assert len(reports) == 2
    report_ids = [r["id"] for r in reports]
    assert report_id in report_ids

    # 4. Download Report File
    download_resp = await client.get(
        f"/api/v1/reports/{report_id}/download",
        headers=headers
    )
    assert download_resp.status_code == 200
    assert download_resp.headers["content-type"] == "application/pdf"
    assert download_resp.headers["X-Report-SHA256"] == pdf_hash
    assert len(download_resp.content) > 100

    # 5. Verify Report Cryptographic Hash
    verify_resp = await client.post(
        "/api/v1/reports/verify",
        json={"file_hash_sha256": pdf_hash}
    )
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert verify_data["verified"] is True
    assert verify_data["project_name"] == "Apollo Banking Web App"

    # 6. List Templates
    tmpl_resp = await client.get(
        "/api/v1/reports/templates",
        headers=headers
    )
    assert tmpl_resp.status_code == 200
    templates = tmpl_resp.json()
    assert len(templates) >= 4

    # 7. Delete Report
    del_resp = await client.delete(
        f"/api/v1/reports/{report_id}",
        headers=headers
    )
    assert del_resp.status_code == 204

    # Confirm deletion
    download_after_del = await client.get(
        f"/api/v1/reports/{report_id}/download",
        headers=headers
    )
    assert download_after_del.status_code == 404


@pytest.mark.asyncio
async def test_finding_retest_and_triage_api(
    client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    report_test_project: Project
):
    """Verify finding retest, batch update, and deduplication API endpoints."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    project_id = str(report_test_project.id)

    # 1. Fetch Finding
    findings_resp = await client.get(
        f"/api/v1/projects/{project_id}/findings",
        headers=headers
    )
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) >= 1
    finding_id = findings[0]["id"]

    # 2. Retest Finding (Vulnerability Fixed -> 400 Bad Request expected)
    FindingService.default_http_transport = httpx.MockTransport(
        lambda req: httpx.Response(400, json={"error": "Cross-account access blocked"})
    )
    try:
        retest_resp = await client.post(
            f"/api/v1/projects/{project_id}/findings/{finding_id}/retest",
            json={"expected_status_code": 400},
            headers=headers
        )
    finally:
        FindingService.default_http_transport = None
    assert retest_resp.status_code == 200
    retest_data = retest_resp.json()
    assert retest_data["is_remediated"] is True
    assert retest_data["new_status"] == "Remediated"

    # 3. Batch Update Status
    batch_resp = await client.post(
        f"/api/v1/projects/{project_id}/findings/batch-update",
        json={
            "finding_ids": [finding_id],
            "status": "Confirmed",
            "justification": "Operator manually reopened finding during QA check"
        },
        headers=headers
    )
    assert batch_resp.status_code == 200
    updated = batch_resp.json()
    assert len(updated) == 1
    assert updated[0]["status"] == "Confirmed"

    # 4. Deduplicate Findings
    dedup_resp = await client.get(
        f"/api/v1/projects/{project_id}/findings/deduplicate",
        headers=headers
    )
    assert dedup_resp.status_code == 200
    dedup_data = dedup_resp.json()
    assert "total_findings" in dedup_data
    assert "unique_clusters" in dedup_data
