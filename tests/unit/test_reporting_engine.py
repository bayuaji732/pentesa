"""Unit tests for PTES Reporting Engine, ReportLab PDF rendering, Jinja2 compilation, and Finding Triage."""

import datetime
import hashlib
import os
import uuid
import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.discovery import DiscoveredDomain, Endpoint, Technology
from database.models.finding import Finding, FindingEvidence
from database.models.project import Project
from database.models.scope import ScopeRule
from database.models.user import User
from database.models.wstg import WSTGTestCatalog, WSTGTestInstance
from packages.schemas.finding import (
    FindingBatchUpdate,
    FindingCreate,
    FindingRetestRequest
)
from packages.schemas.report import (
    FindingReportItem,
    ReportContext,
    ReportGenerateRequest,
    WSTGCategoryReportItem
)
from services.evidence_engine.finding_service import FindingService
from services.reporting_engine.context_builder import build_report_context
from services.reporting_engine.renderer import ReportRenderer
from services.reporting_engine.reporting_service import ReportingService


@pytest.fixture
def sample_report_context() -> ReportContext:
    """Fixture providing a mock ReportContext satisfying all 17 PTES sections."""
    return ReportContext(
        project_id=str(uuid.uuid4()),
        project_name="Acme Health Portal Security Assessment",
        client_name="Acme Healthcare Inc.",
        target_scope=["api.acme-health.com", "portal.acme-health.com"],
        excluded_scope=["auth0.com", "billing.stripe.com"],
        start_date="2026-11-01",
        end_date="2026-11-08",
        lead_tester="Senior Lead Auditor",
        classification="STRICTLY CONFIDENTIAL",
        generated_at="2026-11-09 10:00:00 UTC",
        report_title="PTES Penetration Test Report — Acme Health Portal",
        report_format="PDF",
        executive_narrative="Pentesa performed an authorized penetration test revealing an elevated risk posture with 1 High severity BOLA finding.",
        risk_summary={"Critical": 0, "High": 1, "Medium": 1, "Low": 0, "Informational": 1},
        total_findings=3,
        critical_findings=0,
        high_findings=1,
        medium_findings=1,
        low_findings=0,
        info_findings=1,
        discovered_domains_count=2,
        discovered_endpoints_count=15,
        discovered_technologies=["Nginx 1.24", "FastAPI", "PostgreSQL"],
        domains_sample=["api.acme-health.com", "portal.acme-health.com"],
        coverage_score=85.5,
        wstg_categories=[
            WSTGCategoryReportItem(
                code="INFO",
                name="Information Gathering",
                total_tests=10,
                executed_tests=10,
                passed_tests=10,
                failed_tests=0,
                coverage_percentage=100.0
            ),
            WSTGCategoryReportItem(
                code="ATHZ",
                name="Authorization Testing",
                total_tests=8,
                executed_tests=6,
                passed_tests=5,
                failed_tests=1,
                coverage_percentage=75.0
            )
        ],
        findings=[
            FindingReportItem(
                id="FIND-001",
                title="Broken Object Level Authorization in Patient Records",
                severity="High",
                cvss_score=8.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                cwe_id="CWE-639",
                wstg_id="WSTG-ATHZ-04",
                owasp_category="A01:2021-Broken Access Control",
                endpoint_url="https://api.acme-health.com/api/v1/patients/1042/records",
                http_method="GET",
                affected_parameter="id",
                description="Endpoint permits authenticated patient A to access patient B records by replacing the path parameter.",
                business_impact="Confidentiality breach violating HIPAA privacy requirements.",
                remediation_guidance="Enforce server-side authorization ensuring requesting user owns the requested record.",
                reproduction_curl="curl -i -s 'https://api.acme-health.com/api/v1/patients/1042/records' -H 'Authorization: Bearer [TOKEN]'",
                raw_request="GET /api/v1/patients/1042/records HTTP/1.1\nHost: api.acme-health.com\n\n",
                raw_response="HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"patient\":\"Jane Doe\",\"records\":[]}",
                request_hash_sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                response_hash_sha256="123456abcdef123456abcdef123456abcdef123456abcdef123456abcdef123456",
                status="Confirmed",
                confidence="Confirmed"
            )
        ],
        include_raw_evidence=True,
        immediate_actions=["Implement object-level access controls on /api/v1/patients/{id}"],
        near_term_actions=["Conduct full API schema review across tenant boundaries"],
        long_term_actions=["Deploy automated authorization test regression harness"]
    )


def test_report_renderer_html(tmp_path, sample_report_context):
    """Verify HTML rendering compiles all 17 PTES sections and generates valid SHA-256."""
    renderer = ReportRenderer(output_dir=str(tmp_path))
    file_path, file_hash = renderer.render_html(sample_report_context)

    assert os.path.exists(file_path)
    assert file_path.endswith(".html")
    assert len(file_hash) == 64

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Verify key sections
    assert "Acme Health Portal Security Assessment" in content
    assert "Broken Object Level Authorization" in content
    assert "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" in content
    assert "RAW HTTP REQUEST STREAM" in content
    assert "CRYPTOGRAPHIC INTEGRITY SEAL" in content


def test_report_renderer_pdf(tmp_path, sample_report_context):
    """Verify PDF rendering produces valid PDF binary bytes and matching SHA-256 hash."""
    renderer = ReportRenderer(output_dir=str(tmp_path))
    file_path, file_hash = renderer.render_pdf(sample_report_context)

    assert os.path.exists(file_path)
    assert file_path.endswith(".pdf")
    assert len(file_hash) == 64

    # Verify PDF magic bytes
    with open(file_path, "rb") as f:
        header = f.read(5)
    assert header == b"%PDF-"


def test_report_renderer_pdf_escapes_xml_special_chars(tmp_path, sample_report_context):
    """Verify ReportLab PDF & HTML rendering succeed when findings contain <script> and & characters."""
    sample_report_context.project_name = "R&D Sandbox <Target>"
    sample_report_context.report_title = "PTES & WSTG Assessment <Live>"
    sample_report_context.executive_narrative = "Validated R&D risks including <script>alert('xss')</script> & SQLi."
    sample_report_context.immediate_actions = ["Encode <script> output & parameterize queries"]
    sample_report_context.findings = [
        FindingReportItem(
            id="FIND-XSS1",
            title="Reflected Cross-Site Scripting & Config Disclosure",
            severity="Critical",
            cvss_score=9.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            cwe_id="CWE-79",
            wstg_id="WSTG-INPV-01",
            owasp_category="A03:2021-Injection",
            endpoint_url="http://127.0.0.1:9000/search?q=<script>alert('pentesa_xss_8421')</script>&mode=1",
            http_method="GET",
            affected_parameter=None,
            description="Parameter reflects unescaped <script>alert('pentesa_xss_8421')</script> & raw JSON.",
            business_impact="Session hijacking & credential exposure.",
            remediation_guidance="Escape <, >, & in HTML responses and apply CSP.",
            reproduction_curl="curl -i -s \"http://127.0.0.1:9000/search?q=%3Cscript%3Ealert(1)%3C/script%3E&a=1&b=2\"",
            raw_request="GET /search?q=<script>alert(1)</script>&a=1 HTTP/1.1\nHost: 127.0.0.1:9000\n\n",
            raw_response="HTTP/1.1 200 OK\n\n<script>alert(1)</script> & debug",
            request_hash_sha256="a" * 64,
            response_hash_sha256="b" * 64,
            status="Confirmed",
            confidence="Confirmed"
        )
    ]

    renderer = ReportRenderer(output_dir=str(tmp_path))
    pdf_path, pdf_hash = renderer.render_pdf(sample_report_context)
    html_path, html_hash = renderer.render_html(sample_report_context)

    assert os.path.exists(pdf_path) and len(pdf_hash) == 64
    assert os.path.exists(html_path) and len(html_hash) == 64
    with open(pdf_path, "rb") as f:
        assert f.read(5) == b"%PDF-"
    with open(html_path, "r", encoding="utf-8") as f:
        html_text = f.read()
    assert "&lt;script&gt;alert(&#39;pentesa_xss_8421&#39;)&lt;/script&gt;" in html_text or "&lt;script&gt;" in html_text


@pytest.mark.asyncio
async def test_reporting_service_lifecycle(db_session: AsyncSession, admin_user: User, tmp_path):
    """Verify full reporting service lifecycle: generation, database persistence, listing, and verification."""
    now = datetime.datetime.now(datetime.timezone.utc)
    # 1. Create project
    project = Project(
        id=uuid.uuid4(),
        name="Hospital Core API",
        status="ACTIVE",
        authorization_start=now - datetime.timedelta(days=2),
        authorization_end=now + datetime.timedelta(days=20),
        created_by=admin_user.id
    )
    db_session.add(project)
    await db_session.commit()

    # 2. Add Scope & Findings
    scope = ScopeRule(project_id=project.id, rule_type="INCLUDE", target_type="IN_SCOPE", pattern="api.hospital.local")
    db_session.add(scope)

    finding = Finding(
        project_id=project.id,
        title="SQL Injection on Search",
        description="Union-based SQL injection on 'q' parameter.",
        severity="Critical",
        status="Confirmed",
        confidence="Confirmed",
        cvss_score=9.8,
        detection_source="manual"
    )
    db_session.add(finding)
    await db_session.commit()

    # 3. Instantiate ReportingService
    renderer = ReportRenderer(output_dir=str(tmp_path))
    service = ReportingService(db_session, renderer=renderer)

    # 4. Generate PDF Report
    pdf_req = ReportGenerateRequest(format="PDF", title="Official Audit Deliverable")
    pdf_report = await service.generate_report(
        project_id=project.id,
        payload=pdf_req,
        user=admin_user
    )

    assert pdf_report.id is not None
    assert pdf_report.format == "PDF"
    assert len(pdf_report.file_hash_sha256) == 64
    assert os.path.exists(pdf_report.file_path)

    # 5. List Reports
    reports_list = await service.list_reports(project.id)
    assert len(reports_list) == 1
    assert reports_list[0].id == pdf_report.id

    # 6. Verify Cryptographic Integrity
    verification = await service.verify_report_hash(pdf_report.file_hash_sha256)
    assert verification.verified is True
    assert verification.report_id == pdf_report.id
    assert verification.project_name == "Hospital Core API"

    # 7. Verification Failure Case
    fake_hash = "0" * 64
    bad_verification = await service.verify_report_hash(fake_hash)
    assert bad_verification.verified is False

    # 8. List Templates
    templates = await service.list_templates()
    assert len(templates) >= 4
    template_names = [t.name for t in templates]
    assert "ptes_standard" in template_names
    assert "executive_summary" in template_names

    # 9. Delete Report
    await service.delete_report(pdf_report.id, project_id=project.id)
    assert not os.path.exists(pdf_report.file_path)
    remaining_reports = await service.list_reports(project.id)
    assert len(remaining_reports) == 0


@pytest.mark.asyncio
async def test_finding_retest_and_triage(db_session: AsyncSession, admin_user: User):
    """Verify one-click finding retesting and batch triage lifecycle transitions."""
    now = datetime.datetime.now(datetime.timezone.utc)
    project = Project(
        id=uuid.uuid4(),
        name="Fintech Platform",
        status="ACTIVE",
        target_domains=["fintech.local"],
        authorization_start=now - datetime.timedelta(days=2),
        authorization_end=now + datetime.timedelta(days=20),
        created_by=admin_user.id
    )
    db_session.add(project)
    await db_session.flush()

    db_session.add(ScopeRule(
        project_id=project.id,
        rule_type="EXACT_DOMAIN",
        target_type="IN_SCOPE",
        pattern="fintech.local",
        protocol="https,http",
    ))
    ep = Endpoint(
        project_id=project.id,
        fqdn="fintech.local",
        url_path="/search",
        http_method="GET",
    )
    db_session.add(ep)
    await db_session.commit()

    service = FindingService(db_session)
    finding = await service.create_finding(
        project_id=project.id,
        payload=FindingCreate(
            endpoint_id=ep.id,
            title="Cross-Site Scripting (Reflected)",
            description="Reflected XSS in query string parameter.",
            severity="Medium",
            cwe_id="CWE-79",
            affected_parameter="q",
            status="Confirmed",
            confidence="Confirmed",
            detection_source="manual",
            raw_request="GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: fintech.local\r\n\r\n",
            raw_response="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>",
        ),
        user_id=admin_user.id,
    )

    # 1. Retest: Vulnerability Still Present
    unpatched_transport = httpx.MockTransport(
        lambda req: httpx.Response(200, headers={"Content-Type": "text/html"}, text="<p><script>alert(1)</script></p>")
    )
    retest_unfixed = await service.retest_finding(
        finding_id=finding.id,
        project_id=project.id,
        payload=FindingRetestRequest(),
        http_transport=unpatched_transport,
    )
    assert retest_unfixed.is_remediated is False
    assert retest_unfixed.new_status == "Confirmed"

    # 2. Retest: Developer Patched (400 Bad Request on sanitized input)
    patched_transport = httpx.MockTransport(
        lambda req: httpx.Response(400, json={"detail": "Invalid characters blocked"})
    )
    retest_fixed = await service.retest_finding(
        finding_id=finding.id,
        project_id=project.id,
        payload=FindingRetestRequest(expected_status_code=400),
        http_transport=patched_transport,
    )
    assert retest_fixed.is_remediated is True
    assert retest_fixed.new_status == "Remediated"

    # 3. Batch Update Status
    f2 = Finding(
        project_id=project.id,
        title="Missing Strict-Transport-Security Header",
        description="HSTS header missing.",
        severity="Low",
        status="Detected",
        confidence="Medium",
        detection_source="nuclei"
    )
    db_session.add(f2)
    await db_session.commit()

    batch_resp = await service.batch_update_status(
        project_id=project.id,
        payload=FindingBatchUpdate(
            finding_ids=[f2.id],
            status="Triaged",
            justification="Audited during morning triage"
        ),
        user_id=admin_user.id
    )
    assert len(batch_resp) == 1
    assert batch_resp[0].status == "Triaged"

    # 4. Deduplication
    f3 = Finding(
        project_id=project.id,
        title="Missing Strict-Transport-Security Header Duplicate",
        description="Second instance of missing HSTS.",
        severity="Low",
        status="Detected",
        confidence="Medium",
        detection_source="nuclei"
    )
    db_session.add(f3)
    await db_session.commit()

    dedup = await service.deduplicate_findings(project.id)
    assert dedup["total_findings"] >= 3
    assert "unique_clusters" in dedup
