"""Unit tests for FindingService: CRUD, evidence attachment, 10-step lifecycle, false positives, and reproductions."""

import uuid
import pytest
from packages.common.exceptions import BadRequestError, ResourceNotFoundError
from packages.schemas.finding import FalsePositiveCreate, FindingCreate, FindingStatusUpdate
from services.evidence_engine.finding_service import FindingService


@pytest.mark.asyncio
async def test_create_and_get_finding_with_evidence(db_session, test_project, admin_user):
    """Verify finding creation with initial forensic evidence and audit logging."""
    service = FindingService(db_session)

    payload = FindingCreate(
        title="SQL Injection in Login Form",
        description="User-controlled parameter 'username' is vulnerable to boolean-based blind SQL injection.",
        severity="Critical",
        cwe_id="CWE-89",
        wstg_id="WSTG-INPV-05",
        owasp_category="A03:2021-Injection",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        affected_parameter="username",
        detection_source="wstg_runner",
        remediation_guidance="Use parameterized queries and ORM prepared statements.",
        raw_request="POST /api/v1/login HTTP/1.1\r\nHost: target.com\r\n\r\nusername=admin' OR 1=1--",
        raw_response="HTTP/1.1 200 OK\r\n\r\n{\"token\": \"ey...\"}"
    )

    finding = await service.create_finding(
        project_id=test_project.id,
        payload=payload,
        user_id=admin_user.id
    )

    assert finding.id is not None
    assert finding.title == "SQL Injection in Login Form"
    assert finding.severity == "Critical"
    assert finding.status == "Detected"
    assert finding.confidence == "Medium"
    assert len(finding.evidence) == 1
    assert finding.evidence[0].request_hash_sha256 is not None
    assert len(finding.status_history) == 1
    assert finding.status_history[0].new_status == "Detected"

    # Get finding
    fetched = await service.get_finding(finding.id, test_project.id)
    assert fetched.id == finding.id
    assert fetched.cwe_id == "CWE-89"


@pytest.mark.asyncio
async def test_list_findings_filtering(db_session, test_project, admin_user):
    """Verify multi-dimensional query filters on findings."""
    service = FindingService(db_session)

    f1 = await service.create_finding(
        project_id=test_project.id,
        payload=FindingCreate(
            title="Reflected XSS in search",
            description="Unsanitized query reflected in HTML",
            severity="Medium",
            cwe_id="CWE-79",
            wstg_id="WSTG-INPV-01",
            status="Detected"
        ),
        user_id=admin_user.id
    )
    f2 = await service.create_finding(
        project_id=test_project.id,
        payload=FindingCreate(
            title="Missing Security Headers",
            description="HSTS and CSP headers are missing",
            severity="Low",
            cwe_id="CWE-693",
            wstg_id="WSTG-CONF-07",
            status="Triaged"
        ),
        user_id=admin_user.id
    )

    # Filter by severity
    res_med = await service.list_findings(test_project.id, severity="Medium")
    assert len(res_med) == 1
    assert res_med[0].id == f1.id

    # Filter by WSTG ID
    res_wstg = await service.list_findings(test_project.id, wstg_id="WSTG-CONF-07")
    assert len(res_wstg) == 1
    assert res_wstg[0].id == f2.id

    # Search query
    res_search = await service.list_findings(test_project.id, search="CSP")
    assert len(res_search) == 1
    assert res_search[0].id == f2.id


@pytest.mark.asyncio
async def test_finding_status_lifecycle_transitions(db_session, test_project, admin_user):
    """Verify 10-step lifecycle validation: permits legal transitions and rejects illegal ones."""
    service = FindingService(db_session)

    finding = await service.create_finding(
        project_id=test_project.id,
        payload=FindingCreate(
            title="Path Traversal in download.php",
            description="Path traversal flaw",
            severity="High",
            cwe_id="CWE-22",
            wstg_id="WSTG-CONF-04"
        ),
        user_id=admin_user.id
    )

    # 1. Illegal transition: Detected -> Retested (must go via Confirmed/Remediated)
    with pytest.raises(BadRequestError) as exc_info:
        await service.update_status(
            finding_id=finding.id,
            project_id=test_project.id,
            payload=FindingStatusUpdate(
                status="Retested",
                justification="Direct jump to Retested without remediation"
            ),
            user_id=admin_user.id
        )
    assert "Illegal finding status transition" in str(exc_info.value)

    # 2. Legal transition: Detected -> Triaged
    t1 = await service.update_status(
        finding_id=finding.id,
        project_id=test_project.id,
        payload=FindingStatusUpdate(
            status="Triaged",
            justification="Triage verified vulnerable code path"
        ),
        user_id=admin_user.id
    )
    assert t1.status == "Triaged"

    # 3. Legal transition: Triaged -> Confirmed
    t2 = await service.update_status(
        finding_id=finding.id,
        project_id=test_project.id,
        payload=FindingStatusUpdate(
            status="Confirmed",
            justification="Exploited successfully in staging"
        ),
        user_id=admin_user.id
    )
    assert t2.status == "Confirmed"

    # 4. Legal transition: Confirmed -> Remediated
    t3 = await service.update_status(
        finding_id=finding.id,
        project_id=test_project.id,
        payload=FindingStatusUpdate(
            status="Remediated",
            justification="Applied patch in commit ab12cd"
        ),
        user_id=admin_user.id
    )
    assert t3.status == "Remediated"

    # Verify history chain length (Initial + 3 transitions = 4)
    refreshed = await service.get_finding(finding.id, test_project.id)
    assert len(refreshed.status_history) == 4


@pytest.mark.asyncio
async def test_register_false_positive(db_session, test_project, admin_user):
    """Verify false positive refutation with required classification and justification."""
    service = FindingService(db_session)

    finding = await service.create_finding(
        project_id=test_project.id,
        payload=FindingCreate(
            title="Apparent SQLi in search",
            description="Detected by heuristic pattern",
            severity="Medium",
            cwe_id="CWE-89",
            wstg_id="WSTG-INPV-05"
        ),
        user_id=admin_user.id
    )

    fp = await service.register_false_positive(
        finding_id=finding.id,
        project_id=test_project.id,
        payload=FalsePositiveCreate(
            classification="WAF_FILTER_BLOCK",
            justification="Application error was simulated by WAF blocking, backend query was never executed."
        ),
        user_id=admin_user.id
    )

    assert fp.id is not None
    assert fp.classification == "WAF_FILTER_BLOCK"

    refreshed = await service.get_finding(finding.id, test_project.id)
    assert refreshed.status == "False Positive"
    assert len(refreshed.false_positives) == 1


@pytest.mark.asyncio
async def test_record_reproduction(db_session, test_project, admin_user):
    """Verify empirical reproduction tracking and confidence elevation."""
    service = FindingService(db_session)

    finding = await service.create_finding(
        project_id=test_project.id,
        payload=FindingCreate(
            title="CORS Misconfiguration",
            description="Wildcard origin with credentials allowed",
            severity="Medium",
            cwe_id="CWE-942",
            wstg_id="WSTG-CONF-07",
            confidence="Tentative"
        ),
        user_id=admin_user.id
    )

    repro = await service.record_reproduction(
        finding_id=finding.id,
        project_id=test_project.id,
        reproduced_by="Security Engineer Alice",
        success=True,
        status_code=200,
        duration_ms=45
    )

    assert repro.id is not None
    assert repro.success is True

    refreshed = await service.get_finding(finding.id, test_project.id)
    assert refreshed.confidence == "Confirmed"
    assert len(refreshed.reproductions) == 1
