"""Regression tests for P1-FIND-02: FindingResponse endpoint and method normalization."""

import uuid
from datetime import datetime, timezone
import pytest

from database.models.discovery import Endpoint
from database.models.finding import Finding, FindingEvidence
from packages.schemas.finding import FindingResponse


def test_finding_response_has_endpoint_and_method_fields():
    """Verify FindingResponse schema declares root endpoint and method string fields."""
    fields = FindingResponse.model_fields
    assert "endpoint" in fields, "FindingResponse missing root 'endpoint' field"
    assert "method" in fields, "FindingResponse missing root 'method' field"


def test_finding_response_populates_from_linked_endpoint():
    """Verify FindingResponse populates endpoint and method from linked Endpoint relation."""
    project_id = uuid.uuid4()
    endpoint_id = uuid.uuid4()
    finding_id = uuid.uuid4()

    mock_endpoint = Endpoint(
        id=endpoint_id,
        project_id=project_id,
        fqdn="target.lab",
        url_path="/api/v1/vulnerable/search",
        http_method="POST",
        parameter_schema={},
        testing_status="Discovered"
    )

    finding = Finding(
        id=finding_id,
        project_id=project_id,
        endpoint_id=endpoint_id,
        title="SQL Injection in Search",
        description="SQL injection vulnerability in query parameter",
        severity="High",
        status="Confirmed",
        confidence="High",
        detection_source="manual",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )
    finding.endpoint = mock_endpoint
    finding.evidence = []

    resp = FindingResponse.model_validate(finding)
    assert resp.endpoint == "/api/v1/vulnerable/search"
    assert resp.method == "POST"
    assert resp.endpoint_id == endpoint_id


def test_finding_response_fallback_to_raw_request_when_endpoint_unlinked():
    """Verify FindingResponse extracts endpoint and method from raw_request when endpoint_id is None."""
    project_id = uuid.uuid4()
    finding_id = uuid.uuid4()

    evidence = FindingEvidence(
        id=uuid.uuid4(),
        finding_id=finding_id,
        raw_request="GET /admin/dashboard?debug=1 HTTP/1.1\r\nHost: target.lab\r\n\r\n",
        raw_response="HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
        reproduction_curl="curl http://target.lab/admin/dashboard?debug=1",
        request_hash_sha256="abc",
        response_hash_sha256="def",
        captured_at=datetime.now(timezone.utc)
    )

    finding = Finding(
        id=finding_id,
        project_id=project_id,
        endpoint_id=None,
        title="Information Disclosure",
        description="Debug info exposed on dashboard",
        severity="Medium",
        status="Confirmed",
        confidence="High",
        detection_source="nuclei",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )
    finding.endpoint = None
    finding.evidence = [evidence]

    resp = FindingResponse.model_validate(finding)
    assert resp.endpoint == "/admin/dashboard?debug=1"
    assert resp.method == "GET"
    assert resp.endpoint_id is None


def test_finding_response_returns_none_when_both_absent():
    """Verify FindingResponse sets endpoint and method to None when neither relation nor raw_request exists."""
    project_id = uuid.uuid4()
    finding_id = uuid.uuid4()

    finding = Finding(
        id=finding_id,
        project_id=project_id,
        endpoint_id=None,
        title="Generic Finding",
        description="No endpoint or evidence available",
        severity="Low",
        status="Detected",
        confidence="Low",
        detection_source="manual",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )
    finding.endpoint = None
    finding.evidence = []

    resp = FindingResponse.model_validate(finding)
    assert resp.endpoint is None
    assert resp.method is None
