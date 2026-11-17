"""Unit tests for benchmark/baseline_adapter.py."""

import json
from benchmark.baseline_adapter import (
    adapt_combined_baseline,
    adapt_ffuf_findings,
    adapt_nuclei_findings,
    extract_method_from_request,
    extract_parameter_from_url_or_request,
)
from benchmark.score import PHASE_7_REQUIRED_FIELDS, evaluate_evidence_completeness


def test_extract_parameter_from_url_or_request():
    """Verify parameter extraction from queries and request bodies."""
    assert extract_parameter_from_url_or_request("http://target.local/search?q=test&lang=en") == "q"
    assert extract_parameter_from_url_or_request("http://target.local/profile") == ""

    post_req = "POST /login HTTP/1.1\r\nHost: target.local\r\n\r\nusername=admin&password=secret"
    assert extract_parameter_from_url_or_request("http://target.local/login", post_req) == "username"


def test_extract_method_from_request():
    """Verify method extraction from raw requests."""
    assert extract_method_from_request("POST /api/test HTTP/1.1\r\n") == "POST"
    assert extract_method_from_request("GET /path HTTP/1.1\r\n") == "GET"
    assert extract_method_from_request("", default_method="PUT") == "PUT"


def test_adapt_nuclei_findings():
    """Verify conversion of Nuclei results to Phase 7 score.py schema."""
    raw_nuclei = [
        {
            "template_id": "cve-2021-1234",
            "info": {"name": "Test Vulnerability", "severity": "high"},
            "matched_at": "http://bench-juiceshop:3000/rest/products/search?q=123",
            "cwe_id": ["CWE-89"],
            "wstg_id": "WSTG-INPV-05",
            "raw_request": "GET /rest/products/search?q=123 HTTP/1.1\r\nHost: bench-juiceshop:3000\r\n\r\n",
            "raw_response": "HTTP/1.1 200 OK\r\n\r\n[{\"id\":1}]",
            "reproduction_curl": "curl -s 'http://bench-juiceshop:3000/rest/products/search?q=123'",
        }
    ]
    adapted = adapt_nuclei_findings(raw_nuclei, target_base_url="http://bench-juiceshop:3000")
    assert len(adapted) == 1
    finding = adapted[0]

    assert finding["endpoint"] == "/rest/products/search"
    assert finding["method"] == "GET"
    assert finding["parameter"] == "q"
    assert finding["wstg_id"] == "WSTG-INPV-05"
    assert finding["cwe_id"] == "CWE-89"
    assert finding["detection_source"] == "nuclei"

    # Verify all Phase 7 required fields are present
    for req_field in PHASE_7_REQUIRED_FIELDS:
        assert req_field in finding, f"Missing Phase 7 field: {req_field}"

    score, missing = evaluate_evidence_completeness(finding)
    assert score == 100.0, f"Evidence completeness was not 100%: missing {missing}"


def test_adapt_ffuf_findings():
    """Verify conversion of ffuf results to Phase 7 score.py schema."""
    raw_ffuf = [
        {
            "url": "http://bench-pentesa-app:8080/admin/config",
            "matched_at": "http://bench-pentesa-app:8080/admin/config",
            "status_code": 200,
            "length": 456,
            "raw_request": "GET /admin/config HTTP/1.1\r\nHost: bench-pentesa-app:8080\r\n\r\n",
            "raw_response": "HTTP/1.1 200 OK\r\n\r\nAdmin Config Page",
            "reproduction_curl": "curl -i -s 'http://bench-pentesa-app:8080/admin/config'",
        }
    ]
    adapted = adapt_ffuf_findings(raw_ffuf, target_base_url="http://bench-pentesa-app:8080")
    assert len(adapted) == 1
    finding = adapted[0]

    assert finding["endpoint"] == "/admin/config"
    assert finding["method"] == "GET"
    assert finding["detection_source"] == "ffuf"

    # Verify all Phase 7 required fields are present
    for req_field in PHASE_7_REQUIRED_FIELDS:
        assert req_field in finding, f"Missing Phase 7 field: {req_field}"

    score, missing = evaluate_evidence_completeness(finding)
    assert score == 100.0, f"Evidence completeness was not 100%: missing {missing}"


def test_adapt_combined_baseline():
    """Verify combining nuclei and ffuf findings with execution telemetry."""
    nuclei_items = [{"matched_at": "http://target/a?p=1", "cwe_id": 89}]
    ffuf_items = [{"matched_at": "http://target/b", "status_code": 200}]

    combined = adapt_combined_baseline(nuclei_items, ffuf_items, target_base_url="http://target")
    assert "findings" in combined
    assert len(combined["findings"]) == 2
    assert "execution_telemetry" in combined
    assert combined["execution_telemetry"]["scheduled_runs"] == 1
