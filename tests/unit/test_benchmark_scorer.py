"""Unit tests for the Pentesa Pentest Effectiveness Benchmark Scorer.

Proves the deterministic scoring mathematics and Phase 7 evidence checklist evaluation
using clearly labelled synthetic findings fixtures before any real benchmark runs exist.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
import pytest

from benchmark.score import (
    PHASE_7_REQUIRED_FIELDS,
    evaluate_evidence_completeness,
    extract_cwe_id,
    extract_wstg_category,
    finding_matches_ground_truth,
    normalize_endpoint,
    normalize_method,
    normalize_parameter,
    score_benchmark,
)

FIXTURES_PATH = Path(__file__).parent.parent / "fixtures" / "synthetic_benchmark_findings.json"
GROUND_TRUTH_PATH = Path(__file__).parent.parent.parent / "benchmark" / "ground_truth.yaml"


@pytest.fixture
def synthetic_data():
    """Load the clearly labelled synthetic benchmark findings fixture."""
    with open(FIXTURES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def tp_findings(synthetic_data):
    """Return only the 15 synthetic true positive findings."""
    return [
        f for f in synthetic_data["findings"]
        if f.get("synthetic_label") == "TRUE_POSITIVE"
    ]


# ==============================================================================
# 1. Normalization & Utility Unit Tests
# ==============================================================================

def test_normalize_endpoint():
    """Verify endpoint normalization handles full URLs, query params, trailing slashes."""
    assert normalize_endpoint("http://juiceshop:3000/rest/products/search?q=test") == "/rest/products/search"
    assert normalize_endpoint("https://example.com/api/v1/users/") == "/api/v1/users"
    assert normalize_endpoint("cmd/ping") == "/cmd/ping"
    assert normalize_endpoint("/") == "/"
    assert normalize_endpoint("") == "/"
    assert normalize_endpoint("  /FILES/READ/  ") == "/files/read"


def test_normalize_method():
    """Verify method normalization returns uppercase trimmed strings."""
    assert normalize_method("get") == "GET"
    assert normalize_method("  post  ") == "POST"
    assert normalize_method("") == "GET"
    assert normalize_method(None) == "GET"


def test_normalize_parameter():
    """Verify parameter normalization handles header prefixes and casing."""
    assert normalize_parameter("header:Authorization") == "authorization"
    assert normalize_parameter("HEADER:X-Api-Key") == "x-api-key"
    assert normalize_parameter("  q  ") == "q"
    assert normalize_parameter("") == ""
    assert normalize_parameter(None) == ""


def test_extract_cwe_id():
    """Verify integer CWE extraction from strings and ints."""
    assert extract_cwe_id("CWE-89") == 89
    assert extract_cwe_id("cwe-79") == 79
    assert extract_cwe_id(918) == 918
    assert extract_cwe_id("918") == 918
    assert extract_cwe_id("no-cwe") is None
    assert extract_cwe_id(None) is None


def test_extract_wstg_category():
    """Verify extraction of 4-letter WSTG category."""
    assert extract_wstg_category("WSTG-INPV-05") == "INPV"
    assert extract_wstg_category("wstg-athz-04") == "ATHZ"
    assert extract_wstg_category("WSTG-BUSL-01") == "BUSL"
    assert extract_wstg_category("INVALID-CODE") == ""
    assert extract_wstg_category("") == ""
    assert extract_wstg_category(None) == ""


# ==============================================================================
# 2. Phase 7 Evidence Completeness Unit Tests
# ==============================================================================

def test_evaluate_evidence_completeness_perfect(tp_findings):
    """Verify that a fully compliant finding scores 100.0% evidence completeness."""
    first_tp = tp_findings[0]
    pct, missing = evaluate_evidence_completeness(first_tp)
    assert pct == 100.0
    assert missing == []


def test_evaluate_evidence_completeness_missing_fields():
    """Verify that omitting required Phase 7 fields calculates exact penalty."""
    incomplete_finding = {
        "id": "INCOMPLETE-01",
        "target": "http://localhost:3000",
        "endpoint": "/api/test",
        "method": "GET",
        "parameter": "id",
        # missing: wstg_id, cwe_id, detection_source
        "reproduction_procedure": "curl http://localhost:3000/api/test?id=1",
        "actual_evidence": "leaked data",
        "severity_justification": "SQLi impact",
        "confidence": "HIGH",
        "false_positive_assessment": "verified",
        "remediation": "use parameterized query",
        "validation_status": "CONFIRMED",
    }
    pct, missing = evaluate_evidence_completeness(incomplete_finding)
    # 12 present out of 15 required = 12 / 15 = 80.0%
    assert pct == 80.0
    assert set(missing) == {"wstg_id", "cwe_id", "detection_source"}


# ==============================================================================
# 3. Deterministic Ground Truth Matching Unit Tests
# ==============================================================================

def test_finding_matches_ground_truth_exact():
    """Verify exact match on endpoint, method, parameter, and CWE."""
    gt_case = {
        "id": "GT-SQLI-01-V",
        "endpoint": "/rest/products/search",
        "method": "GET",
        "parameter": "q",
        "cwe": "CWE-89",
        "wstg_id": "WSTG-INPV-05",
        "category": "SQL Injection"
    }
    finding = {
        "endpoint": "/rest/products/search",
        "method": "GET",
        "parameter": "q",
        "cwe_id": 89,
        "wstg_id": "WSTG-INPV-05"
    }
    assert finding_matches_ground_truth(finding, gt_case) is True


def test_finding_matches_ground_truth_dynamic_path():
    """Verify path variable replacement in crAPI vehicle endpoint."""
    gt_case = {
        "id": "GT-IDOR-01-V",
        "endpoint": "/identity/api/v2/vehicle/{vehicleId}/location",
        "method": "GET",
        "parameter": "vehicleId",
        "cwe": "CWE-639",
        "wstg_id": "WSTG-ATHZ-04",
        "category": "IDOR / BOLA"
    }
    finding = {
        "endpoint": "/identity/api/v2/vehicle/99999/location",
        "method": "GET",
        "parameter": "vehicleId",
        "cwe_id": 639,
        "wstg_id": "WSTG-ATHZ-04"
    }
    assert finding_matches_ground_truth(finding, gt_case) is True


def test_finding_matches_ground_truth_mismatches():
    """Verify that method or endpoint mismatches return False."""
    gt_case = {
        "id": "GT-CMDI-01-V",
        "endpoint": "/cmd/ping",
        "method": "GET",
        "parameter": "host",
        "cwe": "CWE-78",
        "wstg_id": "WSTG-INPV-12"
    }
    # Method mismatch
    assert finding_matches_ground_truth({
        "endpoint": "/cmd/ping", "method": "POST", "parameter": "host", "cwe_id": 78
    }, gt_case) is False

    # Endpoint mismatch
    assert finding_matches_ground_truth({
        "endpoint": "/cmd/traceroute", "method": "GET", "parameter": "host", "cwe_id": 78
    }, gt_case) is False

    # Parameter mismatch
    assert finding_matches_ground_truth({
        "endpoint": "/cmd/ping", "method": "GET", "parameter": "count", "cwe_id": 78
    }, gt_case) is False


# ==============================================================================
# 4. Scorer Mathematical Proofs & Metrics (Phase 3 A3 Scorer Policy)
# ==============================================================================

def test_scorer_tp_detection_math(tp_findings):
    """PROVE MATH: True Positive detection across the master 63-case ground truth matrix.
    
    15 TP detected out of 45 vulnerable cases:
    - TP = 15
    - FN = 30
    - FP = 0
    - Precision = 15 / 15 = 1.0
    - Recall = 15 / 45 = 0.3333 (each detected case = 2.22% recall)
    - F1 = 2 * (1.0 * 0.3333) / (1.0 + 0.3333) = 0.50
    - FPR_secure = 0 / 18 = 0.0
    """
    assert len(tp_findings) == 15
    result = score_benchmark(str(GROUND_TRUTH_PATH), tp_findings)

    metrics = result["detection_metrics"]
    assert metrics["true_positives"] == 15
    assert metrics["false_positives"] == 0
    assert metrics["false_negatives"] == 30
    assert metrics["secure_cases_false_positives"] == 0
    assert metrics["precision"] == 1.0
    assert metrics["strict_precision"] == 1.0
    assert metrics["adjudicated_precision"] == 1.0
    assert metrics["recall"] == 0.3333
    assert metrics["f1_score"] == 0.5
    assert metrics["false_positive_rate_secure"] == 0.0

    # Summary
    summary = result["benchmark_summary"]
    assert summary["total_ground_truth_cases"] == 63
    assert summary["vulnerable_cases_count"] == 45
    assert summary["secure_cases_count"] == 18
    assert summary["total_findings_evaluated"] == 15


def test_scorer_strict_vs_adjudicated_precision(synthetic_data):
    """PROVE MATH: Unlisted findings policy and strict vs adjudicated precision (A3).
    
    Inputs:
    - 10 True Positives
    - 2 False Positives on Secure cases (DVWA impossible SQLi, bench app secure JWT)
    - 1 Unmatched finding adjudicated as FALSE_POSITIVE via reference PoC
    Total findings = 13.
    
    Expected Math:
    TP = 10
    FN = 45 - 10 = 35
    Secure FP = 2
    Unlisted = 1 (adjudicated FP)
    Strict FP = 2 + 1 = 3
    Strict Precision = 10 / (10 + 3) = 10 / 13 = 0.7692
    Adjudicated Precision = 10 / (10 + 2 + 1) = 0.7692
    Recall = 10 / 45 = 0.2222
    F1 = 2 * (0.7692 * 0.2222) / (0.7692 + 0.2222) = 0.3448
    FPR_secure = 2 / 18 = 0.1111
    """
    findings_list = synthetic_data["findings"]
    tp_10 = [f for f in findings_list if f.get("synthetic_label") == "TRUE_POSITIVE"][:10]
    fp_secure = [f for f in findings_list if f.get("synthetic_label") == "FALSE_POSITIVE_ON_SECURE_ENDPOINT"]
    fp_unmatched = [f for f in findings_list if f.get("synthetic_label") == "UNMATCHED_FALSE_POSITIVE"]

    test_findings = tp_10 + fp_secure + fp_unmatched
    assert len(test_findings) == 13

    result = score_benchmark(str(GROUND_TRUTH_PATH), test_findings)
    metrics = result["detection_metrics"]

    assert metrics["true_positives"] == 10
    assert metrics["false_negatives"] == 35
    assert metrics["secure_cases_false_positives"] == 2
    assert metrics["unlisted_findings_count"] == 1
    assert metrics["unlisted_adjudicated_fp"] == 1
    assert metrics["unlisted_adjudicated_tp"] == 0
    assert metrics["strict_precision"] == 0.7692
    assert metrics["adjudicated_precision"] == 0.7692
    assert metrics["recall"] == 0.2222
    assert metrics["f1_score"] == 0.3448
    assert metrics["false_positive_rate_secure"] == 0.1111


def test_scorer_unlisted_adjudicated_true_positive():
    """PROVE MATH: Unlisted finding adjudicated as genuine vulnerability increases adjudicated precision."""
    synthetic_unlisted_tp = [
        {
            "id": "UNLISTED-VALID-01",
            "target": "http://juiceshop:3000",
            "endpoint": "/rest/extra/unknown-sqli",
            "method": "GET",
            "parameter": "extra",
            "wstg_id": "WSTG-INPV-05",
            "cwe_id": 89,
            "category": "SQL Injection",
            "adjudication": "CONFIRMED_VULNERABILITY",
            "reproduction_curl": "curl -s 'http://juiceshop:3000/rest/extra/unknown-sqli?extra=1'",
            "validation_status": "CONFIRMED"
        }
    ]
    result = score_benchmark(str(GROUND_TRUTH_PATH), synthetic_unlisted_tp)
    metrics = result["detection_metrics"]

    # 0 TP on master GT, 1 unlisted finding
    assert metrics["true_positives"] == 0
    assert metrics["unlisted_findings_count"] == 1
    assert metrics["unlisted_adjudicated_tp"] == 1
    assert metrics["unlisted_adjudicated_fp"] == 0
    # Strict precision treats unlisted as FP: 0 / (0 + 1) = 0.0
    assert metrics["strict_precision"] == 0.0
    # Adjudicated precision credits confirmed unlisted vulnerability: 1 / 1 = 1.0
    assert metrics["adjudicated_precision"] == 1.0


def test_scorer_authoritative_bench_app_precision(tp_findings):
    """PROVE POLICY: Precision is reported as AUTHORITATIVE specifically on pentesa-bench."""
    result = score_benchmark(str(GROUND_TRUTH_PATH), tp_findings)
    bench_metrics = result["authoritative_bench_metrics"]

    assert bench_metrics["target"] == "pentesa-bench"
    assert "AUTHORITATIVE" in bench_metrics["authority_status"]
    assert bench_metrics["benchmark_cases_count"] == 42  # 26 vulnerable + 16 secure paired controls
    assert bench_metrics["vulnerable_cases_count"] == 26
    assert bench_metrics["secure_cases_count"] == 16
    assert bench_metrics["strict_precision"] == 1.0
    assert bench_metrics["adjudicated_precision"] == 1.0
    assert bench_metrics["recall"] == round(bench_metrics["true_positives"] / 26, 4)


def test_category_equivalence_sqli_at_login():
    """PROVE POLICY: Category-equivalence rule correctly scores SQLi at login under SQLi, not Authentication."""
    gt_sqli = {
        "id": "GT-SQLI-02-V",
        "endpoint": "/rest/user/login",
        "method": "POST",
        "parameter": "email",
        "category": "SQL Injection",
        "wstg_id": "WSTG-INPV-05",
        "cwe": "CWE-89"
    }
    gt_auth = {
        "id": "GT-AUTH-01-V",
        "endpoint": "/rest/user/login",
        "method": "POST",
        "parameter": "email",
        "category": "Authentication weaknesses",
        "wstg_id": "WSTG-ATHN-02",
        "cwe": "CWE-287"
    }

    # Finding reports SQL injection at login endpoint
    finding_sqli_at_login = {
        "endpoint": "/rest/user/login",
        "method": "POST",
        "parameter": "email",
        "cwe_id": 89,
        "wstg_id": "WSTG-INPV-05",
        "category": "Authentication weaknesses"  # Spurious high-level label from tool
    }

    # Must match SQL Injection ground truth case via category equivalence
    assert finding_matches_ground_truth(finding_sqli_at_login, gt_sqli) is True
    # Must NOT match Authentication ground truth case because canonical category is sql_injection
    assert finding_matches_ground_truth(finding_sqli_at_login, gt_auth) is False


def test_scorer_zero_findings():
    """PROVE MATH: Zero findings emitted (complete tool outage / total blind test).
    
    Expected Math:
    TP = 0, FP = 0, FN = 45
    Precision = 0.0, Recall = 0.0, F1 = 0.0, FPR_secure = 0.0
    """
    result = score_benchmark(str(GROUND_TRUTH_PATH), [])
    metrics = result["detection_metrics"]

    assert metrics["true_positives"] == 0
    assert metrics["false_positives"] == 0
    assert metrics["false_negatives"] == 45
    assert metrics["secure_cases_false_positives"] == 0
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1_score"] == 0.0
    assert metrics["false_positive_rate_secure"] == 0.0


def test_scorer_suppressed_and_refuted_findings(synthetic_data):
    """PROVE LOGIC: Refuted / suppressed candidate findings are not counted as false positives."""
    findings_list = synthetic_data["findings"]
    refuted = [f for f in findings_list if f.get("synthetic_label") == "SUPPRESSED_REFUTED_FINDING"]
    assert len(refuted) == 1

    # Only pass the refuted finding
    result = score_benchmark(str(GROUND_TRUTH_PATH), refuted)
    metrics = result["detection_metrics"]

    # Refuted finding should not register as an unlisted false positive
    assert metrics["false_positives"] == 0
    assert metrics["true_positives"] == 0
    assert metrics["false_negatives"] == 45


def test_scorer_wstg_coverage_formula_executed_over_applicable(synthetic_data):
    """PROVE MATH: WSTG Coverage calculates Executed / Applicable (A3 fix).
    
    In synthetic telemetry:
    - executed_wstg_tests = 38
    - applicable_wstg_tests = 38 (tests applicable to target web profile)
    - total_catalog_tests = 106
    
    Executed / Applicable = 38 / 38 = 100.0%
    Executed / Total Catalog = 38 / 106 = 35.85%
    """
    telemetry = synthetic_data["execution_telemetry"]
    tp_findings = [f for f in synthetic_data["findings"] if f.get("synthetic_label") == "TRUE_POSITIVE"]

    result = score_benchmark(str(GROUND_TRUTH_PATH), tp_findings, execution_telemetry=telemetry)
    quality = result["quality_and_reliability_metrics"]

    assert quality["reproduction_success_rate"] == 1.0
    assert quality["mean_evidence_completeness_pct"] == 100.0
    assert quality["execution_reliability"] == 1.0
    assert quality["wstg_executed_tests"] == 38
    assert quality["wstg_applicable_tests"] == 38
    assert quality["wstg_total_catalog_tests"] == 106
    # Executed / Applicable MUST be 100.0%
    assert quality["wstg_coverage_pct"] == 100.0
    # Executed / Catalog is 35.85%
    assert quality["wstg_catalog_coverage_pct"] == 35.85


# ==============================================================================
# 5. CLI Execution & End-to-End JSON Output Test
# ==============================================================================

def test_scorer_cli_execution():
    """Verify benchmark/score.py runs cleanly via CLI and outputs valid JSON."""
    cmd = [
        sys.executable,
        str(Path(__file__).parent.parent.parent / "benchmark" / "score.py"),
        "--ground-truth", str(GROUND_TRUTH_PATH),
        "--findings", str(FIXTURES_PATH)
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    assert proc.returncode == 0

    output_data = json.loads(proc.stdout)
    assert "benchmark_summary" in output_data
    assert "detection_metrics" in output_data
    assert "authoritative_bench_metrics" in output_data
    assert "quality_and_reliability_metrics" in output_data
    assert "breakdown" in output_data

    # Verify key counts in full synthetic dataset (15 TP + 2 FP secure + 1 FP unmatched + 1 Refuted = 19 items)
    summary = output_data["benchmark_summary"]
    assert summary["total_ground_truth_cases"] == 63
    assert summary["vulnerable_cases_count"] == 45
    assert summary["secure_cases_count"] == 18
    assert summary["total_findings_evaluated"] == 19

    metrics = output_data["detection_metrics"]
    assert metrics["true_positives"] == 15
    assert metrics["false_negatives"] == 30
    assert metrics["false_positives"] == 3  # 2 secure + 1 unlisted (refuted correctly ignored)
    assert metrics["secure_cases_false_positives"] == 2
    assert metrics["unlisted_findings_count"] == 1
    # Precision = 15 / (15 + 3) = 15 / 18 = 0.8333
    assert metrics["strict_precision"] == 0.8333
    assert metrics["adjudicated_precision"] == 0.8333
    # Recall = 15 / 45 = 0.3333
    assert metrics["recall"] == 0.3333
