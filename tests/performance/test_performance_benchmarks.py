"""Empirical Performance & Concurrency Benchmarks.

Asserts throughput and latency requirements across critical platform operations:
1. Scope Engine Evaluation Throughput (>= 2,000 evaluations/sec)
2. Finding Deduplication Signature Hashing (>= 10,000 signatures/sec)
3. Forensic Redactor Stream Scrubbing (>= 500 payloads/sec)
4. Vector PDF Report Generation Latency (< 2.0s per complete deliverable)
"""

import hashlib
import time
import uuid
import pytest

from packages.schemas.report import (
    FindingReportItem,
    ReportContext,
    WSTGCategoryReportItem
)
from services.evidence_engine.redactor import redact_raw_stream
from services.reporting_engine.renderer import ReportRenderer
from services.scope_engine.validator import ScopeValidator


def test_benchmark_scope_engine_throughput():
    """Benchmark ScopeValidator evaluation speed over 2,000 URL checks."""
    rules = [
        {"rule_type": "EXACT_DOMAIN", "target_type": "IN_SCOPE", "pattern": "api.bank.com"},
        {"rule_type": "DOMAIN_WILDCARD", "target_type": "IN_SCOPE", "pattern": "*.bank.com"},
        {"rule_type": "EXCLUDED_PATH", "target_type": "OUT_OF_SCOPE", "pattern": "/admin"},
        {"rule_type": "EXCLUDED_PATH", "target_type": "OUT_OF_SCOPE", "pattern": "/logout"}
    ]
    validator = ScopeValidator(rules)

    test_urls = [
        f"https://sub{i % 20}.bank.com/api/v1/resource/{i}" for i in range(2000)
    ]

    t0 = time.perf_counter()
    for url in test_urls:
        validator.is_in_scope(url)
    elapsed = time.perf_counter() - t0

    throughput = len(test_urls) / elapsed
    print(f"\n[BENCHMARK] Scope Engine: {throughput:.0f} evaluations/sec (Elapsed: {elapsed:.3f}s for 2,000 checks)")
    assert throughput >= 2000, f"Scope engine throughput too low: {throughput:.0f} ops/s"


def test_benchmark_deduplication_hashing():
    """Benchmark finding deduplication signature generation over 5,000 tuples."""
    project_id = str(uuid.uuid4())
    tuples = [
        (f"/api/v1/endpoint/{i % 50}", "GET" if i % 2 == 0 else "POST", f"param_{i % 10}", f"CWE-{i % 20}")
        for i in range(5000)
    ]

    t0 = time.perf_counter()
    for path, method, param, cwe in tuples:
        sig_raw = f"{project_id}|{path}|{method}|{param}|{cwe}".lower()
        hashlib.sha256(sig_raw.encode("utf-8")).hexdigest()
    elapsed = time.perf_counter() - t0

    throughput = len(tuples) / elapsed
    print(f"\n[BENCHMARK] Deduplication Hasher: {throughput:.0f} signatures/sec (Elapsed: {elapsed:.3f}s for 5,000 tuples)")
    assert throughput >= 10000, f"Hasher throughput too low: {throughput:.0f} hashes/s"


def test_benchmark_stream_redaction():
    """Benchmark sensitive data redactor scrubbing over 500 HTTP payloads."""
    sample = (
        "HTTP/1.1 200 OK\r\n"
        "Set-Cookie: sessionid=secret_session_token_12345; Secure\r\n"
        "Authorization: Bearer secret_bearer_token_abcdef1234567890\r\n"
        "\r\n"
        '{"user": "alice", "password": "PlainTextPassword987!", "token": "sensitive_jwt_token_here"}'
    )

    t0 = time.perf_counter()
    for _ in range(500):
        redact_raw_stream(sample)
    elapsed = time.perf_counter() - t0

    throughput = 500 / elapsed
    print(f"\n[BENCHMARK] Stream Redactor: {throughput:.0f} payloads/sec (Elapsed: {elapsed:.3f}s for 500 payloads)")
    assert throughput >= 500, f"Redactor throughput too low: {throughput:.0f} scrubs/s"


def test_benchmark_pdf_report_rendering(tmp_path):
    """Benchmark full PDF compilation time with 10 detailed findings."""
    renderer = ReportRenderer(output_dir=str(tmp_path))

    findings = [
        FindingReportItem(
            id=f"FIND-{i:03d}",
            title=f"Vulnerability Finding #{i}",
            severity="High" if i % 2 == 0 else "Medium",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            cwe_id="CWE-79",
            wstg_id="WSTG-INPV-01",
            endpoint_url=f"https://target.com/api/v1/test/{i}",
            http_method="POST",
            affected_parameter="input",
            description="Detailed technical description of simulated vulnerability.",
            business_impact="Operational impact description.",
            remediation_guidance="Sanitize inputs according to OWASP guidelines.",
            reproduction_curl=f"curl -i -s 'https://target.com/api/v1/test/{i}'",
            status="Confirmed",
            confidence="Confirmed"
        )
        for i in range(10)
    ]

    ctx = ReportContext(
        project_id=str(uuid.uuid4()),
        project_name="Performance Test Project",
        client_name="Acme Corp",
        target_scope=["target.com"],
        excluded_scope=[],
        start_date="2026-11-01",
        end_date="2026-11-09",
        lead_tester="Perf Benchmark Runner",
        classification="CONFIDENTIAL",
        generated_at="2026-11-09 12:00:00 UTC",
        report_title="Performance Benchmark Report",
        report_format="PDF",
        executive_narrative="Benchmark narrative testing PDF generation performance under finding volume.",
        risk_summary={"Critical": 0, "High": 5, "Medium": 5, "Low": 0, "Informational": 0},
        total_findings=10,
        critical_findings=0,
        high_findings=5,
        medium_findings=5,
        low_findings=0,
        info_findings=0,
        discovered_domains_count=1,
        discovered_endpoints_count=20,
        discovered_technologies=["FastAPI"],
        domains_sample=["target.com"],
        coverage_score=80.0,
        wstg_categories=[],
        findings=findings,
        include_raw_evidence=False,
        immediate_actions=["Harden endpoints"],
        near_term_actions=[],
        long_term_actions=[]
    )

    t0 = time.perf_counter()
    file_path, file_hash = renderer.render_pdf(ctx)
    elapsed = time.perf_counter() - t0

    print(f"\n[BENCHMARK] PDF Generation: {elapsed:.3f}s for 10 finding sheets (File: {file_path})")
    assert elapsed < 2.0, f"PDF generation took too long: {elapsed:.3f}s"
