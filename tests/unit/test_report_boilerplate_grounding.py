"""Regression test for DEFECT-REP-02: Ground PTES report template boilerplate in truthful runtime tooling."""

import os
import uuid
import pytest
from packages.schemas.report import ReportContext, FindingReportItem, WSTGCategoryReportItem
from services.reporting_engine.renderer import ReportRenderer


@pytest.fixture
def minimal_report_context() -> ReportContext:
    return ReportContext(
        project_id=str(uuid.uuid4()),
        project_name="Grounded Boilerplate Verification",
        client_name="Lab Verification Client",
        target_scope=["api.target.lab"],
        excluded_scope=[],
        start_date="2026-11-20",
        end_date="2026-11-25",
        lead_tester="Auditor",
        classification="CONFIDENTIAL",
        generated_at="2026-11-25 12:00:00 UTC",
        report_title="PTES Security Report",
        report_format="HTML",
        executive_narrative="Testing completed with truthful capability disclosures.",
        risk_summary={"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0},
        total_findings=0,
        critical_findings=0,
        high_findings=0,
        medium_findings=0,
        low_findings=0,
        info_findings=0,
        discovered_domains_count=1,
        discovered_endpoints_count=5,
        discovered_technologies=["Python/3.12", "FastAPI"],
        domains_sample=["api.target.lab"],
        coverage_score=85.0,
        wstg_categories=[],
        findings=[],
        candidate_findings=[],
        include_raw_evidence=False,
        immediate_actions=[],
        near_term_actions=[],
        long_term_actions=[]
    )


def test_html_report_does_not_contain_ungrounded_capability_claims(tmp_path, minimal_report_context):
    """Verify rendered PTES HTML report contains ZERO ungrounded boilerplate claims."""
    renderer = ReportRenderer(output_dir=str(tmp_path))
    file_path, _ = renderer.render_html(minimal_report_context)

    with open(file_path, "r", encoding="utf-8") as f:
        html_content = f.read()

    prohibited_claims = [
        "Layer 2 kernel/proxy egress enforcement prevented out-of-scope transmissions",
        "Katana (headless crawler)",
        "Httpx (probing)",
        "governed by LangGraph",
        "katana",
        "langgraph",
        "layer 2"
    ]

    html_lower = html_content.lower()
    offending_claims = [claim for claim in prohibited_claims if claim.lower() in html_lower]

    assert len(offending_claims) == 0, f"Found ungrounded capability claims in rendered HTML: {offending_claims}"
