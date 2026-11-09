"""Report context builder querying database entities and formatting for Jinja2 templates."""

import datetime
import uuid
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from database.models.discovery import DiscoveredDomain, Endpoint, Technology
from database.models.finding import Finding, FindingEvidence
from database.models.project import Project, ProjectMember
from database.models.scope import ScopeRule
from database.models.user import User
from database.models.wstg import WSTGTestCatalog, WSTGTestInstance
from packages.common.exceptions import ResourceNotFoundError
from packages.schemas.report import (
    FindingReportItem,
    ReportContext,
    ReportGenerateRequest,
    WSTGCategoryReportItem
)
from services.execution_engine.coverage import WSTGCoverageService


async def build_report_context(
    session: AsyncSession,
    project_id: uuid.UUID,
    options: ReportGenerateRequest,
    user: Optional[User] = None
) -> ReportContext:
    """Compile exhaustive 17-section PTES reporting context for a given project."""

    # 1. Fetch Project & Members
    proj_stmt = (
        select(Project)
        .options(selectinload(Project.members).selectinload(ProjectMember.user))
        .where(Project.id == project_id)
    )
    project = (await session.execute(proj_stmt)).scalar_one_or_none()
    if not project:
        raise ResourceNotFoundError(f"Project {project_id} not found.")

    lead_tester = user.full_name if user and user.full_name else (user.email if user else "Lead Penetration Tester")

    # 2. Fetch Scope Rules
    scope_stmt = select(ScopeRule).where(ScopeRule.project_id == project_id)
    scope_rules = list((await session.execute(scope_stmt)).scalars().all())
    target_scope = [
        r.pattern for r in scope_rules
        if getattr(r, "target_type", "") == "IN_SCOPE" or getattr(r, "rule_type", "") == "INCLUDE"
    ]
    excluded_scope = [
        r.pattern for r in scope_rules
        if getattr(r, "target_type", "") == "OUT_OF_SCOPE" or getattr(r, "rule_type", "") == "EXCLUDE"
    ]
    if not target_scope:
        # Fallback to target_domains on Project if defined
        if project.target_domains:
            target_scope = list(project.target_domains)
        else:
            target_scope = ["Authorized application endpoints & subdomains"]

    # 3. Fetch Attack Surface (Domains, Endpoints, Technologies)
    domains_stmt = select(DiscoveredDomain).where(DiscoveredDomain.project_id == project_id)
    domains = list((await session.execute(domains_stmt)).scalars().all())
    domains_sample = [d.domain for d in domains[:10]]

    endpoints_stmt = select(Endpoint).where(Endpoint.project_id == project_id)
    endpoints = list((await session.execute(endpoints_stmt)).scalars().all())

    tech_stmt = select(Technology).where(Technology.project_id == project_id)
    techs = list((await session.execute(tech_stmt)).scalars().all())
    tech_names = sorted(list({f"{t.name} ({t.version})" if t.version else t.name for t in techs}))

    # 4. Fetch WSTG Coverage & Category Breakdown
    coverage_score = 0.0
    wstg_categories: List[WSTGCategoryReportItem] = []
    try:
        coverage_service = WSTGCoverageService(session)
        coverage_report = await coverage_service.calculate_project_coverage(project_id)
        coverage_score = coverage_report.overall_coverage_pct

        cats = coverage_report.categories.values() if isinstance(coverage_report.categories, dict) else coverage_report.categories
        for cat in cats:
            executed = cat.passed_count + cat.failed_count + cat.needs_review_count + cat.not_applicable_count
            wstg_categories.append(
                WSTGCategoryReportItem(
                    code=cat.category_code,
                    name=cat.category_name,
                    total_tests=cat.total_tests,
                    executed_tests=executed,
                    passed_tests=cat.passed_count,
                    failed_tests=cat.failed_count,
                    coverage_percentage=cat.coverage_pct
                )
            )
    except Exception:
        pass

    # 5. Fetch Findings & Filter
    findings_stmt = (
        select(Finding)
        .options(
            selectinload(Finding.evidence),
            selectinload(Finding.endpoint)
        )
        .where(
            Finding.project_id == project_id,
            Finding.status != "False Positive"  # Suppress false positives from client report
        )
    )

    if options.severity_filter:
        findings_stmt = findings_stmt.where(Finding.severity.in_(options.severity_filter))

    findings_stmt = findings_stmt.order_by(
        desc(Finding.cvss_score),
        desc(Finding.created_at)
    )
    findings_raw = list((await session.execute(findings_stmt)).scalars().all())

    # Calculate Risk Counts
    risk_summary = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0
    }
    for f in findings_raw:
        sev = f.severity.capitalize() if f.severity else "Informational"
        if sev in risk_summary:
            risk_summary[sev] += 1
        else:
            risk_summary["Informational"] += 1

    # Convert Findings to Report Items
    finding_items: List[FindingReportItem] = []
    for f in findings_raw:
        primary_evidence: Optional[FindingEvidence] = f.evidence[0] if f.evidence else None

        ep_url = f.endpoint.url if f.endpoint and hasattr(f.endpoint, "url") else (
            f"https://{f.endpoint.fqdn}{f.endpoint.url_path}" if f.endpoint else "Target Host"
        )
        ep_method = f.endpoint.http_method if f.endpoint else "GET"

        finding_items.append(
            FindingReportItem(
                id=f"FIND-{str(f.id)[:8].upper()}",
                title=f.title,
                severity=f.severity,
                cvss_score=float(f.cvss_score) if f.cvss_score is not None else None,
                cvss_vector=f.cvss_vector,
                cwe_id=f.cwe_id or "CWE-Unknown",
                wstg_id=f.wstg_id or "WSTG-GENERIC",
                owasp_category=f.owasp_category or "OWASP Top 10",
                endpoint_url=ep_url,
                http_method=ep_method,
                affected_parameter=f.affected_parameter,
                description=f.description,
                business_impact=f.business_impact or "Unauthorized access or system manipulation.",
                remediation_guidance=f.remediation_guidance or "Apply secure input validation and access controls.",
                reproduction_curl=primary_evidence.reproduction_curl if primary_evidence else None,
                raw_request=primary_evidence.raw_request if (primary_evidence and options.include_raw_evidence) else None,
                raw_response=primary_evidence.raw_response if (primary_evidence and options.include_raw_evidence) else None,
                request_hash_sha256=primary_evidence.request_hash_sha256 if primary_evidence else None,
                response_hash_sha256=primary_evidence.response_hash_sha256 if primary_evidence else None,
                screenshot_path=primary_evidence.screenshot_path if primary_evidence else None,
                status=f.status,
                confidence=f.confidence
            )
        )

    # 6. Executive Narrative
    if options.executive_summary_override:
        executive_narrative = options.executive_summary_override
    else:
        crit_count = risk_summary["Critical"]
        high_count = risk_summary["High"]
        total = len(finding_items)
        if crit_count > 0:
            posture_assessment = f"The assessment revealed a HIGH RISK posture with {crit_count} Critical and {high_count} High severity vulnerabilities that require immediate remediation to prevent unauthorized system compromise."
        elif high_count > 0:
            posture_assessment = f"The assessment revealed an ELEVATED RISK posture with {high_count} High severity findings that require prioritized engineering attention."
        elif total > 0:
            posture_assessment = f"The assessment revealed a MODERATE RISK posture with {total} total findings, primarily consisting of medium and low severity defense-in-depth opportunities."
        else:
            posture_assessment = "The assessment revealed a STRONG SECURITY POSTURE with zero confirmed high-severity vulnerabilities across the tested target scope."

        executive_narrative = (
            f"During the penetration testing window, Pentesa conducted an automated and assisted assessment "
            f"of '{project.name}' strictly adhering to the OWASP Web Security Testing Guide (WSTG v4.2) and "
            f"Penetration Testing Execution Standard (PTES). {posture_assessment} A total of {len(endpoints)} "
            f"endpoints were mapped across {len(domains)} hostnames, achieving an overall WSTG testing coverage score of {coverage_score:.1f}%."
        )

    # 7. Remediation Roadmap Suggestions
    immediate_actions = []
    near_term_actions = []
    long_term_actions = []

    for item in finding_items:
        if item.severity in ["Critical", "High"]:
            immediate_actions.append(f"Remediate {item.title} on {item.endpoint_url} ({item.cwe_id})")
        elif item.severity == "Medium":
            near_term_actions.append(f"Resolve {item.title} ({item.cwe_id})")
        else:
            long_term_actions.append(f"Harden {item.title}")

    if not immediate_actions:
        immediate_actions.append("Maintain continuous integration security unit testing and automated dependency scanning.")
    if not near_term_actions:
        near_term_actions.append("Implement centralized security header and Content-Security-Policy enforcement.")
    if not long_term_actions:
        long_term_actions.append("Perform quarterly recurring automated penetration tests.")

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    start_dt = project.authorization_start or project.created_at
    end_dt = project.authorization_end or now_utc

    return ReportContext(
        project_id=str(project.id),
        project_name=project.name,
        client_name=getattr(project, "client_name", None) or project.name,
        target_scope=target_scope,
        excluded_scope=excluded_scope,
        start_date=start_dt.strftime("%Y-%m-%d"),
        end_date=end_dt.strftime("%Y-%m-%d"),
        lead_tester=lead_tester,
        classification="STRICTLY CONFIDENTIAL",
        generated_at=now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        report_title=options.title or f"Penetration Testing Execution Standard (PTES) Report — {project.name}",
        report_format=options.format,
        executive_narrative=executive_narrative,
        risk_summary=risk_summary,
        total_findings=len(finding_items),
        critical_findings=risk_summary["Critical"],
        high_findings=risk_summary["High"],
        medium_findings=risk_summary["Medium"],
        low_findings=risk_summary["Low"],
        info_findings=risk_summary["Informational"],
        discovered_domains_count=len(domains),
        discovered_endpoints_count=len(endpoints),
        discovered_technologies=tech_names,
        domains_sample=domains_sample,
        coverage_score=coverage_score,
        wstg_categories=wstg_categories,
        findings=finding_items,
        include_raw_evidence=options.include_raw_evidence,
        immediate_actions=immediate_actions[:5],
        near_term_actions=near_term_actions[:5],
        long_term_actions=long_term_actions[:5],
        report_sha256=None
    )
