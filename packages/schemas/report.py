"""Pydantic schemas for PTES Report Generation, Templates, and Verification."""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


class ReportGenerateRequest(BaseModel):
    """Payload to trigger report compilation and export."""
    format: Literal["PDF", "HTML"] = Field(
        default="PDF",
        description="Target export format: PDF or HTML"
    )
    template_name: str = Field(
        default="ptes_standard",
        description="Template style: ptes_standard, executive_summary, developer_remediation, wstg_compliance"
    )
    title: Optional[str] = Field(
        default=None,
        description="Optional custom title for the report"
    )
    include_raw_evidence: bool = Field(
        default=True,
        description="Include raw HTTP request/response forensic bytes and SHA-256 hashes"
    )
    severity_filter: Optional[List[str]] = Field(
        default=None,
        description="Filter findings to include only specified severities (e.g. ['Critical', 'High'])"
    )
    section_toggles: Optional[Dict[str, bool]] = Field(
        default=None,
        description="Toggle specific report sections on or off"
    )
    executive_summary_override: Optional[str] = Field(
        default=None,
        description="Custom executive narrative overriding automatic synthesis"
    )
    client_logo_url: Optional[str] = Field(
        default=None,
        description="Optional URL or path to client logo for the cover page"
    )


class ReportResponse(BaseModel):
    """Metadata of a compiled and finalized penetration test report."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    title: str
    format: str
    file_path: str
    file_hash_sha256: str
    is_finalized: bool
    generated_by: Optional[uuid.UUID] = None
    report_metadata: Optional[Dict[str, Any]] = None
    created_at: datetime
    download_url: Optional[str] = None


class ReportTemplateResponse(BaseModel):
    """Report template metadata."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: Optional[str] = None
    is_default: bool
    created_at: datetime


class ReportVerificationRequest(BaseModel):
    """Hash or file payload for authenticity verification."""
    file_hash_sha256: str = Field(..., min_length=64, max_length=64, description="SHA-256 checksum of report file")


class ReportVerificationResponse(BaseModel):
    """Outcome of cryptographic report authenticity verification."""
    verified: bool
    report_id: Optional[uuid.UUID] = None
    project_id: Optional[uuid.UUID] = None
    project_name: Optional[str] = None
    title: Optional[str] = None
    file_format: Optional[str] = None
    generated_at: Optional[datetime] = None
    message: str


class WSTGCategoryReportItem(BaseModel):
    """WSTG category metrics in the report context."""
    code: str
    name: str
    total_tests: int
    executed_tests: int
    passed_tests: int
    failed_tests: int
    coverage_percentage: float


class FindingReportItem(BaseModel):
    """Finding detail formatted for PTES report inclusion."""
    id: str
    title: str
    severity: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    wstg_id: Optional[str] = None
    owasp_category: Optional[str] = None
    endpoint_url: str
    http_method: str
    affected_parameter: Optional[str] = None
    description: str
    business_impact: Optional[str] = None
    remediation_guidance: Optional[str] = None
    reproduction_curl: Optional[str] = None
    raw_request: Optional[str] = None
    raw_response: Optional[str] = None
    request_hash_sha256: Optional[str] = None
    response_hash_sha256: Optional[str] = None
    screenshot_path: Optional[str] = None
    status: str
    confidence: str


class ReportContext(BaseModel):
    """Strongly-typed data context passed to Jinja2 rendering pipeline."""
    project_id: str
    project_name: str
    client_name: str
    target_scope: List[str]
    excluded_scope: List[str]
    start_date: str
    end_date: str
    lead_tester: str
    classification: str = "STRICTLY CONFIDENTIAL"
    generated_at: str
    report_title: str
    report_format: str

    # Executive Summary & Risk Posture
    executive_narrative: str
    risk_summary: Dict[str, int]
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int

    # Attack Surface
    discovered_domains_count: int
    discovered_endpoints_count: int
    discovered_technologies: List[str]
    domains_sample: List[str]

    # WSTG Coverage
    coverage_score: float
    wstg_categories: List[WSTGCategoryReportItem]

    # Findings & Evidence
    findings: List[FindingReportItem]
    include_raw_evidence: bool = True

    # Roadmap
    immediate_actions: List[str]
    near_term_actions: List[str]
    long_term_actions: List[str]

    # Metadata & Checksums
    report_sha256: Optional[str] = None

