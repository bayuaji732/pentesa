"""Pydantic schemas for Findings, Evidence, Reproductions, and False Positives."""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class FindingEvidenceCreate(BaseModel):
    """Payload to attach forensic evidence to a finding."""
    raw_request: str = Field(..., description="Raw HTTP request stream")
    raw_response: str = Field(..., description="Raw HTTP response stream")
    reproduction_curl: Optional[str] = Field(None, description="Optional pre-generated curl command")
    screenshot_path: Optional[str] = None


class FindingEvidenceResponse(BaseModel):
    """Forensic evidence details including cryptographic SHA-256 digests."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    raw_request: str
    raw_response: str
    reproduction_curl: str
    request_hash_sha256: str
    response_hash_sha256: str
    screenshot_path: Optional[str] = None
    captured_at: datetime


class FindingReproductionCreate(BaseModel):
    """Payload to trigger or record a reproduction run."""
    reproduced_by: str = Field(default="MANUAL", description="Tester user ID or Agent ID")


class FindingReproductionResponse(BaseModel):
    """Reproduction verification outcome."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    reproduced_by: str
    success: bool
    response_status_code: Optional[int] = None
    duration_ms: Optional[int] = None
    created_at: datetime


class FalsePositiveCreate(BaseModel):
    """Payload to refute a candidate finding as a false positive."""
    classification: str = Field(
        ...,
        description="Reason: STATIC_PAGE_REFLECTION, WAF_BLOCK_PAGE, CUSTOM_ERROR_PAGE, EXPECTED_BEHAVIOR"
    )
    justification: str = Field(..., min_length=10, description="Mandatory detailed justification")


class FalsePositiveResponse(BaseModel):
    """Documented false positive refutation record."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    classification: str
    justification: str
    created_at: datetime


class FindingStatusUpdate(BaseModel):
    """Payload to transition finding status."""
    status: str = Field(
        ...,
        description="Detected, Triaged, Validating, Confirmed, False Positive, Needs Manual Review, Remediated, Retested, Accepted Risk"
    )
    justification: str = Field(..., min_length=5, description="Auditable justification for transition")


class FindingCreate(BaseModel):
    """Payload to create a new security finding."""
    title: str = Field(..., min_length=3, max_length=255)
    description: str = Field(..., min_length=10)
    severity: str = Field(
        ...,
        description="Critical, High, Medium, Low, Informational"
    )
    status: str = Field(default="Detected")
    confidence: str = Field(default="Medium")
    endpoint_id: Optional[uuid.UUID] = None
    wstg_id: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    affected_parameter: Optional[str] = None
    detection_source: str = Field(default="manual")
    remediation_guidance: Optional[str] = None
    business_impact: Optional[str] = None
    raw_request: Optional[str] = None
    raw_response: Optional[str] = None
    reproduction_curl: Optional[str] = None
    is_simulated: Optional[bool] = Field(default=None, description="Tag finding as mock/simulated")


class FindingBatchUpdate(BaseModel):
    """Payload to perform batch status transition across multiple findings."""
    finding_ids: List[uuid.UUID] = Field(..., min_length=1, description="List of finding UUIDs to update")
    status: str = Field(..., description="Target status for all specified findings")
    justification: str = Field(..., min_length=5, description="Auditable justification for batch triage")


class FindingRetestRequest(BaseModel):
    """Payload to trigger an empirical retest on an existing finding."""
    verification_payload: Optional[str] = Field(None, description="Optional custom payload override for retest")
    expected_status_code: Optional[int] = Field(None, description="Expected status code indicating fixed behavior")


class FindingRetestResponse(BaseModel):
    """Outcome of a finding retest execution."""
    finding_id: uuid.UUID
    previous_status: str
    new_status: str
    is_remediated: bool
    reproduction_success: bool
    http_status_code: Optional[int] = None
    verification_notes: str
    tested_at: datetime


class FindingResponse(BaseModel):
    """Detailed finding representation with forensic evidence."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    endpoint_id: Optional[uuid.UUID] = None
    wstg_id: Optional[str] = None
    title: str
    description: str
    severity: str
    status: str
    confidence: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    affected_parameter: Optional[str] = None
    detection_source: str
    remediation_guidance: Optional[str] = None
    business_impact: Optional[str] = None
    is_simulated: bool = False
    created_at: datetime
    updated_at: datetime
    evidence: List[FindingEvidenceResponse] = Field(default_factory=list)

