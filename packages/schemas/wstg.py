"""Pydantic schemas for OWASP WSTG catalog, test instances, coverage metrics, and executions."""

import uuid
from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class WSTGCatalogItemResponse(BaseModel):
    """Schema for an OWASP WSTG v4.2 master catalog entry."""
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="WSTG test ID, e.g. WSTG-INPV-05")
    category: str = Field(..., description="Category title, e.g. Input Validation")
    category_code: str = Field(..., description="Category code prefix, e.g. WSTG-INPV")
    name: str = Field(..., description="Test name")
    description: str = Field(..., description="Detailed methodology description")
    automation_capability: str = Field(..., description="Full, Partial, or Manual")
    default_risk: str = Field(..., description="Critical, High, Medium, Low, or Info")
    cwe_id: Optional[str] = Field(None, description="Mapped CWE identifier, e.g. CWE-89")
    owasp_category: Optional[str] = Field(None, description="OWASP Top 10:2021 mapping")
    required_tools: List[str] = Field(default_factory=list, description="Recommended security testing tools")
    requires_human_review: bool = Field(False, description="Whether test needs human review for logic verification")
    endpoint_types: List[str] = Field(default_factory=list, description="Endpoint criteria (e.g. PARAMETERIZED, API, AUTH)")


class WSTGTestInstanceResponse(BaseModel):
    """Schema for a project-specific WSTG test case instance."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    wstg_id: str
    category: str
    category_code: str = ""
    name: str
    description: str = ""
    status: str
    applicable: bool = True
    notes: Optional[str] = None
    justification: Optional[str] = None
    applicable_endpoints_count: int = 0
    execution_count: int = 0
    findings_count: int = 0
    automation_capability: str = "Full"
    default_risk: str = "Medium"
    updated_at: datetime


class WSTGTestInstanceUpdate(BaseModel):
    """Schema for updating a test instance status, notes, or justification."""
    status: Optional[str] = Field(
        None,
        description="New status: Not Started, Planned, Running, Passed, Failed, Needs Manual Review, Not Applicable, Blocked, Error"
    )
    notes: Optional[str] = Field(None, description="Tester or agent execution notes")
    justification: Optional[str] = Field(None, description="Mandatory justification when marking Not Applicable or overriding")


class CoverageCategoryMetrics(BaseModel):
    """Metrics breakdown for a single WSTG category."""
    category_code: str
    category_name: str
    total_tests: int
    passed_count: int
    failed_count: int
    needs_review_count: int
    not_applicable_count: int
    planned_count: int
    running_count: int
    not_started_count: int
    coverage_pct: float
    health_score: float
    executed_coverage_pct: float = 0.0


class WSTGCoverageReport(BaseModel):
    """Empirical mathematical coverage report for a project."""
    project_id: uuid.UUID
    overall_coverage_pct: float
    testing_health_score: float
    executed_coverage_pct: float = 0.0
    total_catalog_tests: int
    in_scope_tests_count: int
    applicable_tests_count: int = 0
    passed_count: int
    failed_count: int
    needs_review_count: int
    not_applicable_count: int
    planned_count: int
    running_count: int
    not_started_count: int
    categories: Dict[str, CoverageCategoryMetrics]
    generated_at: datetime


class TestExecutionCreate(BaseModel):
    """Schema to dispatch a WSTG test execution."""
    wstg_id: str = Field(..., description="WSTG test ID to execute")
    endpoint_id: Optional[uuid.UUID] = Field(None, description="Specific target endpoint, or None for domain/host test")
    runner_type: str = Field("AUTOMATED", description="AUTOMATED, AGENT, or MANUAL")


class TestExecutionResponse(BaseModel):
    """Schema for a test execution record."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    wstg_instance_id: uuid.UUID
    wstg_id: str
    endpoint_id: Optional[uuid.UUID] = None
    status: str
    runner_type: str
    start_time: datetime
    end_time: Optional[datetime] = None
    exit_code: Optional[int] = None
    summary: Optional[str] = None


class TestExecutionLogResponse(BaseModel):
    """Schema for an execution log entry."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    execution_id: uuid.UUID
    log_level: str
    message: str
    created_at: datetime


class TestPlanRecalculateResponse(BaseModel):
    """Schema returned after recalculating test plan applicability."""
    project_id: uuid.UUID
    total_instances: int
    planned_count: int
    not_applicable_count: int
    failed_count: int = 0
    endpoints_analyzed: int = 0
    summary: str

