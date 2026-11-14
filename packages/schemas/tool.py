"""Pydantic schemas for Security Tool Execution and Raw HTTP Testing."""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ToolInfoResponse(BaseModel):
    """Metadata for an integrated security CLI tool."""
    name: str
    description: str
    installed: bool
    version: Optional[str] = None
    binary_path: Optional[str] = None


class ToolExecutionRequest(BaseModel):
    """Request payload to dispatch a tool run."""
    tool_name: str = Field(..., description="nuclei, ffuf, katana, httpx, etc.")
    target_url: str = Field(..., description="Target URL or endpoint within project scope")
    tags: Optional[List[str]] = Field(default=None, description="Nuclei template tags, e.g. cve, exposure")
    severity: Optional[List[str]] = Field(default=None, description="Nuclei severities, e.g. medium, high, critical")
    template_path: Optional[str] = Field(default=None, description="Path to specific Nuclei template")
    wordlist: Optional[str] = Field(default=None, description="Wordlist identifier for ffuf")
    rate_limit: int = Field(default=20, ge=1, le=100, description="Max requests per second")
    timeout_seconds: int = Field(default=300, ge=10, le=1800, description="Overall subprocess execution timeout in seconds")
    request_timeout: Optional[int] = Field(default=5, ge=1, le=30, description="Per-probe HTTP request timeout in seconds")


class ToolExecutionResponse(BaseModel):
    """Result and metadata of a tool execution run."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    tool_name: str
    target_url: str
    argv: List[str] = Field(default_factory=list)
    status: str
    duration_ms: Optional[int] = None
    exit_code: Optional[int] = None
    stdout_summary: Optional[str] = None
    stderr_summary: Optional[str] = None
    findings_count: int = 0
    created_at: datetime

    @field_validator("argv", mode="before")
    @classmethod
    def sanitize_argv(cls, v: Any) -> List[str]:
        if isinstance(v, list):
            return [str(x) for x in v if x is not None]
        return []


class ToolConfigUpdate(BaseModel):
    """Update custom tool configuration for a project."""
    tool_name: str
    config: Dict[str, Any]


class HttpTestRequest(BaseModel):
    """Request payload for raw HTTP testing and mutation."""
    url: str = Field(..., description="Target URL")
    method: str = Field(default="GET", description="HTTP Method: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD")
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    follow_redirects: bool = False
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)


class HttpTestResponse(BaseModel):
    """Forensic result of a raw HTTP test invocation."""
    status_code: int
    headers: Dict[str, str]
    body: str
    duration_ms: int
    raw_request: str
    raw_response: str
    request_hash_sha256: str
    response_hash_sha256: str
    reproduction_curl: str
    redirect_note: Optional[str] = None

