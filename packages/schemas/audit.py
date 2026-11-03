"""Audit log API schemas."""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AuditLogResponse(BaseModel):
    """Audit log record response."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: Optional[uuid.UUID] = None
    user_id: Optional[uuid.UUID] = None
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    prev_hash: str
    hash: str
    created_at: datetime


class AuditLogQuery(BaseModel):
    """Filter criteria for audit logs."""
    project_id: Optional[uuid.UUID] = None
    user_id: Optional[uuid.UUID] = None
    action: Optional[str] = None
    resource_type: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class AuditVerificationResponse(BaseModel):
    """Response verifying the cryptographic integrity of the audit log chain."""
    is_valid: bool
    total_records: int
    broken_index: Optional[int] = None
    reason: Optional[str] = None
    first_hash: Optional[str] = None
    last_hash: Optional[str] = None

