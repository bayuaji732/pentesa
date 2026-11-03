"""Project management and membership schemas."""

import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from packages.schemas.user import UserResponse


class ProjectStatus(str, Enum):
    """Lifecycle status of a penetration testing project."""
    PLANNING = "PLANNING"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    ARCHIVED = "ARCHIVED"


class ProjectRole(str, Enum):
    """Project-level access control role."""
    LEAD = "LEAD"
    TESTER = "TESTER"
    VIEWER = "VIEWER"


class ProjectBase(BaseModel):
    """Core project fields."""
    name: str = Field(min_length=2, max_length=150)
    description: Optional[str] = Field(default=None, max_length=2000)
    target_domains: List[str] = Field(default_factory=list, description="Primary root domains in scope")
    allowed_cidrs: List[str] = Field(default_factory=list, description="Allowed IP/CIDR ranges")
    excluded_paths: List[str] = Field(default_factory=list, description="Endpoints or path prefixes excluded from testing")
    allow_internal_networks: bool = Field(default=False, description="Explicit authorization for RFC 1918 internal targets")
    authorization_document_ref: Optional[str] = Field(default=None, description="Signed RoE / Authorization document reference")
    authorization_start: datetime = Field(description="Start time of testing authorization")
    authorization_end: datetime = Field(description="End time of testing authorization")


class ProjectCreate(ProjectBase):
    """Payload to create a new penetration testing project."""
    pass


class ProjectUpdate(BaseModel):
    """Payload to update an existing project."""
    name: Optional[str] = Field(default=None, min_length=2, max_length=150)
    description: Optional[str] = None
    status: Optional[ProjectStatus] = None
    target_domains: Optional[List[str]] = None
    allowed_cidrs: Optional[List[str]] = None
    excluded_paths: Optional[List[str]] = None
    allow_internal_networks: Optional[bool] = None
    authorization_document_ref: Optional[str] = None
    authorization_start: Optional[datetime] = None
    authorization_end: Optional[datetime] = None


class ProjectMemberCreate(BaseModel):
    """Add a member to a project."""
    user_id: uuid.UUID
    role: ProjectRole = ProjectRole.TESTER


class ProjectMemberResponse(BaseModel):
    """Project membership representation."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    user_id: uuid.UUID
    role: ProjectRole
    user: Optional[UserResponse] = None
    created_at: datetime


class ProjectResponse(ProjectBase):
    """Detailed project representation."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    status: ProjectStatus
    created_by: uuid.UUID
    created_at: datetime
    updated_at: datetime
    members: List[ProjectMemberResponse] = Field(default_factory=list)
