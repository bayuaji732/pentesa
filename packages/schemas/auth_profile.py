"""Authentication profile schemas."""

import uuid
from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field


class AuthProfileBase(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    auth_type: str = Field(default="BEARER", description="BEARER, BASIC, API_KEY, COOKIE, HEADER, CUSTOM")
    headers: Dict[str, str] = Field(default_factory=dict, description="Non-sensitive headers")
    is_active: bool = Field(default=True)
    description: Optional[str] = Field(default=None, max_length=1000)


class AuthProfileCreate(AuthProfileBase):
    """Payload to create an authentication profile. Credentials are encrypted at rest with AES-256-GCM."""
    credentials: Dict[str, Any] = Field(
        description="Key-value credentials (e.g. token, password, api_key) to encrypt at rest"
    )


class AuthProfileUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=100)
    auth_type: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    is_active: Optional[bool] = None
    description: Optional[str] = None
    credentials: Optional[Dict[str, Any]] = None


class AuthProfileResponse(AuthProfileBase):
    """Safe response model. Raw credentials are never exposed in plaintext."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    masked_credentials: Dict[str, str] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
