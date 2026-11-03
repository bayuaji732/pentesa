"""User schemas and role definitions."""

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserRole(str, Enum):
    """System-wide role-based access control roles."""
    ADMIN = "ADMIN"
    LEAD = "LEAD"
    TESTER = "TESTER"
    VIEWER = "VIEWER"


class UserBase(BaseModel):
    """Base user fields."""
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=120)
    role: UserRole = UserRole.TESTER
    is_active: bool = True


class UserCreate(UserBase):
    """Payload to register or create a new user."""
    password: str = Field(min_length=8, max_length=128)


class UserUpdate(BaseModel):
    """Payload to update user metadata or role."""
    full_name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


class UserPasswordUpdate(BaseModel):
    """Payload for changing password."""
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


class UserResponse(UserBase):
    """Public user response representation."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    updated_at: datetime
