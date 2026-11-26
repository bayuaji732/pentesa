"""Authentication and authorization token schemas."""

from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    """Credentials payload for login."""
    email: EmailStr
    password: str = Field(min_length=1)


class TokenResponse(BaseModel):
    """JWT response structure."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshTokenRequest(BaseModel):
    """Request payload to renew access token."""
    refresh_token: str


class TokenPayload(BaseModel):
    """Decoded JWT payload structure."""
    sub: str
    role: str
    type: str
    exp: int
    iat: int
    email: Optional[str] = None


class ChangePasswordRequest(BaseModel):
    """Request payload for self-service password change."""
    current_password: str = Field(min_length=1, description="Current password for verification")
    new_password: str = Field(min_length=12, description="New password meeting security requirements")
    new_password_confirm: str = Field(min_length=12, description="Confirmation of new password")


class MessageResponse(BaseModel):
    """Standard message response."""
    message: str

