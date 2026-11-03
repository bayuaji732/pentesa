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

