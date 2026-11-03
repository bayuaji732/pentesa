"""Pentesa security primitives: password hashing, JWT management, and constant-time checks."""

import hmac
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
import bcrypt
import jwt

from packages.common.config import settings
from packages.common.exceptions import AuthenticationError


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt with salt."""
    salt = bcrypt.gensalt(rounds=12)
    pwd_bytes = password.encode("utf-8")
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash in constant time."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def create_access_token(
    subject: str,
    claims: Optional[Dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create a signed JWT access token."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.access_token_expire_minutes)

    payload: Dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": expire,
        "type": "access"
    }
    if claims:
        payload.update(claims)

    encoded_jwt = jwt.encode(
        payload,
        settings.secret_key,
        algorithm=settings.jwt_algorithm
    )
    return encoded_jwt


def create_refresh_token(
    subject: str,
    claims: Optional[Dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create a signed JWT refresh token."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(days=settings.refresh_token_expire_days)

    payload: Dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": expire,
        "type": "refresh"
    }
    if claims:
        payload.update(claims)

    encoded_jwt = jwt.encode(
        payload,
        settings.secret_key,
        algorithm=settings.jwt_algorithm
    )
    return encoded_jwt


def verify_token(token: str, expected_type: str = "access") -> Dict[str, Any]:
    """Verify and decode a JWT token, raising AuthenticationError on failure."""
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm]
        )
        if payload.get("type") != expected_type:
            raise AuthenticationError(f"Invalid token type: expected {expected_type}")
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthenticationError("Token has expired")
    except jwt.InvalidTokenError as exc:
        raise AuthenticationError(f"Invalid token: {str(exc)}")


def constant_time_compare(val1: str, val2: str) -> bool:
    """Compare two strings in constant time to prevent timing side-channel attacks."""
    return hmac.compare_digest(val1.encode("utf-8"), val2.encode("utf-8"))
