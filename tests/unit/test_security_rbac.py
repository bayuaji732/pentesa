"""Unit tests for security primitives, JWT tokens, and RBAC."""

from datetime import timedelta
import pytest

from packages.common.exceptions import AuthenticationError
from packages.common.security import (
    constant_time_compare,
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
    verify_token
)
from packages.schemas.user import UserRole


def test_password_hashing():
    """Verify bcrypt salt uniqueness and verification."""
    pwd = "CorrectHorseBatteryStaple123!"
    h1 = hash_password(pwd)
    h2 = hash_password(pwd)

    # Salt ensures different hashes for the same password
    assert h1 != h2
    assert verify_password(pwd, h1) is True
    assert verify_password(pwd, h2) is True
    assert verify_password("WrongPassword123!", h1) is False


def test_jwt_access_and_refresh_tokens():
    """Verify access and refresh token lifecycle and type validation."""
    sub = "user-12345"
    claims = {"role": UserRole.TESTER.value, "email": "tester@pentesa.local"}

    access_tok = create_access_token(subject=sub, claims=claims)
    refresh_tok = create_refresh_token(subject=sub, claims=claims)

    # Valid access token
    payload = verify_token(access_tok, expected_type="access")
    assert payload["sub"] == sub
    assert payload["role"] == "TESTER"
    assert payload["type"] == "access"

    # Valid refresh token
    r_payload = verify_token(refresh_tok, expected_type="refresh")
    assert r_payload["sub"] == sub
    assert r_payload["type"] == "refresh"

    # Type mismatch: cannot use refresh token where access token is expected
    with pytest.raises(AuthenticationError) as exc_info:
        verify_token(refresh_tok, expected_type="access")
    assert "Invalid token type" in str(exc_info.value)


def test_jwt_expired_token():
    """Verify expired token raises AuthenticationError."""
    sub = "user-12345"
    # Create expired token (-1 minute)
    expired_tok = create_access_token(
        subject=sub,
        expires_delta=timedelta(minutes=-1)
    )

    with pytest.raises(AuthenticationError) as exc_info:
        verify_token(expired_tok, expected_type="access")
    assert "Token has expired" in str(exc_info.value)


def test_constant_time_comparison():
    """Verify constant-time comparison helper."""
    assert constant_time_compare("secret_string_123", "secret_string_123") is True
    assert constant_time_compare("secret_string_123", "secret_string_456") is False
    assert constant_time_compare("short", "long_string_different_length") is False
