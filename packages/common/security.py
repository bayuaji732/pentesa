"""Pentesa security primitives: password hashing, JWT management, and constant-time checks."""

import base64
import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Union
import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import jwt

from packages.common.config import settings
from packages.common.exceptions import AuthenticationError

KNOWN_INSECURE_KEYS = {
    "pentesa-master-key-32-bytes-long-change-in-prod!",
    "pentesa-super-secret-default-key-change-in-production-1234567890",
    "default-insecure-master-key-32b!",
    "change-me-in-production-use-a-strong-secret-key",
    "00000000000000000000000000000000",
    "11111111111111111111111111111111",
    "12345678901234567890123456789012",
}


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


def derive_aes_key(key: Optional[Union[bytes, str]] = None) -> bytes:
    """Derive a 32-byte (256-bit) cryptographic key for AES-256-GCM (SEC-KEY-01)."""
    if key is None:
        key = (
            os.environ.get("PENTESA_ENCRYPTION_KEY")
            or getattr(settings, "encryption_key", "")
        )
    if not key:
        raise ValueError("Encryption key not configured. Set PENTESA_ENCRYPTION_KEY environment variable.")

    if isinstance(key, str):
        key = key.encode("utf-8")

    if len(key) < 32:
        raise ValueError(f"Encryption key must be at least 32 bytes (got {len(key)} bytes).")

    key_str = key.decode("utf-8", errors="replace") if isinstance(key, bytes) else str(key)
    env = (getattr(settings, "env", "") or os.getenv("PENTESA_ENV", "")).lower()
    if env not in ("test",) and key_str in KNOWN_INSECURE_KEYS:
        raise ValueError(f"Encryption key '{key_str[:12]}...' is a known repository default or insecure placeholder string.")

    if len(key) == 32:
        return key
    return hashlib.sha256(key).digest()


def encrypt_secret(
    plaintext: str,
    key: Optional[Union[bytes, str]] = None,
    associated_data: Optional[bytes] = None
) -> str:
    """Encrypt a plaintext string using AES-256-GCM.
    
    Returns base64-encoded string: nonce (12 bytes) + ciphertext + tag (16 bytes).
    """
    if not isinstance(plaintext, str):
        raise TypeError("Plaintext must be a string")

    derived_key = derive_aes_key(key)
    aesgcm = AESGCM(derived_key)
    nonce = os.urandom(12)  # NIST standard 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data)
    payload = nonce + ciphertext
    return base64.b64encode(payload).decode("ascii")


def decrypt_secret(
    encrypted_token: str,
    key: Optional[Union[bytes, str]] = None,
    associated_data: Optional[bytes] = None
) -> str:
    """Decrypt an AES-256-GCM encrypted token.
    
    Raises ValueError on tampering, invalid format, or tag verification failure.
    """
    if not encrypted_token:
        return ""

    try:
        raw = base64.b64decode(encrypted_token.encode("ascii"))
    except Exception as exc:
        raise ValueError(f"Invalid base64 payload: {exc}") from exc

    if len(raw) < 28:  # 12-byte nonce + 16-byte tag minimum
        raise ValueError("Invalid encrypted payload length: shorter than nonce + tag")

    nonce = raw[:12]
    ciphertext = raw[12:]
    derived_key = derive_aes_key(key)
    aesgcm = AESGCM(derived_key)

    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data)
        return decrypted_bytes.decode("utf-8")
    except Exception as exc:
        raise ValueError(f"Decryption failed: integrity verification error ({exc})") from exc


