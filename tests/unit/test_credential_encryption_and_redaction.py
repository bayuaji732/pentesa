"""Comprehensive tests for AES-256-GCM credential encryption at rest and sensitive redaction.

Verifies:
- AES-256-GCM authenticated encryption roundtrip
- Unique nonce generation per encryption
- AEAD tamper resistance (corrupt ciphertext or tag raises ValueError)
- Key derivation from environment variable (PENTESA_ENCRYPTION_KEY)
- Target credentials in AuthProfile stored encrypted at rest in database
- Credential masking in response models
- Evidence engine redaction of tokens and custom secrets
- Logging filter redaction preventing credential leakage
"""

import base64
import json
import logging
import os
import uuid
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.main import app
from database.models.auth_profile import AuthProfile
from database.models.project import Project
from database.models.user import User
from packages.common.logging_filter import SensitiveDataLoggingFilter
from packages.common.security import (
    create_access_token,
    decrypt_secret,
    derive_aes_key,
    encrypt_secret,
    hash_password,
)
from services.evidence_engine.collector import build_forensic_evidence
from services.evidence_engine.redactor import redact_custom_secrets, redact_raw_stream


@pytest.fixture(autouse=True)
def setup_test_key(monkeypatch):
    """Set explicit 256-bit test encryption key via environment."""
    test_key = "pentesa_preflight_audit_encryption_key_32bytes!"
    monkeypatch.setenv("PENTESA_ENCRYPTION_KEY", test_key)
    return test_key


def test_aes_gcm_roundtrip():
    """Verify AES-256-GCM encrypts and decrypts accurately."""
    secret = "SuperSecret_P@ssw0rd!_12345"
    encrypted = encrypt_secret(secret)

    assert encrypted != secret
    assert isinstance(encrypted, str)

    decrypted = decrypt_secret(encrypted)
    assert decrypted == secret


def test_aes_gcm_unique_nonce_per_encryption():
    """Verify every encryption produces a unique nonce (different ciphertext for identical plaintext)."""
    secret = "IdenticalPlaintextSecret"
    c1 = encrypt_secret(secret)
    c2 = encrypt_secret(secret)

    assert c1 != c2, "Encryption must use unique random nonces for identical plaintexts"

    assert decrypt_secret(c1) == secret
    assert decrypt_secret(c2) == secret


def test_aes_gcm_tamper_resistance():
    """Verify AEAD authentication tag prevents tampering and raises ValueError."""
    secret = "SensitiveAPIKey_abcdef123456"
    encrypted = encrypt_secret(secret)

    # Decode, tamper with a byte, and re-encode
    raw = bytearray(base64.b64decode(encrypted))
    raw[-1] ^= 0x01  # Flip bit in auth tag
    tampered = base64.b64encode(raw).decode("ascii")

    with pytest.raises(ValueError, match="Decryption failed"):
        decrypt_secret(tampered)


def test_aes_gcm_env_key_derivation(monkeypatch):
    """Verify that changing PENTESA_ENCRYPTION_KEY changes key and prevents decrypt with wrong key."""
    key_a = "secret_key_alpha_32_bytes_long_1"
    key_b = "secret_key_bravo_32_bytes_long_2"

    monkeypatch.setenv("PENTESA_ENCRYPTION_KEY", key_a)
    secret = "TopSecretPayload"
    encrypted = encrypt_secret(secret)

    # Switch to different key
    monkeypatch.setenv("PENTESA_ENCRYPTION_KEY", key_b)
    with pytest.raises(ValueError, match="Decryption failed"):
        decrypt_secret(encrypted)


@pytest.mark.asyncio
async def test_auth_profile_encrypted_at_rest_in_db(db_session: AsyncSession):
    """Verify target credentials in AuthProfile are stored encrypted at rest in the database."""
    proj = Project(
        id=uuid.uuid4(),
        name="Target Credential Test Project",
        status="PLANNING",
        target_domains=["target.corp"],
        allowed_cidrs=["192.168.1.0/24"],
        excluded_paths=[],
        authorization_start=pytest.fixture_now if hasattr(pytest, "fixture_now") else None,
        authorization_end=pytest.fixture_now if hasattr(pytest, "fixture_now") else None,
        created_by=uuid.uuid4()
    )
    # Provide required dates
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    proj.authorization_start = now
    proj.authorization_end = now + timedelta(days=7)

    # User
    user = User(
        id=proj.created_by,
        email=f"tester_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Tester Lead",
        password_hash=hash_password("Password123!"),
        role="LEAD",
        is_active=True
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(proj)
    await db_session.flush()

    raw_credentials = {
        "username": "admin",
        "password": "UltraSecretP@ssword999!",
        "api_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.target_token_string"
    }

    profile = AuthProfile(
        id=uuid.uuid4(),
        project_id=proj.id,
        name="Production Admin Profile",
        auth_type="BEARER",
        headers={"X-Environment": "Production"}
    )
    profile.set_credentials(raw_credentials)
    db_session.add(profile)
    await db_session.commit()

    # Direct query to inspect what is actually stored at rest
    result = await db_session.execute(
        select(AuthProfile.encrypted_credentials).where(AuthProfile.id == profile.id)
    )
    db_row_value = result.scalar_one()

    # The raw database text MUST NOT contain plaintext passwords or tokens
    assert "UltraSecretP@ssword999!" not in db_row_value
    assert "target_token_string" not in db_row_value

    # Decrypt via model method
    retrieved = await db_session.get(AuthProfile, profile.id)
    decrypted_creds = retrieved.get_credentials()
    assert decrypted_creds == raw_credentials

    # Masked representation for UI
    masked = retrieved.get_masked_credentials()
    assert "UltraSecretP@ssword999!" not in masked["password"]
    assert "[REDACTED]" in masked["password"]


def test_evidence_engine_redacts_credentials_and_custom_secrets():
    """Verify evidence engine masks authorization tokens, passwords, and custom secrets in raw streams."""
    raw_req = (
        "POST /api/v1/login HTTP/1.1\r\n"
        "Host: api.example.com\r\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive_token_12345\r\n"
        "Content-Type: application/json\r\n\r\n"
        '{"username": "admin", "password": "TargetSensitivePassword987!"}'
    )

    custom_secret = "TargetSensitivePassword987!"
    redacted = redact_raw_stream(raw_req, custom_secrets=[custom_secret])

    assert "sensitive_token_12345" not in redacted
    assert "Bearer [REDACTED]" in redacted
    assert custom_secret not in redacted
    assert "[REDACTED]" in redacted


def test_evidence_collector_build_forensic_evidence_redaction():
    """Verify build_forensic_evidence integrates custom secret redaction."""
    evidence = build_forensic_evidence(
        method="POST",
        url="https://api.target.com/auth/token",
        request_headers={"Authorization": "Bearer super_secret_token_12345678"},
        request_body='{"client_secret": "my_confidential_client_secret_999"}',
        response_status=200,
        response_body='{"access_token": "secret_jwt_access_token_12345"}',
        custom_secrets=["my_confidential_client_secret_999"]
    )

    assert "super_secret_token_12345678" not in evidence["raw_request"]
    assert "Bearer [REDACTED]" in evidence["raw_request"]
    assert "my_confidential_client_secret_999" not in evidence["raw_request"]
    assert "secret_jwt_access_token_12345" not in evidence["raw_response"]


def test_logging_filter_redacts_secrets():
    """Verify SensitiveDataLoggingFilter scrubs credentials from log records."""
    log_filter = SensitiveDataLoggingFilter(custom_secrets=["CustomSecretToken999"])

    logger = logging.getLogger("test_security_logger")
    logger.setLevel(logging.DEBUG)
    logger.addFilter(log_filter)

    # Test formatting on log record
    record = logger.makeRecord(
        name="test_security_logger",
        level=logging.INFO,
        fn="test_file.py",
        lno=1,
        msg="Authenticated user with token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token12345 and secret CustomSecretToken999",
        args=(),
        exc_info=None
    )

    log_filter.filter(record)
    assert "token12345" not in record.msg
    assert "CustomSecretToken999" not in record.msg
    assert "[REDACTED]" in record.msg


@pytest.mark.asyncio
async def test_api_auth_profile_crud_encrypted(client: AsyncClient, admin_token: str):
    """Verify API endpoints create and return masked auth profiles while encrypting credentials at rest."""
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)

    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Create a project
    proj_payload = {
        "name": "Auth Profile Encrypted Vault Project",
        "description": "AES-256-GCM verification",
        "target_domains": ["vault.target.local"],
        "allowed_cidrs": [],
        "excluded_paths": [],
        "allow_internal_networks": False,
        "authorization_document_ref": "ROE-VAULT-001",
        "authorization_start": now.isoformat(),
        "authorization_end": (now + timedelta(days=7)).isoformat()
    }
    proj_resp = await client.post("/api/v1/projects", json=proj_payload, headers=headers)
    assert proj_resp.status_code == 201, proj_resp.text
    project_id = proj_resp.json()["id"]

    # 2. Create auth profile with sensitive credentials
    create_payload = {
        "name": "Target API Token",
        "auth_type": "BEARER",
        "headers": {"X-Custom": "Value"},
        "credentials": {
            "token": "TargetSensitiveSecretTokenValue123",
            "api_key": "AnotherConfidentialSecret"
        }
    }
    resp = await client.post(
        f"/api/v1/projects/{project_id}/auth-profiles",
        json=create_payload,
        headers=headers
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["name"] == "Target API Token"
    assert "masked_credentials" in data
    assert "TargetSensitiveSecretTokenValue123" not in str(data["masked_credentials"])
    assert "[REDACTED]" in str(data["masked_credentials"])
    profile_id = data["id"]

    # 3. List profiles and verify masked display
    list_resp = await client.get(
        f"/api/v1/projects/{project_id}/auth-profiles",
        headers=headers
    )
    assert list_resp.status_code == 200
    profiles = list_resp.json()
    assert len(profiles) >= 1
    assert any(p["id"] == profile_id for p in profiles)

    # 4. Delete profile
    del_resp = await client.delete(
        f"/api/v1/projects/{project_id}/auth-profiles/{profile_id}",
        headers=headers
    )
    assert del_resp.status_code == 204

