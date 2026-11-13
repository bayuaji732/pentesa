"""Regression and unit tests for FIX-02 (SEC-KEY-01): Master key safety and fail-closed startup."""

import os
from pathlib import Path
import pytest

from apps.api.main import KNOWN_INSECURE_KEYS, validate_encryption_key_startup
from packages.common.config import settings
from packages.common.security import derive_aes_key


def test_derive_aes_key_fails_closed_when_unset(monkeypatch):
    """Verify derive_aes_key raises ValueError when no key is provided and environment is clean."""
    monkeypatch.delenv("PENTESA_ENCRYPTION_KEY", raising=False)
    monkeypatch.setattr(settings, "encryption_key", "")

    with pytest.raises(ValueError) as exc_info:
        derive_aes_key(None)
    assert "Encryption key not configured" in str(exc_info.value)


def test_derive_aes_key_rejects_under_32_bytes():
    """Verify derive_aes_key rejects keys shorter than 32 bytes."""
    with pytest.raises(ValueError) as exc_info:
        derive_aes_key("short-key-16b!!")
    assert "must be at least 32 bytes" in str(exc_info.value)


def test_derive_aes_key_accepts_valid_32_byte_key():
    """Verify derive_aes_key successfully derives 32-byte key when given valid input."""
    valid_key = "a" * 32
    derived = derive_aes_key(valid_key)
    assert len(derived) == 32
    assert derived == valid_key.encode("utf-8")


def test_startup_validation_refuses_missing_key(monkeypatch):
    """Verify API startup fails closed with RuntimeError when PENTESA_ENCRYPTION_KEY is unset."""
    monkeypatch.delenv("PENTESA_ENCRYPTION_KEY", raising=False)
    monkeypatch.setattr(settings, "encryption_key", "")

    with pytest.raises(RuntimeError) as exc_info:
        validate_encryption_key_startup()
    assert "PENTESA_ENCRYPTION_KEY is not set" in str(exc_info.value)


def test_startup_validation_refuses_short_key(monkeypatch):
    """Verify API startup fails closed with RuntimeError when key is < 32 bytes."""
    monkeypatch.setenv("PENTESA_ENCRYPTION_KEY", "too_short_key_20_bytes")

    with pytest.raises(RuntimeError) as exc_info:
        validate_encryption_key_startup()
    assert "must be >= 32 bytes" in str(exc_info.value)


def test_startup_validation_refuses_known_default_key_outside_test(monkeypatch):
    """Verify API startup fails closed in production when key is a repository default."""
    monkeypatch.setattr(settings, "env", "production")
    monkeypatch.setenv("PENTESA_ENCRYPTION_KEY", "pentesa-master-key-32-bytes-long-change-in-prod!")

    with pytest.raises(RuntimeError) as exc_info:
        validate_encryption_key_startup()
    assert "known repository default" in str(exc_info.value)


def test_repo_scan_zero_default_master_key_literals():
    """Verify production Python modules contain zero occurrences of default master key literals."""
    root_dir = Path(__file__).resolve().parent.parent.parent
    target_dirs = ["packages", "services", "apps", "agents", "database", "integrations"]

    forbidden_literals = [
        "pentesa-master-key-32-bytes-long-change-in-prod!",
        "default-insecure-master-key-32b!",
    ]

    violations = []

    for d in target_dirs:
        dir_path = root_dir / d
        if not dir_path.exists():
            continue
        for py_file in dir_path.rglob("*.py"):
            if "node_modules" in py_file.parts or ".venv" in py_file.parts:
                continue
            text = py_file.read_text(encoding="utf-8", errors="ignore")
            for forbidden in forbidden_literals:
                # Disallow default key literals anywhere in production code
                # (except the explicit rejection blacklist KNOWN_INSECURE_KEYS in main.py)
                if forbidden in text and py_file.name != "main.py":
                    violations.append((str(py_file.relative_to(root_dir)), forbidden))

    assert len(violations) == 0, f"Found default master key literals in production code: {violations}"
