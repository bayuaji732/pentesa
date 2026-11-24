"""Regression test for DEFECT-CFG-01: Fail closed in production when DATABASE_URL is missing or non-PostgreSQL."""

import os
import subprocess
import sys
import pytest


def test_production_without_database_url_fails_closed():
    """Production mode without DATABASE_URL must exit non-zero with a clear error."""
    env = os.environ.copy()
    env["PENTESA_ENV"] = "production"
    env.pop("PENTESA_DATABASE_URL", None)
    env.pop("DATABASE_URL", None)
    env["PENTESA_ENCRYPTION_KEY"] = "a" * 32
    env["PENTESA_SECRET_KEY"] = "b" * 32
    env["PENTESA_LLM_PROVIDER"] = "azure_openai"

    cmd = [
        sys.executable,
        "-c",
        (
            "import os; "
            "from apps.api.main import validate_encryption_key_startup; "
            "validate_encryption_key_startup(); "
            "from packages.common.config import Settings; "
            "s = Settings()"
        ),
    ]
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert proc.returncode != 0, f"Expected non-zero exit in production without DATABASE_URL, got 0. Stdout: {proc.stdout}"
    assert (
        "CRITICAL" in proc.stderr
        or "PostgreSQL" in proc.stderr
        or "prohibited" in proc.stderr.lower()
        or "DATABASE_URL" in proc.stderr
    ), f"Expected clear error message in stderr, got: {proc.stderr}"


def test_production_with_sqlite_fails_closed():
    """Production mode configured with SQLite DATABASE_URL must exit non-zero."""
    env = os.environ.copy()
    env["PENTESA_ENV"] = "production"
    env["PENTESA_DATABASE_URL"] = "sqlite+aiosqlite:///./pentesa.db"
    env["PENTESA_ENCRYPTION_KEY"] = "a" * 32
    env["PENTESA_SECRET_KEY"] = "b" * 32
    env["PENTESA_LLM_PROVIDER"] = "azure_openai"

    cmd = [
        sys.executable,
        "-c",
        (
            "import os; "
            "from apps.api.main import validate_encryption_key_startup; "
            "validate_encryption_key_startup(); "
            "from packages.common.config import Settings; "
            "s = Settings()"
        ),
    ]
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert proc.returncode != 0, f"Expected non-zero exit when production uses SQLite, got 0. Stdout: {proc.stdout}"
    assert "sqlite" in proc.stderr.lower(), f"Expected sqlite rejection in stderr, got: {proc.stderr}"


def test_sqlite_requires_explicit_test_setting():
    """SQLite database is prohibited unless explicit test setting is provided."""
    env = os.environ.copy()
    env["PENTESA_ENV"] = "development"
    env["PENTESA_DATABASE_URL"] = "sqlite+aiosqlite:///./test.db"
    env["PENTESA_ALLOW_TEST_SQLITE"] = "0"
    env.pop("PYTEST_CURRENT_TEST", None)

    cmd = [
        sys.executable,
        "-c",
        "from packages.common.config import Settings; s = Settings()",
    ]
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert proc.returncode != 0, "Expected non-zero exit when SQLite is used without explicit test setting"


def test_sqlite_permitted_under_explicit_test_setting():
    """SQLite is permitted when PENTESA_ALLOW_TEST_SQLITE=1 or PENTESA_ENV=test."""
    env = os.environ.copy()
    env["PENTESA_ENV"] = "test"
    env["PENTESA_DATABASE_URL"] = "sqlite+aiosqlite:///./test.db"
    env["PENTESA_ALLOW_TEST_SQLITE"] = "1"

    cmd = [
        sys.executable,
        "-c",
        "from packages.common.config import Settings; s = Settings(); assert 'sqlite' in s.database_url",
    ]
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert proc.returncode == 0, f"Expected success in test mode with SQLite, got stderr: {proc.stderr}"
