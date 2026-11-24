"""Regression test for SEC-LEAK-02: Hardcoded credential scrubbing and benchmark-admin inactivation."""

import os
import re
import pytest

SETUP_SCRIPT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "benchmark",
    "setup_engagement_and_scope_check.py"
)

def test_setup_script_has_no_hardcoded_password_or_mock_hash():
    """Ensure benchmark/setup_engagement_and_scope_check.py does not contain hardcoded passwords or placeholder hashes."""
    assert os.path.exists(SETUP_SCRIPT_PATH), f"Setup script not found at {SETUP_SCRIPT_PATH}"
    with open(SETUP_SCRIPT_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    # Must not contain the old placeholder string
    assert "[MOCKED_FOR_BENCHMARK_SETUP]" not in content, (
        "Found hardcoded placeholder '[MOCKED_FOR_BENCHMARK_SETUP]' in tracked setup script!"
    )

    # Must read password from environment / untracked file
    assert "PENTESA_BENCHMARK_ADMIN_PASSWORD" in content, (
        "Setup script must read benchmark-admin password from PENTESA_BENCHMARK_ADMIN_PASSWORD or untracked file."
    )

def test_setup_script_enforces_inactive_benchmark_admin():
    """Ensure benchmark-admin is created with is_active=False per ENV RULES v2."""
    with open(SETUP_SCRIPT_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    # The user instantiation for benchmark-admin must set is_active=False
    match = re.search(r'email="benchmark-admin@pentesa\.lab"[\s\S]*?is_active\s*=\s*(True|False)', content)
    assert match is not None, "Could not find benchmark-admin user instantiation in setup script."
    assert match.group(1) == "False", (
        f"benchmark-admin must be created with is_active=False, found is_active={match.group(1)}"
    )
