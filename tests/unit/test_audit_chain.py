"""Unit tests for cryptographic audit log hash chaining and tamper detection."""

import uuid
from datetime import datetime, timezone
import pytest

from packages.common.audit import (
    GENESIS_HASH,
    compute_audit_hash,
    verify_audit_chain
)


def test_genesis_hash():
    """Verify genesis block has 64 zero characters."""
    assert GENESIS_HASH == "0" * 64
    assert len(GENESIS_HASH) == 64


def test_audit_hash_chain_valid():
    """Verify valid cryptographic chain passes verification."""
    now = datetime.now(timezone.utc)
    entries = []

    # Entry 1 (Genesis child)
    prev = GENESIS_HASH
    h1 = compute_audit_hash(
        prev_hash=prev,
        timestamp=now,
        user_id="user-1",
        action="USER_LOGIN",
        resource_type="auth",
        resource_id="user-1",
        details={"ip": "10.0.0.1"}
    )
    entries.append({
        "prev_hash": prev,
        "hash": h1,
        "timestamp": now,
        "user_id": "user-1",
        "action": "USER_LOGIN",
        "resource_type": "auth",
        "resource_id": "user-1",
        "details": {"ip": "10.0.0.1"}
    })

    # Entry 2
    prev = h1
    h2 = compute_audit_hash(
        prev_hash=prev,
        timestamp=now,
        user_id="user-1",
        action="PROJECT_CREATED",
        resource_type="project",
        resource_id="proj-100",
        details={"name": "Web Pentest"}
    )
    entries.append({
        "prev_hash": prev,
        "hash": h2,
        "timestamp": now,
        "user_id": "user-1",
        "action": "PROJECT_CREATED",
        "resource_type": "project",
        "resource_id": "proj-100",
        "details": {"name": "Web Pentest"}
    })

    # Entry 3
    prev = h2
    h3 = compute_audit_hash(
        prev_hash=prev,
        timestamp=now,
        user_id="user-1",
        action="SCOPE_RULE_ADDED",
        resource_type="scope_rule",
        resource_id="rule-1",
        details={"pattern": "*.target.com"}
    )
    entries.append({
        "prev_hash": prev,
        "hash": h3,
        "timestamp": now,
        "user_id": "user-1",
        "action": "SCOPE_RULE_ADDED",
        "resource_type": "scope_rule",
        "resource_id": "rule-1",
        "details": {"pattern": "*.target.com"}
    })

    is_valid, reason, broken_idx = verify_audit_chain(entries)
    assert is_valid is True
    assert reason is None
    assert broken_idx is None


def test_audit_tampering_detected_on_content_change():
    """Verify tampering with entry details or action is caught immediately."""
    now = datetime.now(timezone.utc)
    entries = []

    prev = GENESIS_HASH
    h1 = compute_audit_hash(prev, now, "u1", "SCAN_START", "scan", "s1", {"tool": "nuclei"})
    entries.append({
        "prev_hash": prev,
        "hash": h1,
        "timestamp": now,
        "user_id": "u1",
        "action": "SCAN_START",
        "resource_type": "scan",
        "resource_id": "s1",
        "details": {"tool": "nuclei"}
    })

    h2 = compute_audit_hash(h1, now, "u1", "SCAN_FINISH", "scan", "s1", {"findings": 0})
    entries.append({
        "prev_hash": h1,
        "hash": h2,
        "timestamp": now,
        "user_id": "u1",
        "action": "SCAN_FINISH",
        "resource_type": "scan",
        "resource_id": "s1",
        "details": {"findings": 0}
    })

    # Tamper with entry 1: change tool from 'nuclei' to 'nmap'
    entries[0]["details"] = {"tool": "nmap"}

    is_valid, reason, broken_idx = verify_audit_chain(entries)
    assert is_valid is False
    assert broken_idx == 0
    assert "Hash mismatch at index 0" in reason


def test_audit_tampering_detected_on_deletion():
    """Verify deleting an entry in the middle breaks the chain continuity."""
    now = datetime.now(timezone.utc)
    entries = []

    prev = GENESIS_HASH
    for i in range(3):
        h = compute_audit_hash(prev, now, "u1", f"ACTION_{i}", "res", str(i), None)
        entries.append({
            "prev_hash": prev,
            "hash": h,
            "timestamp": now,
            "user_id": "u1",
            "action": f"ACTION_{i}",
            "resource_type": "res",
            "resource_id": str(i),
            "details": None
        })
        prev = h

    # Delete middle entry (index 1)
    del entries[1]

    # Entry 2 now points to deleted Entry 1's hash instead of Entry 0's hash
    is_valid, reason, broken_idx = verify_audit_chain(entries)
    assert is_valid is False
    assert broken_idx == 1
    assert "Broken hash chain at index 1" in reason

