"""Regression tests for DEFECT-AUD-02 (Audit foreign key mutation & hash integrity).

Verifies:
1. Deleting a user with existing audit records is rejected with IntegrityError (ON DELETE RESTRICT).
2. Backward-compatible hash verification: legacy v1 rows compute identical hashes.
3. Version 2 audit entries incorporate user_email snapshot and verify cleanly in verify_audit_chain.
"""

import pytest
import uuid
from datetime import datetime, timezone
from sqlalchemy import select, delete, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.user import User
from database.models.audit import AuditLog
from packages.common.audit import compute_audit_hash, verify_audit_chain, GENESIS_HASH


@pytest.mark.asyncio
async def test_cannot_delete_user_with_audit_records(db_session: AsyncSession):
    """DEFECT-AUD-02.1: Deleting a user with linked audit logs is rejected (ON DELETE RESTRICT)."""
    # Create test user
    user = User(
        email=f"audtest-{uuid.uuid4().hex[:8]}@example.com",
        password_hash="test_hash_123",
        full_name="Audit Test User",
        role="LEAD",
        is_active=True,
    )
    db_session.add(user)
    await db_session.flush()

    # Create audit record referencing this user
    now = datetime.now(timezone.utc)
    h = compute_audit_hash(
        prev_hash=GENESIS_HASH,
        timestamp=now,
        user_id=str(user.id),
        action="user_login",
        resource_type="auth",
        resource_id=str(user.id),
        details={"login": "success"},
        hash_version=1
    )
    audit = AuditLog(
        user_id=user.id,
        action="user_login",
        resource_type="auth",
        resource_id=str(user.id),
        details={"login": "success"},
        prev_hash=GENESIS_HASH,
        hash=h,
        created_at=now,
        hash_version=1,
    )
    db_session.add(audit)
    await db_session.commit()

    # Attempt to delete the user -> MUST raise IntegrityError due to ON DELETE RESTRICT
    with pytest.raises(IntegrityError):
        await db_session.execute(delete(User).where(User.id == user.id))
        await db_session.commit()

    await db_session.rollback()


def test_hash_version_compatibility():
    """DEFECT-AUD-02.2: Backward compatibility for hash_version=1 vs hash_version=2."""
    now = datetime(2026, 11, 26, 10, 0, 0, tzinfo=timezone.utc)
    uid = str(uuid.uuid4())
    email = "lead@pentesa.lab"

    # v1 hash without hash_version argument must match default
    h1_default = compute_audit_hash(
        prev_hash=GENESIS_HASH,
        timestamp=now,
        user_id=uid,
        action="create",
        resource_type="project",
        resource_id="123",
        details={"name": "test"},
    )
    h1_explicit = compute_audit_hash(
        prev_hash=GENESIS_HASH,
        timestamp=now,
        user_id=uid,
        action="create",
        resource_type="project",
        resource_id="123",
        details={"name": "test"},
        hash_version=1,
    )
    assert h1_default == h1_explicit

    # v2 hash incorporates email snapshot
    h2 = compute_audit_hash(
        prev_hash=h1_default,
        timestamp=now,
        user_id=uid,
        action="create",
        resource_type="project",
        resource_id="123",
        details={"name": "test"},
        hash_version=2,
        user_email=email,
    )
    assert h2 != h1_default

    # Verify mixed chain passes verification
    entries = [
        {
            "prev_hash": GENESIS_HASH,
            "created_at": now,
            "user_id": uid,
            "action": "create",
            "resource_type": "project",
            "resource_id": "123",
            "details": {"name": "test"},
            "hash": h1_default,
            "hash_version": 1,
        },
        {
            "prev_hash": h1_default,
            "created_at": now,
            "user_id": uid,
            "user_email": email,
            "action": "create",
            "resource_type": "project",
            "resource_id": "123",
            "details": {"name": "test"},
            "hash": h2,
            "hash_version": 2,
        }
    ]
    is_valid, err, idx = verify_audit_chain(entries)
    assert is_valid is True, f"Mixed chain validation failed: {err}"
