"""Audit log recording utility with concurrency control and cryptographic chaining."""

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.audit import AuditLog
from packages.common.audit import GENESIS_HASH, compute_audit_hash

_AUDIT_CHAIN_LOCK_KEY = 0x50454E54  # "PENT" in ASCII

_AUDIT_LOCKS: dict[asyncio.AbstractEventLoop, asyncio.Lock] = {}

def _get_audit_lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    lock = _AUDIT_LOCKS.get(loop)
    if lock is None:
        lock = asyncio.Lock()
        _AUDIT_LOCKS[loop] = lock
    return lock

async def record_audit_log(
    session: AsyncSession,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    project_id: Optional[uuid.UUID] = None,
    user_id: Optional[uuid.UUID] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    commit: bool = True,
    user_email: Optional[str] = None,
    hash_version: int = 2,
) -> AuditLog:
    """
    Record a cryptographically hash-chained audit log entry safely under concurrency.

    Serializes chain-tip reads/appends using a per-loop asyncio.Lock and (on PostgreSQL)
    a transaction-level advisory lock, enforces monotonically increasing UTC timestamps,
    and commits immediately by default so concurrent or long-running caller work cannot
    fork the hash chain.
    """
    lock = _get_audit_lock()
    async with lock:
        await session.flush()

        bind = session.get_bind()
        if bind is not None and bind.dialect.name == "postgresql":
            await session.execute(
                text("SELECT pg_advisory_xact_lock(:lock_id)"),
                {"lock_id": _AUDIT_CHAIN_LOCK_KEY},
            )

        stmt = (
            select(AuditLog.hash, AuditLog.created_at)
            .order_by(desc(AuditLog.created_at))
            .limit(1)
        )
        last_row = (await session.execute(stmt)).first()
        prev_hash = last_row[0] if last_row else GENESIS_HASH
        last_created_at = last_row[1] if last_row else None

        now = datetime.now(timezone.utc)
        if last_created_at is not None:
            if last_created_at.tzinfo is None:
                last_created_at = last_created_at.replace(tzinfo=timezone.utc)
            if now <= last_created_at:
                now = last_created_at + timedelta(microseconds=1)

        entry_hash = compute_audit_hash(
            prev_hash=prev_hash,
            timestamp=now,
            user_id=str(user_id) if user_id else None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            hash_version=hash_version,
            user_email=user_email,
        )

        log_entry = AuditLog(
            id=uuid.uuid4(),
            project_id=project_id,
            user_id=user_id,
            user_email=user_email,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent,
            prev_hash=prev_hash,
            hash=entry_hash,
            hash_version=hash_version,
            created_at=now,
        )
        session.add(log_entry)
        if commit:
            await session.commit()
            await session.refresh(log_entry)
        else:
            await session.flush()
        return log_entry
