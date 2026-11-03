"""Audit log retrieval and verification router."""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.dependencies import get_current_user, require_role
from database.models.audit import AuditLog
from database.models.user import User
from database.session import get_db
from packages.common.audit import verify_audit_chain
from packages.schemas.audit import AuditLogResponse, AuditVerificationResponse
from packages.schemas.user import UserRole

router = APIRouter(prefix="/api/v1/audit-logs", tags=["Audit Logs"])


@router.get("", response_model=List[AuditLogResponse])
async def list_audit_logs(
    project_id: Optional[str] = Query(None, description="Filter by project UUID"),
    action: Optional[str] = Query(None, description="Filter by action code"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.LEAD))
):
    """Query audit logs with optional filters (Admin or Lead)."""
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc())
    if project_id:
        stmt = stmt.where(AuditLog.project_id == project_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)

    stmt = stmt.offset(offset).limit(limit)
    result = await session.execute(stmt)
    return result.scalars().all()


@router.get("/verify", response_model=AuditVerificationResponse)
async def verify_audit_integrity(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    """
    Cryptographically verify the entire audit log hash chain from genesis to head.
    Detects any tampering, deletion, or modification of historical records.
    """
    stmt = select(AuditLog).order_by(AuditLog.created_at.asc())
    result = await session.execute(stmt)
    records = result.scalars().all()

    if not records:
        return AuditVerificationResponse(
            is_valid=True,
            total_records=0
        )

    # Convert records to dicts for verification
    entries = []
    for r in records:
        entries.append({
            "id": str(r.id),
            "project_id": str(r.project_id) if r.project_id else None,
            "user_id": str(r.user_id) if r.user_id else None,
            "action": r.action,
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
            "details": r.details,
            "ip_address": r.ip_address,
            "prev_hash": r.prev_hash,
            "hash": r.hash,
            "timestamp": r.created_at
        })

    is_valid, reason, broken_idx = verify_audit_chain(entries)

    return AuditVerificationResponse(
        is_valid=is_valid,
        total_records=len(records),
        broken_index=broken_idx,
        reason=reason,
        first_hash=records[0].hash,
        last_hash=records[-1].hash
    )
