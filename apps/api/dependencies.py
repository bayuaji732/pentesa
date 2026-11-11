"""FastAPI dependencies: database session, authentication, RBAC, and audit recording."""

import asyncio
import uuid
import weakref
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from database.models.audit import AuditLog
from database.models.project import Project, ProjectMember
from database.models.user import User
from database.session import get_db
from packages.common.audit import GENESIS_HASH, compute_audit_hash
from packages.common.exceptions import AuthenticationError, AuthorizationError, ResourceNotFoundError
from packages.common.security import verify_token
from packages.schemas.user import UserRole

security_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    session: AsyncSession = Depends(get_db)
) -> User:
    """Extract and authenticate user from Bearer JWT token."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    try:
        payload = verify_token(credentials.credentials, expected_type="access")
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"}
        )

    user_id_str = payload.get("sub")
    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token subject",
            headers={"WWW-Authenticate": "Bearer"}
        )

    try:
        user_uuid = uuid.UUID(user_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed user identifier",
            headers={"WWW-Authenticate": "Bearer"}
        )

    stmt = select(User).where(User.id == user_uuid)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token does not exist",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated"
        )

    return user


def require_role(*allowed_roles: UserRole) -> Callable:
    """Role-Based Access Control gate for system-level roles."""
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        user_role = current_user.role
        role_values = [r.value if isinstance(r, UserRole) else str(r) for r in allowed_roles]
        if user_role not in role_values and user_role != UserRole.ADMIN.value:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires one of roles: {role_values} (current: {user_role})"
            )
        return current_user

    return role_checker


async def verify_project_access(
    project_id: uuid.UUID,
    user: User,
    session: AsyncSession,
    min_role: Optional[str] = None
) -> Tuple[Project, Optional[ProjectMember]]:
    """
    Verify user has access to a specific project.
    System ADMIN bypasses project-level membership checks.
    """
    stmt = (
        select(Project)
        .options(selectinload(Project.members), selectinload(Project.scope_rules))
        .where(Project.id == project_id)
    )
    result = await session.execute(stmt)
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID '{project_id}' not found"
        )

    if user.role == UserRole.ADMIN.value:
        return project, None

    # Check project membership
    member = next((m for m in project.members if m.user_id == user.id), None)
    if not member:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not an authorized member of this project"
        )

    # Check minimum role within project
    if min_role:
        role_hierarchy = {"VIEWER": 1, "TESTER": 2, "LEAD": 3}
        user_level = role_hierarchy.get(member.role, 0)
        required_level = role_hierarchy.get(min_role, 99)
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Project role '{min_role}' or higher required (current: {member.role})"
            )

    return project, member


_AUDIT_CHAIN_LOCK_KEY = 72839104  # Stable PostgreSQL advisory lock key for audit hash chain serialization
_AUDIT_LOCKS: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock]" = weakref.WeakKeyDictionary()


def _get_audit_lock() -> asyncio.Lock:
    """Return an asyncio.Lock bound to the currently running event loop."""
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
        # Flush pending caller ORM mutations before reading/advancing the chain tip
        await session.flush()

        bind = session.get_bind()
        if bind is not None and bind.dialect.name == "postgresql":
            await session.execute(
                text("SELECT pg_advisory_xact_lock(:lock_id)"),
                {"lock_id": _AUDIT_CHAIN_LOCK_KEY},
            )

        # Find latest committed audit log entry to extract previous hash and timestamp
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
        )

        log_entry = AuditLog(
            id=uuid.uuid4(),
            project_id=project_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent,
            prev_hash=prev_hash,
            hash=entry_hash,
            created_at=now,
        )
        session.add(log_entry)
        if commit:
            await session.commit()
        else:
            await session.flush()
        return log_entry
