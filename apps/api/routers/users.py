"""User management router."""

import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.dependencies import get_current_user, record_audit_log, require_role
from database.models.user import User
from database.session import get_db
from packages.common.security import hash_password
from packages.schemas.user import UserCreate, UserResponse, UserRole, UserUpdate

router = APIRouter(prefix="/api/v1/users", tags=["Users"])


@router.get("", response_model=List[UserResponse])
async def list_users(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    """List all registered users (Admin only)."""
    stmt = select(User).order_by(User.created_at.desc())
    result = await session.execute(stmt)
    return result.scalars().all()


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    request: Request,
    payload: UserCreate,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    """Create a new user account (Admin only)."""
    email_clean = payload.email.lower().strip()
    stmt = select(User).where(User.email == email_clean)
    result = await session.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with email '{email_clean}' already exists"
        )

    new_user = User(
        id=uuid.uuid4(),
        email=email_clean,
        password_hash=hash_password(payload.password),
        full_name=payload.full_name,
        role=payload.role.value,
        is_active=payload.is_active
    )
    session.add(new_user)
    await session.flush()

    client_ip = request.client.host if request.client else None
    await record_audit_log(
        session=session,
        action="USER_CREATED",
        resource_type="user",
        resource_id=str(new_user.id),
        user_id=current_user.id,
        details={"email": new_user.email, "role": new_user.role},
        ip_address=client_ip
    )

    return new_user


@router.get("/{user_id}", response_model=UserResponse)
async def get_user_by_id(
    user_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get user by ID. Only Admin or the user themselves can view."""
    if current_user.role != UserRole.ADMIN.value and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to requested user profile"
        )

    stmt = select(User).where(User.id == user_id)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update user details."""
    is_admin = current_user.role == UserRole.ADMIN.value
    if not is_admin and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    stmt = select(User).where(User.id == user_id)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    changes = {}
    if payload.full_name is not None:
        user.full_name = payload.full_name
        changes["full_name"] = payload.full_name

    # Only admins can alter role and is_active
    if payload.role is not None:
        if not is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only administrators can update user roles"
            )
        user.role = payload.role.value
        changes["role"] = payload.role.value

    if payload.is_active is not None:
        if not is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only administrators can activate/deactivate accounts"
            )
        user.is_active = payload.is_active
        changes["is_active"] = payload.is_active

    await session.flush()

    client_ip = request.client.host if request.client else None
    await record_audit_log(
        session=session,
        action="USER_UPDATED",
        resource_type="user",
        resource_id=str(user.id),
        user_id=current_user.id,
        details=changes,
        ip_address=client_ip
    )

    return user
