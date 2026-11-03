"""Authentication router."""

import uuid
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.dependencies import get_current_user, record_audit_log
from database.models.user import User
from database.session import get_db
from packages.common.config import settings
from packages.common.exceptions import AuthenticationError
from packages.common.security import (
    create_access_token,
    create_refresh_token,
    verify_password,
    verify_token
)
from packages.schemas.auth import LoginRequest, RefreshTokenRequest, TokenResponse
from packages.schemas.user import UserResponse

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    payload: LoginRequest,
    session: AsyncSession = Depends(get_db)
):
    """Authenticate with email and password to receive JWT tokens."""
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    stmt = select(User).where(User.email == payload.email.lower().strip())
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.password_hash):
        # Record failed audit log
        await record_audit_log(
            session=session,
            action="LOGIN_FAILED",
            resource_type="auth",
            resource_id=payload.email,
            details={"email": payload.email, "reason": "Invalid credentials"},
            ip_address=client_ip,
            user_agent=user_agent
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not user.is_active:
        await record_audit_log(
            session=session,
            action="LOGIN_REJECTED",
            resource_type="auth",
            resource_id=str(user.id),
            user_id=user.id,
            details={"email": user.email, "reason": "Account deactivated"},
            ip_address=client_ip,
            user_agent=user_agent
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated"
        )

    # Issue tokens
    claims = {"role": user.role, "email": user.email}
    access_token = create_access_token(subject=str(user.id), claims=claims)
    refresh_token = create_refresh_token(subject=str(user.id), claims=claims)

    await record_audit_log(
        session=session,
        action="LOGIN_SUCCESS",
        resource_type="auth",
        resource_id=str(user.id),
        user_id=user.id,
        details={"email": user.email, "role": user.role},
        ip_address=client_ip,
        user_agent=user_agent
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token_endpoint(
    payload: RefreshTokenRequest,
    session: AsyncSession = Depends(get_db)
):
    """Renew access token using valid refresh token."""
    try:
        decoded = verify_token(payload.refresh_token, expected_type="refresh")
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"}
        )

    user_id_str = decoded.get("sub")
    try:
        user_uuid = uuid.UUID(user_id_str)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed user ID in refresh token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    stmt = select(User).where(User.id == user_uuid)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"}
        )

    claims = {"role": user.role, "email": user.email}
    new_access_token = create_access_token(subject=str(user.id), claims=claims)
    new_refresh_token = create_refresh_token(subject=str(user.id), claims=claims)

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    """Return profile of currently authenticated user."""
    return current_user
