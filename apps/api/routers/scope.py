"""Scope rules and evaluation router."""

import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from apps.api.dependencies import get_current_user, record_audit_log, verify_project_access
from database.models.project import Project
from database.models.scope import ScopeRule
from database.models.user import User
from database.session import get_db
from packages.schemas.scope import (
    ScopeCheckRequest,
    ScopeCheckResult,
    ScopeRuleCreate,
    ScopeRuleResponse
)
from services.scope_engine.service import scope_service

router = APIRouter(prefix="/api/v1/projects/{project_id}/scope", tags=["Scope"])


@router.get("", response_model=List[ScopeRuleResponse])
async def list_scope_rules(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all scope rules configured for a project."""
    project, _ = await verify_project_access(project_id, current_user, session)
    stmt = select(ScopeRule).where(ScopeRule.project_id == project_id).order_by(ScopeRule.created_at.asc())
    result = await session.execute(stmt)
    return result.scalars().all()


@router.post("", response_model=ScopeRuleResponse, status_code=status.HTTP_201_CREATED)
async def add_scope_rule(
    project_id: uuid.UUID,
    payload: ScopeRuleCreate,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Add a new scope rule to the project (requires LEAD or Admin)."""
    project, _ = await verify_project_access(project_id, current_user, session, min_role="LEAD")

    rule = ScopeRule(
        id=uuid.uuid4(),
        project_id=project_id,
        rule_type=payload.rule_type.value,
        target_type=payload.target_type.value,
        pattern=payload.pattern.strip(),
        port_range=payload.port_range,
        protocol=payload.protocol,
        is_critical=payload.is_critical,
        notes=payload.notes
    )
    session.add(rule)
    await session.flush()

    client_ip = request.client.host if request.client else None
    await record_audit_log(
        session=session,
        action="SCOPE_RULE_ADDED",
        resource_type="scope_rule",
        resource_id=str(rule.id),
        project_id=project.id,
        user_id=current_user.id,
        details={
            "rule_type": rule.rule_type,
            "target_type": rule.target_type,
            "pattern": rule.pattern
        },
        ip_address=client_ip
    )

    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scope_rule(
    project_id: uuid.UUID,
    rule_id: uuid.UUID,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a scope rule (requires LEAD or Admin)."""
    project, _ = await verify_project_access(project_id, current_user, session, min_role="LEAD")

    stmt = select(ScopeRule).where(ScopeRule.id == rule_id, ScopeRule.project_id == project_id)
    result = await session.execute(stmt)
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scope rule '{rule_id}' not found"
        )

    await session.delete(rule)
    await session.flush()

    client_ip = request.client.host if request.client else None
    await record_audit_log(
        session=session,
        action="SCOPE_RULE_REMOVED",
        resource_type="scope_rule",
        resource_id=str(rule.id),
        project_id=project.id,
        user_id=current_user.id,
        details={"pattern": rule.pattern, "rule_type": rule.rule_type},
        ip_address=client_ip
    )
    return None


@router.post("/check", response_model=ScopeCheckResult)
async def check_scope_target(
    project_id: uuid.UUID,
    payload: ScopeCheckRequest,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Evaluate target URL against the project scope rules and authorization window.
    """
    project, _ = await verify_project_access(project_id, current_user, session)

    target = payload.url
    if not target and payload.host:
        proto = payload.protocol or "https"
        port_suffix = f":{payload.port}" if payload.port and payload.port not in (80, 443) else ""
        path = payload.path or "/"
        target = f"{proto}://{payload.host}{port_suffix}{path}"

    if not target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must provide either 'url' or 'host' in check payload"
        )

    result = scope_service.check_target(
        project=project,
        target_url=target,
        rules=project.scope_rules,
        resolve_dns=False
    )
    return result

