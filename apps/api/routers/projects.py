"""Project management router."""

import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from apps.api.dependencies import get_current_user, record_audit_log, verify_project_access
from database.models.agent import (
    AgentDecision,
    AgentExecution,
    AgentToolCall,
    ApprovalRequest,
    WorkflowExecution,
)
from database.models.audit import AuditLog
from database.models.discovery import (
    Cookie,
    DiscoveredDomain,
    Endpoint,
    SecurityHeader,
    Technology,
)
from database.models.finding import (
    FalsePositive,
    Finding,
    FindingEvidence,
    FindingReproduction,
    FindingStatusHistory,
)
from database.models.project import Project, ProjectMember
from database.models.report import Report
from database.models.scope import ScopeRule
from database.models.tool import ToolConfiguration, ToolExecution
from database.models.user import User
from database.models.wstg import TestExecution, TestExecutionLog, WSTGTestInstance
from database.session import get_db
from packages.schemas.project import (
    ProjectCreate,
    ProjectMemberCreate,
    ProjectMemberResponse,
    ProjectResponse,
    ProjectUpdate
)
from packages.schemas.user import UserRole

router = APIRouter(prefix="/api/v1/projects", tags=["Projects"])


@router.get("", response_model=List[ProjectResponse])
async def list_projects(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List projects accessible to the current user."""
    stmt = (
        select(Project)
        .options(
            selectinload(Project.members).selectinload(ProjectMember.user),
            selectinload(Project.scope_rules)
        )
        .order_by(Project.created_at.desc())
    )

    # Non-admin users only see projects they belong to
    if current_user.role != UserRole.ADMIN.value:
        stmt = stmt.join(Project.members).where(ProjectMember.user_id == current_user.id)

    result = await session.execute(stmt)
    return result.scalars().all()


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    payload: ProjectCreate,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new penetration testing project."""
    if payload.authorization_end <= payload.authorization_start:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization end date must be after authorization start date"
        )

    project_id = uuid.uuid4()
    project = Project(
        id=project_id,
        name=payload.name,
        description=payload.description,
        status="PLANNING",
        target_domains=payload.target_domains,
        allowed_cidrs=payload.allowed_cidrs,
        excluded_paths=payload.excluded_paths,
        allow_internal_networks=payload.allow_internal_networks,
        authorization_document_ref=payload.authorization_document_ref,
        authorization_start=payload.authorization_start,
        authorization_end=payload.authorization_end,
        created_by=current_user.id
    )
    session.add(project)

    # Creator is automatically added as LEAD
    membership = ProjectMember(
        id=uuid.uuid4(),
        project_id=project_id,
        user_id=current_user.id,
        role="LEAD"
    )
    session.add(membership)

    # Automatically generate initial scope rules from target_domains and allowed_cidrs
    for domain in payload.target_domains:
        d_clean = domain.strip().lower()
        rule_type = "DOMAIN_WILDCARD" if d_clean.startswith("*.") else "EXACT_DOMAIN"
        session.add(ScopeRule(
            id=uuid.uuid4(),
            project_id=project_id,
            rule_type=rule_type,
            target_type="IN_SCOPE",
            pattern=d_clean
        ))

    for cidr in payload.allowed_cidrs:
        session.add(ScopeRule(
            id=uuid.uuid4(),
            project_id=project_id,
            rule_type="IP_CIDR",
            target_type="IN_SCOPE",
            pattern=cidr.strip()
        ))

    for exc_path in payload.excluded_paths:
        session.add(ScopeRule(
            id=uuid.uuid4(),
            project_id=project_id,
            rule_type="EXCLUDED_PATH",
            target_type="OUT_OF_SCOPE",
            pattern=exc_path.strip()
        ))

    await session.flush()

    client_ip = request.client.host if request.client else None
    await record_audit_log(
        session=session,
        action="PROJECT_CREATED",
        resource_type="project",
        resource_id=str(project.id),
        project_id=project.id,
        user_id=current_user.id,
        details={"name": project.name, "target_domains": project.target_domains},
        ip_address=client_ip
    )

    # Re-fetch with relationships loaded
    stmt = (
        select(Project)
        .options(
            selectinload(Project.members).selectinload(ProjectMember.user),
            selectinload(Project.scope_rules)
        )
        .where(Project.id == project_id)
    )
    result = await session.execute(stmt)
    return result.scalar_one()


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get project details."""
    project, _ = await verify_project_access(project_id, current_user, session)
    return project


@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: uuid.UUID,
    payload: ProjectUpdate,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update project configuration (requires LEAD role)."""
    project, _ = await verify_project_access(project_id, current_user, session, min_role="LEAD")

    changes = {}
    if payload.name is not None:
        project.name = payload.name
        changes["name"] = payload.name
    if payload.description is not None:
        project.description = payload.description
    if payload.status is not None:
        project.status = payload.status.value
        changes["status"] = payload.status.value
    if payload.allow_internal_networks is not None:
        project.allow_internal_networks = payload.allow_internal_networks
        changes["allow_internal_networks"] = payload.allow_internal_networks
    if payload.authorization_document_ref is not None:
        project.authorization_document_ref = payload.authorization_document_ref
    if payload.authorization_start is not None:
        project.authorization_start = payload.authorization_start
    if payload.authorization_end is not None:
        project.authorization_end = payload.authorization_end

    await session.flush()

    client_ip = request.client.host if request.client else None
    await record_audit_log(
        session=session,
        action="PROJECT_UPDATED",
        resource_type="project",
        resource_id=str(project.id),
        project_id=project.id,
        user_id=current_user.id,
        details=changes,
        ip_address=client_ip
    )

    stmt = (
        select(Project)
        .options(
            selectinload(Project.members).selectinload(ProjectMember.user),
            selectinload(Project.scope_rules),
        )
        .where(Project.id == project_id)
    )
    return (await session.execute(stmt)).scalar_one()


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: uuid.UUID,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a project and all dependent assessment artifacts (requires LEAD or Admin)."""
    project, _ = await verify_project_access(project_id, current_user, session, min_role="LEAD")
    project_name = project.name

    # Cancel any in-memory running workflow task tied to this project
    from apps.api.routers import agents as agents_router

    wf_ids = (
        await session.execute(
            select(WorkflowExecution.id).where(WorkflowExecution.project_id == project_id)
        )
    ).scalars().all()
    for wf_id in wf_ids:
        task = agents_router._ACTIVE_WORKFLOW_TASKS.pop(wf_id, None)
        if task and not task.done():
            task.cancel()

    # Delete child entities in deterministic child-to-parent order
    finding_ids = (
        await session.execute(select(Finding.id).where(Finding.project_id == project_id))
    ).scalars().all()
    if finding_ids:
        await session.execute(delete(FindingEvidence).where(FindingEvidence.finding_id.in_(finding_ids)))
        await session.execute(delete(FindingReproduction).where(FindingReproduction.finding_id.in_(finding_ids)))
        await session.execute(delete(FindingStatusHistory).where(FindingStatusHistory.finding_id.in_(finding_ids)))
        await session.execute(delete(FalsePositive).where(FalsePositive.finding_id.in_(finding_ids)))
        await session.execute(delete(Finding).where(Finding.project_id == project_id))

    test_exec_ids = (
        await session.execute(select(TestExecution.id).where(TestExecution.project_id == project_id))
    ).scalars().all()
    if test_exec_ids:
        await session.execute(delete(TestExecutionLog).where(TestExecutionLog.execution_id.in_(test_exec_ids)))
        await session.execute(delete(TestExecution).where(TestExecution.project_id == project_id))
    await session.execute(delete(WSTGTestInstance).where(WSTGTestInstance.project_id == project_id))

    agent_exec_ids = (
        await session.execute(select(AgentExecution.id).where(AgentExecution.project_id == project_id))
    ).scalars().all()
    if agent_exec_ids:
        await session.execute(delete(AgentDecision).where(AgentDecision.agent_execution_id.in_(agent_exec_ids)))
        await session.execute(delete(AgentToolCall).where(AgentToolCall.agent_execution_id.in_(agent_exec_ids)))
    await session.execute(delete(ApprovalRequest).where(ApprovalRequest.project_id == project_id))
    await session.execute(delete(AgentExecution).where(AgentExecution.project_id == project_id))
    await session.execute(delete(WorkflowExecution).where(WorkflowExecution.project_id == project_id))

    await session.execute(delete(ToolExecution).where(ToolExecution.project_id == project_id))
    await session.execute(delete(ToolConfiguration).where(ToolConfiguration.project_id == project_id))
    await session.execute(delete(SecurityHeader).where(SecurityHeader.project_id == project_id))
    await session.execute(delete(Cookie).where(Cookie.project_id == project_id))
    await session.execute(delete(Technology).where(Technology.project_id == project_id))
    await session.execute(delete(Endpoint).where(Endpoint.project_id == project_id))
    await session.execute(delete(DiscoveredDomain).where(DiscoveredDomain.project_id == project_id))
    await session.execute(delete(Report).where(Report.project_id == project_id))
    await session.execute(delete(ScopeRule).where(ScopeRule.project_id == project_id))
    await session.execute(delete(ProjectMember).where(ProjectMember.project_id == project_id))

    # Detach historical audit logs from deleted project while preserving cryptographic hash chain
    await session.execute(update(AuditLog).where(AuditLog.project_id == project_id).values(project_id=None))

    await session.execute(delete(Project).where(Project.id == project_id))
    await session.flush()

    client_ip = request.client.host if request.client else None
    await record_audit_log(
        session=session,
        action="PROJECT_DELETED",
        resource_type="project",
        resource_id=str(project_id),
        project_id=None,
        user_id=current_user.id,
        details={"name": project_name},
        ip_address=client_ip
    )
    await session.commit()
    return None


@router.post("/{project_id}/members", response_model=ProjectMemberResponse, status_code=status.HTTP_201_CREATED)
async def add_project_member(
    project_id: uuid.UUID,
    payload: ProjectMemberCreate,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Add a member to project (LEAD or Admin)."""
    project, _ = await verify_project_access(project_id, current_user, session, min_role="LEAD")

    # Check target user exists
    user_stmt = select(User).where(User.id == payload.user_id)
    u_res = await session.execute(user_stmt)
    target_user = u_res.scalar_one_or_none()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{payload.user_id}' does not exist"
        )

    # Check existing membership
    existing = next((m for m in project.members if m.user_id == payload.user_id), None)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User is already a member of this project"
        )

    member = ProjectMember(
        id=uuid.uuid4(),
        project_id=project_id,
        user_id=payload.user_id,
        role=payload.role.value
    )
    session.add(member)
    await session.flush()

    client_ip = request.client.host if request.client else None
    await record_audit_log(
        session=session,
        action="PROJECT_MEMBER_ADDED",
        resource_type="project_member",
        resource_id=str(member.id),
        project_id=project.id,
        user_id=current_user.id,
        details={"added_user_id": str(payload.user_id), "role": payload.role.value},
        ip_address=client_ip
    )

    stmt = (
        select(ProjectMember)
        .options(selectinload(ProjectMember.user))
        .where(ProjectMember.id == member.id)
    )
    return (await session.execute(stmt)).scalar_one()


@router.delete("/{project_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_project_member(
    project_id: uuid.UUID,
    user_id: uuid.UUID,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Remove a member from project (LEAD or Admin)."""
    project, _ = await verify_project_access(project_id, current_user, session, min_role="LEAD")

    member = next((m for m in project.members if m.user_id == user_id), None)
    if not member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found in this project"
        )

    await session.delete(member)
    await session.flush()

    client_ip = request.client.host if request.client else None
    await record_audit_log(
        session=session,
        action="PROJECT_MEMBER_REMOVED",
        resource_type="project_member",
        resource_id=str(member.id),
        project_id=project.id,
        user_id=current_user.id,
        details={"removed_user_id": str(user_id)},
        ip_address=client_ip
    )
    return None

