"""AI Agents observability, workflow DAG control, and approval gate router."""

import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.dependencies import get_current_user, verify_project_access
from database.models.agent import ApprovalRequest
from database.models.user import User
from database.session import get_db
from packages.common.exceptions import BadRequestError, ProjectAuthorizationExpiredError, ResourceNotFoundError
from packages.schemas.agent import (
    AgentDecisionResponse,
    ApprovalDecisionRequest,
    ApprovalRequestResponse,
    WorkflowStartRequest,
    WorkflowStatusResponse
)
from services.orchestrator.supervisor import WorkflowSupervisor

router = APIRouter(prefix="/api/v1/projects/{project_id}/agents", tags=["AI Agents & Workflow"])


@router.get(
    "/status",
    response_model=WorkflowStatusResponse,
    summary="Query real-time status of all agents and workflow DAG"
)
async def get_agents_status(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve operational state, active phases, and metrics for all 15 agents."""
    await verify_project_access(project_id, current_user, session)
    supervisor = WorkflowSupervisor(session)
    try:
        return await supervisor.get_workflow_status(project_id)
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/workflow/start",
    response_model=WorkflowStatusResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Initiate autonomous multi-agent pentest workflow"
)
async def start_pentest_workflow(
    project_id: uuid.UUID,
    payload: WorkflowStartRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Launch the hierarchical multi-agent workflow DAG across reconnaissance, WSTG, and validation."""
    await verify_project_access(project_id, current_user, session)
    supervisor = WorkflowSupervisor(session)

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        await supervisor.start_workflow(
            project_id=project_id,
            user_id=current_user.id,
            phases=payload.phases,
            scan_profile=payload.scan_profile or "QUICK",
            ip_address=ip_address,
            user_agent=user_agent
        )
        return await supervisor.get_workflow_status(project_id)
    except ProjectAuthorizationExpiredError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except BadRequestError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/workflow/reset",
    summary="Reset active or stuck workflow execution"
)
async def reset_pentest_workflow(
    project_id: uuid.UUID,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Emergency reset any stuck or running workflow for the project."""
    await verify_project_access(project_id, current_user, session)
    supervisor = WorkflowSupervisor(session)
    await supervisor.reset_workflow(project_id=project_id, user_id=current_user.id)
    try:
        return await supervisor.get_workflow_status(project_id)
    except ResourceNotFoundError:
        return {"status": "STOPPED", "message": "Workflow successfully reset"}


@router.post(
    "/workflow/pause",
    response_model=WorkflowStatusResponse,
    summary="Pause active workflow execution at current checkpoint"
)
async def pause_pentest_workflow(
    project_id: uuid.UUID,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Pause the execution DAG and checkpoint current agent states."""
    await verify_project_access(project_id, current_user, session)
    supervisor = WorkflowSupervisor(session)

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        await supervisor.pause_workflow(
            project_id=project_id,
            user_id=current_user.id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        return await supervisor.get_workflow_status(project_id)
    except BadRequestError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/workflow/resume",
    response_model=WorkflowStatusResponse,
    summary="Resume paused pentest workflow"
)
async def resume_pentest_workflow(
    project_id: uuid.UUID,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Resume execution from the last durable checkpoint."""
    await verify_project_access(project_id, current_user, session)
    supervisor = WorkflowSupervisor(session)

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        await supervisor.resume_workflow(
            project_id=project_id,
            user_id=current_user.id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        return await supervisor.get_workflow_status(project_id)
    except BadRequestError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/workflow/stop",
    response_model=WorkflowStatusResponse,
    summary="Emergency stop active pentest workflow"
)
async def stop_pentest_workflow(
    project_id: uuid.UUID,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Hard emergency stop: aborts execution DAG and halts all active agent subtasks."""
    await verify_project_access(project_id, current_user, session)
    supervisor = WorkflowSupervisor(session)

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        await supervisor.stop_workflow(
            project_id=project_id,
            user_id=current_user.id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        return await supervisor.get_workflow_status(project_id)
    except BadRequestError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/decisions",
    response_model=List[AgentDecisionResponse],
    summary="Stream and query agent reasoning thought traces"
)
async def list_agent_decisions(
    project_id: uuid.UUID,
    agent_id: Optional[str] = Query(None, description="Filter by agent ID, e.g. AGT-01, AGT-08"),
    limit: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve immutable thought logs and intent formulations emitted by LLMs."""
    await verify_project_access(project_id, current_user, session)
    supervisor = WorkflowSupervisor(session)
    return await supervisor.list_agent_decisions(project_id, agent_id=agent_id, limit=limit)


@router.get(
    "/approvals",
    response_model=List[ApprovalRequestResponse],
    summary="List approval requests for high-risk actions"
)
async def list_approval_requests(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve human-in-the-loop approval gates."""
    await verify_project_access(project_id, current_user, session)
    stmt = (
        select(ApprovalRequest)
        .where(ApprovalRequest.project_id == project_id)
        .order_by(ApprovalRequest.requested_at.desc())
    )
    return list((await session.execute(stmt)).scalars().all())


@router.post(
    "/approvals/{approval_id}",
    response_model=ApprovalRequestResponse,
    summary="Submit operator authorization decision (Approve / Reject)"
)
async def decide_approval_request(
    project_id: uuid.UUID,
    approval_id: uuid.UUID,
    payload: ApprovalDecisionRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Authorize or reject suspended high-risk penetration testing operation."""
    await verify_project_access(project_id, current_user, session)
    supervisor = WorkflowSupervisor(session)

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        return await supervisor.handle_approval(
            approval_id=approval_id,
            project_id=project_id,
            decision=payload.decision,
            justification=payload.justification,
            user_id=current_user.id,
            ip_address=ip_address,
            user_agent=user_agent
        )
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
