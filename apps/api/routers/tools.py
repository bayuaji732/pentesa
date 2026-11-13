"""Security Tools execution and HTTP testing API router."""

import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.dependencies import get_current_user, verify_project_access
from database.models.user import User
from database.session import get_db
from packages.common.exceptions import BadRequestError, ResourceNotFoundError, ScopeViolationError, ToolNotAvailableError
from packages.schemas.tool import (
    HttpTestRequest,
    HttpTestResponse,
    ToolConfigUpdate,
    ToolExecutionRequest,
    ToolExecutionResponse,
    ToolInfoResponse
)
from services.execution_engine.tools.http_client import RawHttpClient
from services.execution_engine.tools.service import ToolService

router = APIRouter(tags=["Security Tools"])


# ---------------------------------------------------------------------------
# Global Tool Catalog
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/tools",
    response_model=List[ToolInfoResponse],
    summary="List available integrated security tools"
)
async def list_available_tools(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List supported security binaries (Nuclei, ffuf, Katana, httpx) and installation status."""
    service = ToolService(session)
    return service.list_tools()


# ---------------------------------------------------------------------------
# Project Tool Execution & Configuration
# ---------------------------------------------------------------------------

@router.post(
    "/api/v1/projects/{project_id}/tools/execute",
    response_model=ToolExecutionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Dispatch a scoped security tool execution"
)
async def execute_tool_run(
    project_id: uuid.UUID,
    payload: ToolExecutionRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Spawn a deterministic, scope-enforced security tool subprocess."""
    await verify_project_access(project_id, current_user, session)
    service = ToolService(session)

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        execution = await service.execute_tool(
            project_id=project_id,
            payload=payload,
            user_id=current_user.id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        return execution
    except ScopeViolationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ToolNotAvailableError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))
    except BadRequestError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/api/v1/projects/{project_id}/tools/executions",
    response_model=List[ToolExecutionResponse],
    summary="List historical tool executions for project"
)
async def list_project_tool_executions(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve historical tool runs and outcomes."""
    await verify_project_access(project_id, current_user, session)
    service = ToolService(session)
    return await service.list_tool_executions(project_id)


@router.get(
    "/api/v1/projects/{project_id}/tools/executions/{execution_id}",
    response_model=ToolExecutionResponse,
    summary="Get tool execution details"
)
async def get_tool_execution_details(
    project_id: uuid.UUID,
    execution_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve individual tool run record."""
    await verify_project_access(project_id, current_user, session)
    service = ToolService(session)
    try:
        return await service.get_tool_execution(execution_id)
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/api/v1/projects/{project_id}/tools/executions/{execution_id}/cancel",
    response_model=ToolExecutionResponse,
    summary="Cancel running tool execution"
)
async def cancel_tool_execution(
    project_id: uuid.UUID,
    execution_id: uuid.UUID,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Send termination signal to cancel ongoing tool run."""
    await verify_project_access(project_id, current_user, session)
    service = ToolService(session)

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        return await service.cancel_tool_execution(
            execution_id=execution_id,
            project_id=project_id,
            user_id=current_user.id,
            ip_address=ip_address,
            user_agent=user_agent
        )
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.put(
    "/api/v1/projects/{project_id}/tools/config",
    status_code=status.HTTP_200_OK,
    summary="Configure tool parameters for project"
)
async def update_project_tool_config(
    project_id: uuid.UUID,
    payload: ToolConfigUpdate,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Set custom rate limits and template tags for project security tools."""
    await verify_project_access(project_id, current_user, session)
    service = ToolService(session)
    cfg = await service.set_tool_config(
        project_id=project_id,
        tool_name=payload.tool_name,
        config_json=payload.config
    )
    return {"status": "SUCCESS", "tool_name": cfg.tool_name, "config": cfg.config_json}


# ---------------------------------------------------------------------------
# Raw HTTP Testing & Mutation
# ---------------------------------------------------------------------------

@router.post(
    "/api/v1/projects/{project_id}/tools/http-test",
    response_model=HttpTestResponse,
    summary="Execute raw scope-enforced HTTP test"
)
async def execute_raw_http_test(
    project_id: uuid.UUID,
    payload: HttpTestRequest,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Send an arbitrary HTTP request, enforce scope, and record forensic evidence."""
    await verify_project_access(project_id, current_user, session)
    client = RawHttpClient(session)

    try:
        return await client.execute_request(project_id, payload)
    except ScopeViolationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

