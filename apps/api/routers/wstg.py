"""OWASP WSTG Catalog, Test Planning, Coverage, and Execution API Router."""

import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.dependencies import get_current_user, verify_project_access
from database.models.user import User
from database.models.wstg import TestExecution, WSTGTestInstance
from database.session import get_db
from packages.common.exceptions import BadRequestException, NotFoundException, ScopeViolationException
from packages.schemas.wstg import (
    TestExecutionCreate,
    TestExecutionLogResponse,
    TestExecutionResponse,
    TestPlanRecalculateResponse,
    WSTGCatalogItemResponse,
    WSTGCoverageReport,
    WSTGTestInstanceResponse,
    WSTGTestInstanceUpdate
)
from services.execution_engine.service import WSTGExecutionService

router = APIRouter(tags=["OWASP WSTG"])


# ---------------------------------------------------------------------------
# Master WSTG Catalog
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/wstg/catalog",
    response_model=List[WSTGCatalogItemResponse],
    summary="Retrieve master OWASP WSTG v4.2 test catalog"
)
async def get_wstg_catalog(
    category_code: Optional[str] = Query(None, description="Filter by category code (e.g. WSTG-INPV)"),
    automation_capability: Optional[str] = Query(None, description="Filter by Full, Partial, or Manual"),
    search: Optional[str] = Query(None, description="Search by ID, name, or description"),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve all 106 official OWASP WSTG v4.2 test catalog definitions."""
    service = WSTGExecutionService(session)
    items = await service.list_catalog(
        category_code=category_code,
        automation_capability=automation_capability,
        search=search
    )
    return items


# ---------------------------------------------------------------------------
# Project Test Plan & Matrix
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/projects/{project_id}/wstg/plan",
    response_model=List[WSTGTestInstanceResponse],
    summary="Retrieve project-specific WSTG test plan"
)
async def get_project_wstg_plan(
    project_id: uuid.UUID,
    category_code: Optional[str] = Query(None, description="Filter by category code"),
    status: Optional[str] = Query(None, description="Filter by test status"),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve instantiated WSTG test plan for a project with status and applicability."""
    await verify_project_access(project_id, current_user, session)
    service = WSTGExecutionService(session)
    plan = await service.get_project_plan(
        project_id=project_id,
        category_code=category_code,
        status=status
    )
    return plan


@router.patch(
    "/api/v1/projects/{project_id}/wstg/tests/{test_instance_id}",
    response_model=WSTGTestInstanceResponse,
    summary="Update test instance status, notes, or justification"
)
async def update_wstg_test_instance(
    project_id: uuid.UUID,
    test_instance_id: uuid.UUID,
    payload: WSTGTestInstanceUpdate,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update status, notes, or justification for a project test instance.
    
    Enforces the finite state machine and logs changes to the tamper-evident audit trail.
    """
    await verify_project_access(project_id, current_user, session)
    service = WSTGExecutionService(session)

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        updated = await service.update_test_instance(
            project_id=project_id,
            instance_id=test_instance_id,
            payload=payload,
            user_id=current_user.id,
            ip_address=ip_address,
            user_agent=user_agent
        )
    except BadRequestException as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except NotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    # Re-fetch instance with joined catalog item to return WSTGTestInstanceResponse
    plan = await service.get_project_plan(project_id=project_id)
    matched = next((p for p in plan if p["id"] == updated.id), None)
    if not matched:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Instance not found.")
    return matched


# ---------------------------------------------------------------------------
# Coverage Metrics
# ---------------------------------------------------------------------------

@router.get(
    "/api/v1/projects/{project_id}/wstg/coverage",
    response_model=WSTGCoverageReport,
    summary="Retrieve empirical mathematical coverage report"
)
async def get_project_wstg_coverage(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Calculate and return empirical coverage metrics and health score."""
    await verify_project_access(project_id, current_user, session)
    service = WSTGExecutionService(session)
    return await service.get_coverage_report(project_id)


@router.post(
    "/api/v1/projects/{project_id}/wstg/recalculate",
    response_model=TestPlanRecalculateResponse,
    summary="Recalculate test plan applicability against attack surface"
)
async def recalculate_wstg_test_plan(
    project_id: uuid.UUID,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Recalculate test applicability and planned counts against newly discovered attack surface."""
    await verify_project_access(project_id, current_user, session)
    service = WSTGExecutionService(session)

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    result = await service.recalculate_plan(
        project_id=project_id,
        user_id=current_user.id,
        ip_address=ip_address,
        user_agent=user_agent
    )
    return TestPlanRecalculateResponse(
        project_id=project_id,
        total_instances=result["total_instances"],
        planned_count=result["planned_count"],
        not_applicable_count=result["not_applicable_count"],
        summary=result["summary"]
    )


# ---------------------------------------------------------------------------
# Test Execution
# ---------------------------------------------------------------------------

@router.post(
    "/api/v1/projects/{project_id}/wstg/execute/{wstg_id}",
    response_model=TestExecutionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Dispatch a WSTG test execution"
)
async def execute_wstg_test(
    project_id: uuid.UUID,
    wstg_id: str,
    endpoint_id: Optional[uuid.UUID] = Query(None, description="Optional target endpoint ID"),
    runner_type: Optional[str] = Query("AUTOMATED", description="Runner type: AUTOMATED, AGENT, MANUAL"),
    request: Request = None,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Dispatch an automated, agent, or manual execution of a WSTG test case.
    
    Validates scope before execution, streams forensic execution logs, and updates
    test instance status upon completion.
    """
    await verify_project_access(project_id, current_user, session)
    service = WSTGExecutionService(session)

    ip_address = request.client.host if request and request.client else None
    user_agent = request.headers.get("user-agent") if request else None

    payload = TestExecutionCreate(
        wstg_id=wstg_id,
        endpoint_id=endpoint_id,
        runner_type=runner_type
    )

    try:
        execution = await service.dispatch_execution(
            project_id=project_id,
            payload=payload,
            user_id=current_user.id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        return TestExecutionResponse(
            id=execution.id,
            project_id=execution.project_id,
            wstg_instance_id=execution.wstg_instance_id,
            wstg_id=wstg_id,
            endpoint_id=execution.endpoint_id,
            status=execution.status,
            runner_type=execution.runner_type,
            start_time=execution.start_time,
            end_time=execution.end_time,
            exit_code=execution.exit_code,
            summary=execution.summary
        )
    except NotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ScopeViolationException as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.get(
    "/api/v1/projects/{project_id}/wstg/executions/{execution_id}",
    response_model=TestExecutionResponse,
    summary="Retrieve execution details"
)
async def get_test_execution_details(
    project_id: uuid.UUID,
    execution_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve detailed execution run record and timing."""
    await verify_project_access(project_id, current_user, session)
    service = WSTGExecutionService(session)

    try:
        exec_record = await service.get_execution(execution_id)
        # Fetch instance to obtain wstg_id
        inst_stmt = select(WSTGTestInstance).where(WSTGTestInstance.id == exec_record.wstg_instance_id)
        instance = (await session.execute(inst_stmt)).scalar_one()

        return TestExecutionResponse(
            id=exec_record.id,
            project_id=exec_record.project_id,
            wstg_instance_id=exec_record.wstg_instance_id,
            wstg_id=instance.wstg_id,
            endpoint_id=exec_record.endpoint_id,
            status=exec_record.status,
            runner_type=exec_record.runner_type,
            start_time=exec_record.start_time,
            end_time=exec_record.end_time,
            exit_code=exec_record.exit_code,
            summary=exec_record.summary
        )
    except NotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/api/v1/projects/{project_id}/wstg/executions/{execution_id}/logs",
    response_model=List[TestExecutionLogResponse],
    summary="Retrieve execution logs"
)
async def get_test_execution_logs(
    project_id: uuid.UUID,
    execution_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve forensic streaming logs for a test execution."""
    await verify_project_access(project_id, current_user, session)
    service = WSTGExecutionService(session)

    logs = await service.get_execution_logs(execution_id)
    return [
        TestExecutionLogResponse(
            id=log.id,
            execution_id=log.execution_id,
            log_level=log.log_level,
            message=log.message,
            created_at=log.created_at
        )
        for log in logs
    ]

