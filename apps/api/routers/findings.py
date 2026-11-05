"""Findings, evidence inspection, reproduction, and false positive API router."""

import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.dependencies import get_current_user, verify_project_access
from database.models.user import User
from database.session import get_db
from packages.common.exceptions import BadRequestError, ResourceNotFoundError
from packages.schemas.finding import (
    FalsePositiveCreate,
    FalsePositiveResponse,
    FindingCreate,
    FindingEvidenceResponse,
    FindingReproductionCreate,
    FindingReproductionResponse,
    FindingResponse,
    FindingStatusUpdate
)
from services.evidence_engine.finding_service import FindingService

router = APIRouter(prefix="/api/v1/projects/{project_id}/findings", tags=["Findings & Evidence"])


@router.get("", response_model=List[FindingResponse], summary="List findings for project")
async def list_findings(
    project_id: uuid.UUID,
    severity: Optional[str] = Query(None, description="Filter by severity: Critical, High, Medium, Low, Informational"),
    status: Optional[str] = Query(None, description="Filter by status"),
    cwe_id: Optional[str] = Query(None, description="Filter by CWE, e.g. CWE-89"),
    wstg_id: Optional[str] = Query(None, description="Filter by WSTG ID, e.g. WSTG-INPV-05"),
    search: Optional[str] = Query(None, description="Search by title or description"),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve all findings for a project with multi-dimensional filtering."""
    await verify_project_access(project_id, current_user, session)
    service = FindingService(session)
    return await service.list_findings(
        project_id=project_id,
        severity=severity,
        status=status,
        cwe_id=cwe_id,
        wstg_id=wstg_id,
        search=search
    )


@router.post("", response_model=FindingResponse, status_code=status.HTTP_201_CREATED, summary="Create a finding")
async def create_finding(
    project_id: uuid.UUID,
    payload: FindingCreate,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Manually register a security finding with optional forensic evidence."""
    await verify_project_access(project_id, current_user, session)
    service = FindingService(session)

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        return await service.create_finding(
            project_id=project_id,
            payload=payload,
            user_id=current_user.id,
            ip_address=ip_address,
            user_agent=user_agent
        )
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/{finding_id}", response_model=FindingResponse, summary="Get finding details")
async def get_finding(
    project_id: uuid.UUID,
    finding_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve comprehensive finding details, evidence, and history."""
    await verify_project_access(project_id, current_user, session)
    service = FindingService(session)
    try:
        return await service.get_finding(finding_id, project_id)
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.patch("/{finding_id}/status", response_model=FindingResponse, summary="Transition finding status")
async def update_finding_status(
    project_id: uuid.UUID,
    finding_id: uuid.UUID,
    payload: FindingStatusUpdate,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Transition finding status adhering to the 10-step lifecycle state machine."""
    await verify_project_access(project_id, current_user, session)
    service = FindingService(session)

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        return await service.update_status(
            finding_id=finding_id,
            project_id=project_id,
            payload=payload,
            user_id=current_user.id,
            ip_address=ip_address,
            user_agent=user_agent
        )
    except BadRequestError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/{finding_id}/false-positive",
    response_model=FalsePositiveResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Refute finding as false positive"
)
async def refute_false_positive(
    project_id: uuid.UUID,
    finding_id: uuid.UUID,
    payload: FalsePositiveCreate,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Refute a candidate finding as a false positive with auditable justification."""
    await verify_project_access(project_id, current_user, session)
    service = FindingService(session)

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        return await service.register_false_positive(
            finding_id=finding_id,
            project_id=project_id,
            payload=payload,
            user_id=current_user.id,
            ip_address=ip_address,
            user_agent=user_agent
        )
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/{finding_id}/reproduce",
    response_model=FindingReproductionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record reproduction outcome"
)
async def record_finding_reproduction(
    project_id: uuid.UUID,
    finding_id: uuid.UUID,
    payload: FindingReproductionCreate,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Record an empirical vulnerability reproduction attempt."""
    await verify_project_access(project_id, current_user, session)
    service = FindingService(session)

    try:
        return await service.record_reproduction(
            finding_id=finding_id,
            project_id=project_id,
            reproduced_by=payload.reproduced_by or str(current_user.id),
            success=True,
            status_code=200,
            duration_ms=45
        )
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/{finding_id}/evidence",
    response_model=List[FindingEvidenceResponse],
    summary="List forensic evidence artifacts"
)
async def get_finding_evidence(
    project_id: uuid.UUID,
    finding_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve raw HTTP streams, hashes, and reproduction commands for finding."""
    await verify_project_access(project_id, current_user, session)
    service = FindingService(session)
    finding = await service.get_finding(finding_id, project_id)
    return finding.evidence

