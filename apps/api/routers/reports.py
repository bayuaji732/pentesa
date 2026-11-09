"""PTES Report Generation, Download, and Cryptographic Verification API Router."""

import os
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.dependencies import get_current_user, verify_project_access
from database.models.user import User
from database.session import get_db
from packages.common.exceptions import BadRequestError, ResourceNotFoundError
from packages.schemas.report import (
    ReportGenerateRequest,
    ReportResponse,
    ReportTemplateResponse,
    ReportVerificationRequest,
    ReportVerificationResponse
)
from services.reporting_engine.reporting_service import ReportingService

router = APIRouter(tags=["PTES Reporting"])


@router.post(
    "/api/v1/projects/{project_id}/reports/generate",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate and publish formal PTES report"
)
async def generate_project_report(
    project_id: uuid.UUID,
    payload: ReportGenerateRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Compile and publish formal Penetration Testing Execution Standard (PTES) report in PDF or HTML."""
    await verify_project_access(project_id, current_user, session)
    service = ReportingService(session)

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        report = await service.generate_report(
            project_id=project_id,
            payload=payload,
            user=current_user,
            ip_address=ip_address,
            user_agent=user_agent
        )
        resp = ReportResponse.model_validate(report)
        resp.download_url = f"/api/v1/reports/{report.id}/download"
        return resp
    except BadRequestError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/api/v1/projects/{project_id}/reports",
    response_model=List[ReportResponse],
    summary="List historical published reports"
)
async def list_project_reports(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve all published penetration test reports for a project."""
    await verify_project_access(project_id, current_user, session)
    service = ReportingService(session)
    reports = await service.list_reports(project_id)

    results = []
    for r in reports:
        item = ReportResponse.model_validate(r)
        item.download_url = f"/api/v1/reports/{r.id}/download"
        results.append(item)
    return results


@router.get(
    "/api/v1/reports/{report_id}/download",
    summary="Download compiled PDF or HTML report file"
)
async def download_report_file(
    report_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Stream raw PDF or HTML report deliverable file to client."""
    service = ReportingService(session)
    try:
        report = await service.get_report(report_id)
        # Verify access to report's project
        await verify_project_access(report.project_id, current_user, session)

        if not os.path.exists(report.file_path):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file not found on disk.")

        media_type = "application/pdf" if report.format == "PDF" else "text/html"
        filename = os.path.basename(report.file_path)

        return FileResponse(
            path=report.file_path,
            media_type=media_type,
            filename=filename,
            headers={
                "X-Report-SHA256": report.file_hash_sha256,
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/api/v1/reports/templates",
    response_model=List[ReportTemplateResponse],
    summary="List available report templates"
)
async def list_report_templates(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List standard PTES and compliance report templates."""
    service = ReportingService(session)
    return await service.list_templates()


@router.delete(
    "/api/v1/reports/{report_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete historical report"
)
async def delete_report(
    report_id: uuid.UUID,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a published report record and remove file artifact from disk."""
    service = ReportingService(session)
    try:
        report = await service.get_report(report_id)
        await verify_project_access(report.project_id, current_user, session)

        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        await service.delete_report(
            report_id=report_id,
            project_id=report.project_id,
            user_id=current_user.id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/api/v1/reports/verify",
    response_model=ReportVerificationResponse,
    summary="Cryptographically verify report authenticity"
)
async def verify_report_authenticity(
    payload: ReportVerificationRequest,
    session: AsyncSession = Depends(get_db)
):
    """Verify cryptographic authenticity of a report using its SHA-256 digest against sealed platform records."""
    service = ReportingService(session)
    return await service.verify_report_hash(payload.file_hash_sha256)

