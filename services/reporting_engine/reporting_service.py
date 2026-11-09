"""Reporting service orchestrating context assembly, document rendering, and cryptographic verification."""

import datetime
import hashlib
import os
import uuid
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.dependencies import record_audit_log
from database.models.project import Project
from database.models.report import Report, ReportTemplate
from database.models.user import User
from packages.common.exceptions import BadRequestError, ResourceNotFoundError
from packages.schemas.report import (
    ReportGenerateRequest,
    ReportResponse,
    ReportTemplateResponse,
    ReportVerificationResponse
)
from services.reporting_engine.context_builder import build_report_context
from services.reporting_engine.renderer import ReportRenderer


class ReportingService:
    """Service managing penetration test report generation, publishing, and verification."""

    def __init__(self, session: AsyncSession, renderer: Optional[ReportRenderer] = None):
        self.session = session
        self.renderer = renderer or ReportRenderer()

    async def generate_report(
        self,
        project_id: uuid.UUID,
        payload: ReportGenerateRequest,
        user: Optional[User] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Report:
        """Compile and publish formal PTES report in PDF or HTML format."""
        # 1. Verify project exists
        proj_stmt = select(Project).where(Project.id == project_id)
        project = (await self.session.execute(proj_stmt)).scalar_one_or_none()
        if not project:
            raise ResourceNotFoundError(f"Project with ID {project_id} not found.")

        # 2. Build Report Context
        context = await build_report_context(
            session=self.session,
            project_id=project_id,
            options=payload,
            user=user
        )

        # 3. Render Document
        export_format = payload.format.upper()
        if export_format == "PDF":
            file_path, file_hash = self.renderer.render_pdf(context)
        elif export_format == "HTML":
            file_path, file_hash = self.renderer.render_html(context, template_name="ptes_standard.html")
        else:
            raise BadRequestError(f"Unsupported report format: '{payload.format}'. Supported: PDF, HTML.")

        # 4. Create Database Record
        report_title = payload.title or f"PTES Penetration Test Report — {project.name}"
        report = Report(
            project_id=project_id,
            title=report_title,
            format=export_format,
            file_path=file_path,
            file_hash_sha256=file_hash,
            is_finalized=True,
            generated_by=user.id if user else None,
            report_metadata={
                "total_findings": context.total_findings,
                "critical_findings": context.critical_findings,
                "high_findings": context.high_findings,
                "coverage_score": context.coverage_score,
                "template_name": payload.template_name
            }
        )
        self.session.add(report)
        await self.session.commit()
        await self.session.refresh(report)

        # 5. Audit Logging
        await record_audit_log(
            session=self.session,
            action="REPORT_GENERATED",
            resource_type="Report",
            resource_id=str(report.id),
            details={
                "title": report.title,
                "format": report.format,
                "file_hash_sha256": file_hash,
                "findings_count": context.total_findings,
                "coverage_score": context.coverage_score
            },
            project_id=project_id,
            user_id=user.id if user else None,
            ip_address=ip_address,
            user_agent=user_agent
        )
        await self.session.commit()

        return report

    async def list_reports(self, project_id: uuid.UUID) -> List[Report]:
        """List all historical published reports for a project."""
        stmt = (
            select(Report)
            .where(Report.project_id == project_id)
            .order_by(desc(Report.created_at))
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_report(self, report_id: uuid.UUID, project_id: Optional[uuid.UUID] = None) -> Report:
        """Fetch report by ID with optional project ownership validation."""
        stmt = select(Report).where(Report.id == report_id)
        if project_id:
            stmt = stmt.where(Report.project_id == project_id)

        result = await self.session.execute(stmt)
        report = result.scalar_one_or_none()
        if not report:
            raise ResourceNotFoundError(f"Report with ID {report_id} not found.")
        return report

    async def delete_report(
        self,
        report_id: uuid.UUID,
        project_id: Optional[uuid.UUID] = None,
        user_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> None:
        """Delete historical report and file from disk."""
        report = await self.get_report(report_id, project_id)

        # Remove file from disk if present
        if os.path.exists(report.file_path):
            try:
                os.remove(report.file_path)
            except OSError:
                pass

        await self.session.delete(report)
        await self.session.commit()

        # Audit log deletion
        await record_audit_log(
            session=self.session,
            action="REPORT_DELETED",
            resource_type="Report",
            resource_id=str(report_id),
            details={
                "title": report.title,
                "file_hash_sha256": report.file_hash_sha256
            },
            project_id=project_id or report.project_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        await self.session.commit()

    async def verify_report_hash(self, file_hash_sha256: str) -> ReportVerificationResponse:
        """Verify the cryptographic authenticity of a report file using its SHA-256 hash."""
        clean_hash = file_hash_sha256.strip().lower()
        stmt = (
            select(Report)
            .where(Report.file_hash_sha256 == clean_hash)
        )
        report = (await self.session.execute(stmt)).scalar_one_or_none()
        if not report:
            return ReportVerificationResponse(
                verified=False,
                message="Hash not recognized. Report may be modified, unsealed, or not generated by this platform."
            )

        # Query project name
        proj_stmt = select(Project.name).where(Project.id == report.project_id)
        proj_name = (await self.session.execute(proj_stmt)).scalar_one_or_none()

        return ReportVerificationResponse(
            verified=True,
            report_id=report.id,
            project_id=report.project_id,
            project_name=proj_name or "Unknown Project",
            title=report.title,
            file_format=report.format,
            generated_at=report.created_at,
            message="Report authenticity cryptographically verified. SHA-256 digest matches sealed database record."
        )

    async def list_templates(self) -> List[ReportTemplateResponse]:
        """List standard and custom report templates."""
        # Built-in standard templates
        standards = [
            ReportTemplateResponse(
                id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
                name="ptes_standard",
                description="Comprehensive 17-section formal penetration test deliverable compliant with PTES and OWASP WSTG v4.2.",
                is_default=True,
                created_at=datetime.datetime(2026, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
            ),
            ReportTemplateResponse(
                id=uuid.UUID("00000000-0000-0000-0000-000000000002"),
                name="executive_summary",
                description="High-level 3-5 page security posture briefing with risk breakdown cards for CISOs and board members.",
                is_default=False,
                created_at=datetime.datetime(2026, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
            ),
            ReportTemplateResponse(
                id=uuid.UUID("00000000-0000-0000-0000-000000000003"),
                name="developer_remediation",
                description="Technical remediation workbook focused on exact reproduction curl commands and CWE code hardening.",
                is_default=False,
                created_at=datetime.datetime(2026, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
            ),
            ReportTemplateResponse(
                id=uuid.UUID("00000000-0000-0000-0000-000000000004"),
                name="wstg_compliance",
                description="Auditable compliance checklist detailing execution outcomes across all 12 WSTG categories for SOC 2 and ISO 27001.",
                is_default=False,
                created_at=datetime.datetime(2026, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
            )
        ]
        return standards
