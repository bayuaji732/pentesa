"""Report and report template database models for formal PTES deliverable generation."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin


class Report(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Published, immutable penetration test reports with cryptographic integrity sealing."""
    __tablename__ = "reports"
    __table_args__ = (
        Index("ix_reports_project", "project_id"),
        Index("ix_reports_hash", "file_hash_sha256"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    format: Mapped[str] = mapped_column(String(10), nullable=False)  # PDF, HTML
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    file_hash_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    is_finalized: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    generated_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    report_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType, nullable=True)

    # Relationships
    project: Mapped["Project"] = relationship("Project")
    generator: Mapped[Optional["User"]] = relationship("User")


class ReportTemplate(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Custom styling, branding, and section layout templates for reports."""
    __tablename__ = "report_templates"
    __table_args__ = (
        Index("ix_report_template_name", "name", unique=True),
    )

    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    jinja_template: Mapped[str] = mapped_column(Text, nullable=False)
    css_styles: Mapped[str] = mapped_column(Text, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

