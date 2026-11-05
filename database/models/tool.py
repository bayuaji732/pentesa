"""Tool execution tracking and per-project tool configuration models."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.base import Base, JSONType, UUIDPrimaryKeyMixin


class ToolExecution(Base, UUIDPrimaryKeyMixin):
    """Execution record for security tool subprocesses (nuclei, ffuf, etc.)."""
    __tablename__ = "tool_executions"
    __test__ = False
    __table_args__ = (
        Index("ix_tool_exec_project", "project_id"),
        Index("ix_tool_exec_tool", "project_id", "tool_name"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    tool_name: Mapped[str] = mapped_column(String(50), nullable=False)  # nuclei, ffuf, katana, httpx, etc.
    target_url: Mapped[str] = mapped_column(String(500), nullable=False)
    argv: Mapped[List[str]] = mapped_column(JSONType, default=list, nullable=False)
    status: Mapped[str] = mapped_column(
        String(30), default="QUEUED", nullable=False
    )  # QUEUED, RUNNING, SUCCESS, FAILED, TIMEOUT, CANCELLED, SCOPE_REJECTED
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    stdout_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    stderr_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    raw_artifacts_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    project: Mapped["Project"] = relationship("Project")


class ToolConfiguration(Base, UUIDPrimaryKeyMixin):
    """Project-level tool execution parameters, rate limits, and custom flags."""
    __tablename__ = "tool_configurations"
    __table_args__ = (
        UniqueConstraint("project_id", "tool_name", name="uq_project_tool_config"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    tool_name: Mapped[str] = mapped_column(String(50), nullable=False)  # nuclei, ffuf, katana
    config_json: Mapped[Dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    project: Mapped["Project"] = relationship("Project")

