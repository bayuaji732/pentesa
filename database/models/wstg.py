"""OWASP WSTG test catalog, project instances, test executions, and streaming logs."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Boolean,
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

from database.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin


class WSTGTestCatalog(Base):
    """Master reference catalog of all OWASP WSTG v4.2 test cases."""
    __tablename__ = "wstg_test_catalog"

    id: Mapped[str] = mapped_column(String(50), primary_key=True)  # e.g. "WSTG-INPV-05"
    category: Mapped[str] = mapped_column(String(120), nullable=False)  # e.g. "Input Validation"
    category_code: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # e.g. "WSTG-INPV"
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    automation_capability: Mapped[str] = mapped_column(String(50), nullable=False)  # "Full", "Partial", "Manual"
    default_risk: Mapped[str] = mapped_column(String(50), nullable=False)  # "Critical", "High", "Medium", "Low", "Info"
    cwe_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # e.g. "CWE-89"
    owasp_category: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)  # e.g. "A03:2021-Injection"
    required_tools: Mapped[List[str]] = mapped_column(JSONType, default=list, nullable=False)
    requires_human_review: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    endpoint_types: Mapped[List[str]] = mapped_column(JSONType, default=list, nullable=False)

    # Relationships
    instances: Mapped[List["WSTGTestInstance"]] = relationship(
        "WSTGTestInstance",
        back_populates="catalog_item",
        cascade="all, delete-orphan"
    )


class WSTGTestInstance(Base, UUIDPrimaryKeyMixin):
    """Project-specific instantiation and status tracking of a WSTG test case."""
    __tablename__ = "wstg_test_instances"
    __table_args__ = (
        UniqueConstraint("project_id", "wstg_id", name="uq_project_wstg_instance"),
        Index("ix_wstg_instance_project_status", "project_id", "status"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    wstg_id: Mapped[str] = mapped_column(
        String(50), ForeignKey("wstg_test_catalog.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(50), default="Not Started", nullable=False
    )  # Not Started, Planned, Running, Passed, Failed, Needs Manual Review, Not Applicable, Blocked, Error
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    applicable_endpoints_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    project: Mapped["Project"] = relationship("Project")
    catalog_item: Mapped["WSTGTestCatalog"] = relationship("WSTGTestCatalog", back_populates="instances")
    executions: Mapped[List["TestExecution"]] = relationship(
        "TestExecution",
        back_populates="instance",
        cascade="all, delete-orphan"
    )


class TestExecution(Base, UUIDPrimaryKeyMixin):
    """Individual automated, agent, or manual execution of a WSTG test instance."""
    __tablename__ = "test_executions"
    __test__ = False
    __table_args__ = (
        Index("ix_test_exec_project", "project_id"),
        Index("ix_test_exec_instance", "wstg_instance_id"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    wstg_instance_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("wstg_test_instances.id", ondelete="CASCADE"), nullable=False
    )
    endpoint_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid, ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(50), default="QUEUED", nullable=False
    )  # QUEUED, RUNNING, PASSED, FAILED, NEEDS_REVIEW, ERROR, CANCELLED
    runner_type: Mapped[str] = mapped_column(
        String(50), default="AUTOMATED", nullable=False
    )  # AUTOMATED, AGENT, MANUAL
    start_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    end_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    project: Mapped["Project"] = relationship("Project")
    instance: Mapped["WSTGTestInstance"] = relationship("WSTGTestInstance", back_populates="executions")
    endpoint: Mapped[Optional["Endpoint"]] = relationship("Endpoint")
    logs: Mapped[List["TestExecutionLog"]] = relationship(
        "TestExecutionLog",
        back_populates="execution",
        cascade="all, delete-orphan"
    )


class TestExecutionLog(Base, UUIDPrimaryKeyMixin):
    """Streaming log entries emitted during a test execution."""
    __tablename__ = "test_execution_logs"
    __test__ = False
    __table_args__ = (
        Index("ix_test_log_execution", "execution_id"),
    )

    execution_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("test_executions.id", ondelete="CASCADE"), nullable=False
    )
    log_level: Mapped[str] = mapped_column(String(20), default="INFO", nullable=False)  # INFO, WARNING, ERROR, DEBUG
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationship
    execution: Mapped["TestExecution"] = relationship("TestExecution", back_populates="logs")
