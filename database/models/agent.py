"""AI Agent observability and workflow execution models."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin


class AgentExecution(Base, UUIDPrimaryKeyMixin):
    """Lifecycle records for each autonomous agent invocation/dispatch."""
    __tablename__ = "agent_executions"
    __table_args__ = (
        Index("ix_agent_execution_project", "project_id"),
        Index("ix_agent_execution_agent_id", "agent_id"),
        Index("ix_agent_execution_status", "status"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    agent_id: Mapped[str] = mapped_column(String(50), nullable=False)  # e.g. AGT-01, AGT-08
    agent_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), default="QUEUED", nullable=False
    )  # QUEUED, RUNNING, COMPLETED, FAILED, PAUSED, WAITING_APPROVAL
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_cost_usd: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    project: Mapped["Project"] = relationship("Project")
    decisions: Mapped[List["AgentDecision"]] = relationship(
        "AgentDecision", back_populates="execution", cascade="all, delete-orphan"
    )
    tool_calls: Mapped[List["AgentToolCall"]] = relationship(
        "AgentToolCall", back_populates="execution", cascade="all, delete-orphan"
    )


class AgentDecision(Base, UUIDPrimaryKeyMixin):
    """Reasoning traces, intent formulations, and thought logs emitted by agents."""
    __tablename__ = "agent_decisions"
    __table_args__ = (
        Index("ix_agent_decision_exec", "agent_execution_id"),
    )

    agent_execution_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("agent_executions.id", ondelete="CASCADE"), nullable=False
    )
    thought_trace: Mapped[str] = mapped_column(Text, nullable=False)
    intent: Mapped[str] = mapped_column(String(500), nullable=False)
    context_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationship
    execution: Mapped["AgentExecution"] = relationship("AgentExecution", back_populates="decisions")


class AgentToolCall(Base, UUIDPrimaryKeyMixin):
    """Typed tool actions requested and executed by an agent."""
    __tablename__ = "agent_tool_calls"
    __table_args__ = (
        Index("ix_agent_tool_exec", "agent_execution_id"),
    )

    agent_execution_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("agent_executions.id", ondelete="CASCADE"), nullable=False
    )
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    input_arguments: Mapped[Dict[str, Any]] = mapped_column(JSONType, nullable=False)
    output_result: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType, nullable=True)
    status: Mapped[str] = mapped_column(
        String(30), default="PENDING", nullable=False
    )  # PENDING, SUCCESS, FAILED, SCOPE_REJECTED
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationship
    execution: Mapped["AgentExecution"] = relationship("AgentExecution", back_populates="tool_calls")


class WorkflowExecution(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Durable checkpointed state of the multi-agent penetration testing workflow DAG."""
    __tablename__ = "workflow_executions"
    __table_args__ = (
        Index("ix_workflow_execution_project", "project_id"),
        Index("ix_workflow_execution_status", "status"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    current_phase: Mapped[str] = mapped_column(
        String(50), default="RECON", nullable=False
    )  # RECON, MAPPING, WSTG_PLANNING, ACTIVE_ASSESSMENT, VALIDATION, REPORTING, COMPLETED
    status: Mapped[str] = mapped_column(
        String(50), default="NOT_STARTED", nullable=False
    )  # NOT_STARTED, RUNNING, PAUSED, COMPLETED, STOPPED, FAILED, WAITING_APPROVAL
    state_data: Mapped[Dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    project: Mapped["Project"] = relationship("Project")
    approval_requests: Mapped[List["ApprovalRequest"]] = relationship(
        "ApprovalRequest", back_populates="workflow", cascade="all, delete-orphan"
    )


class ApprovalRequest(Base, UUIDPrimaryKeyMixin):
    """Human-in-the-loop approval gate for high-risk penetration testing actions."""
    __tablename__ = "approval_requests"
    __table_args__ = (
        Index("ix_approval_request_project", "project_id"),
        Index("ix_approval_request_status", "status"),
    )

    workflow_execution_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid, ForeignKey("workflow_executions.id", ondelete="CASCADE"), nullable=True
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    agent_id: Mapped[str] = mapped_column(String(50), nullable=False)
    action: Mapped[str] = mapped_column(String(500), nullable=False)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(50), default="MEDIUM", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    parameters: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType, nullable=True)
    status: Mapped[str] = mapped_column(
        String(50), default="PENDING", nullable=False
    )  # PENDING, APPROVED, REJECTED
    justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    decided_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    workflow: Mapped[Optional["WorkflowExecution"]] = relationship("WorkflowExecution", back_populates="approval_requests")
    project: Mapped["Project"] = relationship("Project")
    approver: Mapped[Optional["User"]] = relationship("User")
