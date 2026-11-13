"""Findings, forensic evidence, reproductions, status history, and false positive models."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin


class Finding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Confirmed and candidate security vulnerabilities identified during testing."""
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_finding_project", "project_id"),
        Index("ix_finding_severity", "project_id", "severity"),
        Index("ix_finding_status", "project_id", "status"),
        Index("ix_finding_wstg", "project_id", "wstg_id"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    endpoint_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid, ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True
    )
    wstg_id: Mapped[Optional[str]] = mapped_column(
        String(50), ForeignKey("wstg_test_catalog.id", ondelete="SET NULL"), nullable=True
    )

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # Critical, High, Medium, Low, Informational
    cvss_score: Mapped[Optional[float]] = mapped_column(Numeric(3, 1), nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    cwe_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # e.g. "CWE-89"
    owasp_category: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)  # e.g. "A03:2021-Injection"
    affected_parameter: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    detection_source: Mapped[str] = mapped_column(String(100), nullable=False)  # nuclei, ffuf, agent_auth, manual
    status: Mapped[str] = mapped_column(
        String(50), default="Detected", nullable=False
    )  # Detected, Triaged, Validating, Confirmed, False Positive, Needs Manual Review, Remediated, Retested, Accepted Risk
    confidence: Mapped[str] = mapped_column(
        String(50), default="Medium", nullable=False
    )  # Confirmed, High, Medium, Low
    remediation_guidance: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    business_impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    project: Mapped["Project"] = relationship("Project")
    endpoint: Mapped[Optional["Endpoint"]] = relationship("Endpoint")
    evidence: Mapped[List["FindingEvidence"]] = relationship(
        "FindingEvidence",
        back_populates="finding",
        cascade="all, delete-orphan"
    )
    reproductions: Mapped[List["FindingReproduction"]] = relationship(
        "FindingReproduction",
        back_populates="finding",
        cascade="all, delete-orphan"
    )
    status_history: Mapped[List["FindingStatusHistory"]] = relationship(
        "FindingStatusHistory",
        back_populates="finding",
        cascade="all, delete-orphan"
    )
    false_positives: Mapped[List["FalsePositive"]] = relationship(
        "FalsePositive",
        back_populates="finding",
        cascade="all, delete-orphan"
    )


class FindingEvidence(Base, UUIDPrimaryKeyMixin):
    """Forensic raw HTTP streams, reproduction commands, and cryptographic hashes."""
    __tablename__ = "finding_evidence"
    __table_args__ = (
        Index("ix_evidence_finding", "finding_id"),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    raw_request: Mapped[str] = mapped_column(Text, nullable=False)  # Sanitized/redacted raw HTTP request
    raw_response: Mapped[str] = mapped_column(Text, nullable=False)  # Sanitized raw HTTP response
    raw_response_bytes_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    reproduction_curl: Mapped[str] = mapped_column(Text, nullable=False)
    request_hash_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    response_hash_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    screenshot_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationship
    finding: Mapped["Finding"] = relationship("Finding", back_populates="evidence")


class FindingReproduction(Base, UUIDPrimaryKeyMixin):
    """Automated and manual verification/reproduction attempts."""
    __tablename__ = "finding_reproductions"
    __table_args__ = (
        Index("ix_reproduction_finding", "finding_id"),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    reproduced_by: Mapped[str] = mapped_column(String(100), nullable=False)  # Agent ID or User UUID
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    response_status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationship
    finding: Mapped["Finding"] = relationship("Finding", back_populates="reproductions")


class FindingStatusHistory(Base, UUIDPrimaryKeyMixin):
    """Audit trail of finding status transitions."""
    __tablename__ = "finding_status_history"
    __table_args__ = (
        Index("ix_status_history_finding", "finding_id"),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    previous_status: Mapped[str] = mapped_column(String(50), nullable=False)
    new_status: Mapped[str] = mapped_column(String(50), nullable=False)
    changed_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationship
    finding: Mapped["Finding"] = relationship("Finding", back_populates="status_history")


class FalsePositive(Base, UUIDPrimaryKeyMixin):
    """Records documenting refuted candidate detections."""
    __tablename__ = "false_positives"
    __table_args__ = (
        Index("ix_false_positive_finding", "finding_id"),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    classification: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # e.g. "STATIC_PAGE_REFLECTION", "WAF_BLOCK_PAGE", "CUSTOM_ERROR_PAGE"
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationship
    finding: Mapped["Finding"] = relationship("Finding", back_populates="false_positives")

