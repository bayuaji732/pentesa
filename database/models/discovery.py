"""Attack surface discovery models: domains, endpoints, technologies, cookies, and headers."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin


class DiscoveredDomain(Base, UUIDPrimaryKeyMixin):
    """Enumerated hostnames and subdomains discovered for a project."""
    __tablename__ = "discovered_domains"
    __table_args__ = (
        UniqueConstraint("project_id", "fqdn", name="uq_discovered_domain"),
        Index("ix_discovered_domain_project", "project_id"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    fqdn: Mapped[str] = mapped_column(String(255), nullable=False)
    resolved_ips: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    discovery_source: Mapped[str] = mapped_column(String(50), nullable=False, default="crawler")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    project: Mapped["Project"] = relationship("Project")
    endpoints: Mapped[List["Endpoint"]] = relationship(
        "Endpoint",
        back_populates="domain",
        cascade="all, delete-orphan"
    )


class Endpoint(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Centralized attack surface endpoint inventory."""
    __tablename__ = "endpoints"
    __table_args__ = (
        UniqueConstraint("project_id", "fqdn", "url_path", "http_method", name="uq_endpoint_inventory"),
        Index("ix_endpoint_project_fqdn", "project_id", "fqdn"),
        Index("ix_endpoint_status", "project_id", "testing_status"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    domain_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid, ForeignKey("discovered_domains.id", ondelete="SET NULL"), nullable=True
    )
    fqdn: Mapped[str] = mapped_column(String(255), nullable=False)
    url_path: Mapped[str] = mapped_column(Text, nullable=False)
    http_method: Mapped[str] = mapped_column(String(20), default="GET", nullable=False)
    parameter_schema: Mapped[Dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    content_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    auth_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    discovery_source: Mapped[str] = mapped_column(String(50), default="CRAWLER", nullable=False)
    testing_status: Mapped[str] = mapped_column(String(50), default="Discovered", nullable=False)

    # Relationships
    project: Mapped["Project"] = relationship("Project")
    domain: Mapped[Optional["DiscoveredDomain"]] = relationship("DiscoveredDomain", back_populates="endpoints")
    headers: Mapped[List["SecurityHeader"]] = relationship(
        "SecurityHeader",
        back_populates="endpoint",
        cascade="all, delete-orphan"
    )


class Technology(Base, UUIDPrimaryKeyMixin):
    """Discovered framework and software stack fingerprint."""
    __tablename__ = "technologies"
    __table_args__ = (
        Index("ix_technology_project", "project_id"),
        Index("ix_technology_name", "project_id", "name"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    category: Mapped[str] = mapped_column(String(100), default="UNKNOWN", nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    detected_on_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    project: Mapped["Project"] = relationship("Project")


class Cookie(Base, UUIDPrimaryKeyMixin):
    """Discovered cookies and security attributes."""
    __tablename__ = "cookies"
    __table_args__ = (
        Index("ix_cookie_project", "project_id"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    path: Mapped[str] = mapped_column(String(255), default="/", nullable=False)
    is_secure: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_httponly: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    samesite: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    project: Mapped["Project"] = relationship("Project")


class SecurityHeader(Base, UUIDPrimaryKeyMixin):
    """Observed HTTP response security headers."""
    __tablename__ = "headers"
    __table_args__ = (
        Index("ix_header_project", "project_id"),
        Index("ix_header_endpoint", "endpoint_id"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    endpoint_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=True
    )
    header_name: Mapped[str] = mapped_column(String(255), nullable=False)
    header_value: Mapped[str] = mapped_column(Text, nullable=False)
    is_secure_standard: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    project: Mapped["Project"] = relationship("Project")
    endpoint: Mapped[Optional["Endpoint"]] = relationship("Endpoint", back_populates="headers")

