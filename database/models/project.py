"""Project and ProjectMember model definitions."""

import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin


class Project(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Penetration testing project engagement."""
    __tablename__ = "projects"

    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="PLANNING", index=True, nullable=False)
    
    target_domains: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    allowed_cidrs: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    excluded_paths: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    allow_internal_networks: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    
    authorization_document_ref: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    authorization_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    authorization_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)

    # Relationships
    members: Mapped[List["ProjectMember"]] = relationship(
        "ProjectMember",
        back_populates="project",
        cascade="all, delete-orphan"
    )
    scope_rules: Mapped[List["ScopeRule"]] = relationship(
        "ScopeRule",
        back_populates="project",
        cascade="all, delete-orphan"
    )


class ProjectMember(Base, UUIDPrimaryKeyMixin):
    """Project membership and role assignment."""
    __tablename__ = "project_members"
    __table_args__ = (
        UniqueConstraint("project_id", "user_id", name="uq_project_member"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="TESTER", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="members")
    user: Mapped["User"] = relationship("User", back_populates="memberships")
