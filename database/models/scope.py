"""ScopeRule model definition."""

import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import Boolean, DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.base import Base, UUIDPrimaryKeyMixin


class ScopeRule(Base, UUIDPrimaryKeyMixin):
    """Scope target rule for a project."""
    __tablename__ = "scope_rules"

    project_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False)
    rule_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_type: Mapped[str] = mapped_column(String(20), default="IN_SCOPE", nullable=False)
    pattern: Mapped[str] = mapped_column(String(500), nullable=False)
    port_range: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(50), default="https,http", nullable=True)
    is_critical: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="scope_rules")
