"""Authentication profile and credential vault models."""

import json
import uuid
from typing import Any, Dict, Optional, Union
from sqlalchemy import Boolean, ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin
from packages.common.security import decrypt_secret, encrypt_secret


class AuthProfile(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Target authentication profile storing encrypted credentials at rest (AES-256-GCM)."""
    __tablename__ = "auth_profiles"

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    auth_type: Mapped[str] = mapped_column(String(50), default="BEARER", nullable=False)
    
    # AES-256-GCM encrypted payload at rest
    encrypted_credentials: Mapped[str] = mapped_column(Text, nullable=False)
    
    # Non-sensitive header configurations (e.g. Content-Type, User-Agent)
    headers: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="auth_profiles")

    def set_credentials(
        self,
        credentials_data: Dict[str, Any],
        key: Optional[Union[bytes, str]] = None
    ) -> None:
        """Encrypt credentials dictionary at rest using AES-256-GCM."""
        payload_str = json.dumps(credentials_data)
        self.encrypted_credentials = encrypt_secret(payload_str, key=key)

    def get_credentials(
        self,
        key: Optional[Union[bytes, str]] = None
    ) -> Dict[str, Any]:
        """Decrypt credentials payload using AES-256-GCM."""
        if not self.encrypted_credentials:
            return {}
        decrypted_str = decrypt_secret(self.encrypted_credentials, key=key)
        return json.loads(decrypted_str)

    def get_masked_credentials(self, key: Optional[Union[bytes, str]] = None) -> Dict[str, str]:
        """Return masked credentials dictionary safe for display/audit."""
        try:
            creds = self.get_credentials(key=key)
        except Exception:
            return {"status": "[DECRYPTION_ERROR]"}

        masked: Dict[str, str] = {}
        for k, v in creds.items():
            str_val = str(v)
            if len(str_val) <= 6:
                masked[k] = "[REDACTED]"
            else:
                masked[k] = f"{str_val[:3]}...[REDACTED]...{str_val[-2:]}"
        return masked
