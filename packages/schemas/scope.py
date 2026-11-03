"""Scope rule and evaluation schemas."""

import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ScopeRuleType(str, Enum):
    """Classification of target scope rule."""
    DOMAIN_WILDCARD = "DOMAIN_WILDCARD"    # e.g. *.example.com
    EXACT_DOMAIN = "EXACT_DOMAIN"          # e.g. api.example.com
    IP_CIDR = "IP_CIDR"                    # e.g. 192.168.1.0/24
    EXACT_IP = "EXACT_IP"                  # e.g. 10.0.0.5
    PATH_PREFIX = "PATH_PREFIX"            # e.g. /api/v1/
    EXCLUDED_PATH = "EXCLUDED_PATH"        # e.g. /logout or /oauth/callback


class ScopeTargetType(str, Enum):
    """Disposition of rule: explicit inclusion or strict exclusion."""
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


class ScopeRuleBase(BaseModel):
    """Base fields for a scope rule."""
    rule_type: ScopeRuleType
    target_type: ScopeTargetType = ScopeTargetType.IN_SCOPE
    pattern: str = Field(min_length=1, max_length=500, description="Domain, CIDR, IP, or path pattern")
    port_range: Optional[str] = Field(default=None, description="e.g. 80,443 or 8000-8080. None allows default 80/443")
    protocol: Optional[str] = Field(default="https,http", description="Allowed protocols: http, https")
    is_critical: bool = Field(default=False, description="Flag for sensitive production targets")
    notes: Optional[str] = Field(default=None, max_length=500)


class ScopeRuleCreate(ScopeRuleBase):
    """Payload to add a scope rule to a project."""
    pass


class ScopeRuleResponse(ScopeRuleBase):
    """Scope rule representation."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    created_at: datetime


class ScopeCheckRequest(BaseModel):
    """Request payload to test if a target URL or host is in scope."""
    url: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    path: Optional[str] = None


class ScopeCheckResult(BaseModel):
    """Result of scope evaluation."""
    is_in_scope: bool
    status: str  # "ALLOWED", "BLOCKED", "EXCLUDED", "PRIVATE_NETWORK_BLOCKED", "DNS_REBINDING_VIOLATION"
    reason: str
    target_url: Optional[str] = None
    evaluated_host: Optional[str] = None
    evaluated_port: Optional[int] = None
    matched_rule_id: Optional[uuid.UUID] = None
    resolved_ips: List[str] = Field(default_factory=list)
    dns_rebinding_detected: bool = False
