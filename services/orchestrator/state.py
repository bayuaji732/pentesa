"""Global Penetration Testing Workflow State and Checkpoint Ledger."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class PentestWorkflowState(BaseModel):
    """The unified, serializable state passed across all multi-agent phases in the workflow DAG."""
    model_config = ConfigDict(from_attributes=True)

    project_id: uuid.UUID
    workflow_id: Optional[uuid.UUID] = Field(default=None)
    current_phase: str = Field(
        default="RECON",
        description="PLANNING, RECON, MAPPING, WSTG_PLANNING, ACTIVE_ASSESSMENT, VALIDATION, REPORTING, COMPLETED"
    )
    status: str = Field(
        default="NOT_STARTED",
        description="NOT_STARTED, RUNNING, PAUSED, COMPLETED, STOPPED, FAILED, WAITING_APPROVAL"
    )
    scan_profile: str = Field(
        default="QUICK",
        description="QUICK, FULL, or DEEP assessment scan profile"
    )
    auto_approve_medium: bool = Field(default=True)
    target_base_url: Optional[str] = Field(default=None)
    approved_scope: Dict[str, Any] = Field(default_factory=dict)
    discovered_subdomains: List[str] = Field(default_factory=list)
    endpoints_inventory: List[Dict[str, Any]] = Field(default_factory=list)
    wstg_matrix_state: Dict[str, str] = Field(default_factory=dict)
    candidate_findings: List[Dict[str, Any]] = Field(default_factory=list)
    confirmed_findings: List[Dict[str, Any]] = Field(default_factory=list)
    false_positives: List[Dict[str, Any]] = Field(default_factory=list)
    active_agents: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    execution_logs: List[Dict[str, Any]] = Field(default_factory=list)
    pending_approvals: List[Dict[str, Any]] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def add_log(self, agent_id: str, message: str, level: str = "INFO"):
        """Append real-time log event."""
        self.execution_logs.append({
            "agent_id": agent_id,
            "level": level,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        self.updated_at = datetime.now(timezone.utc)

    def transition_phase(self, next_phase: str):
        """Update current active phase."""
        self.current_phase = next_phase
        self.updated_at = datetime.now(timezone.utc)
