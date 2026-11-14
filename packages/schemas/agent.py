"""Pydantic schemas for AI Agent Observability, Workflow, Decisions, and Approval Gates."""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AgentStatusResponse(BaseModel):
    """Real-time operational status for a single specialized agent."""
    model_config = ConfigDict(from_attributes=True)

    agent_id: str
    agent_name: str
    phase: str
    status: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_cost_usd: float = 0.0
    decisions_count: int = 0
    tool_calls_count: int = 0
    error_message: Optional[str] = None
    last_active: Optional[datetime] = None


class WorkflowStartRequest(BaseModel):
    """Payload to launch the autonomous penetration testing workflow DAG."""
    scan_profile: str = Field(
        default="QUICK",
        description="Scan depth profile: 'QUICK' (Rapid smoke test), 'FULL' (Standard OWASP WSTG), 'DEEP' (Exhaustive fuzzing)"
    )
    phases: Optional[List[str]] = Field(
        default=None,
        description="Target phases to execute: RECON, MAPPING, WSTG_PLANNING, ACTIVE_ASSESSMENT, VALIDATION, REPORTING"
    )
    auto_approve_medium: bool = Field(
        default=False,
        description="Whether to automatically approve medium-risk tasks without manual operator intervention"
    )
    async_execution: bool = Field(
        default=False,
        description="Execute workflow asynchronously in a background task and return RUNNING status immediately"
    )


class WorkflowStatusResponse(BaseModel):
    """Execution status and checkpoint state of the project's pentest workflow."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    current_phase: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    state_data: Dict[str, Any] = Field(default_factory=dict)
    active_agents: List[AgentStatusResponse] = Field(default_factory=list)
    failure_reason: Optional[str] = None


class AgentDecisionResponse(BaseModel):
    """Granular reasoning trace and thought formulation emitted by an agent."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    agent_execution_id: uuid.UUID
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    phase: Optional[str] = None
    thought_trace: str
    intent: str
    context_summary: Optional[str] = None
    confidence: Optional[str] = None
    created_at: datetime


class AgentToolCallResponse(BaseModel):
    """Record of a structured tool action invoked by an agent."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    agent_execution_id: uuid.UUID
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    phase: Optional[str] = None
    tool_name: str
    input_arguments: Dict[str, Any]
    output_result: Optional[Dict[str, Any]] = None
    status: str
    duration_ms: Optional[int] = None
    created_at: datetime


class ApprovalRequestResponse(BaseModel):
    """High-risk action requiring human operator authorization."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    workflow_execution_id: Optional[uuid.UUID] = None
    agent_id: str
    action: str
    target: str
    risk_level: str
    parameters: Optional[Dict[str, Any]] = None
    status: str
    justification: Optional[str] = None
    requested_at: datetime
    decided_at: Optional[datetime] = None
    decided_by: Optional[uuid.UUID] = None


class ApprovalDecisionRequest(BaseModel):
    """Operator decision payload for an approval request."""
    decision: str = Field(..., description="APPROVE or REJECT")
    justification: str = Field(..., min_length=5, description="Auditable justification for decision")
