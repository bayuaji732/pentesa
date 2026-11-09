"""Hierarchical Multi-Agent Supervisor and Pentest Workflow Orchestrator."""

import datetime
import uuid
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from agents.authorization.authz_agent import AuthorizationAgent
from agents.llm.provider import BaseLLMProvider, get_default_llm_provider
from agents.planner.planner_agent import ProjectPlanningAgent
from agents.recon.recon_agent import ReconnaissanceAgent
from agents.reporting.reporting_agent import ReportingAgent
from agents.validation.validation_agent import ValidationAgent
from agents.vulnerability.vuln_agent import VulnerabilityAgent
from agents.wstg.wstg_agent import WSTGAssessmentAgent
from apps.api.dependencies import record_audit_log
from database.models.agent import (
    AgentDecision,
    AgentExecution,
    ApprovalRequest,
    WorkflowExecution
)
from database.models.project import Project
from database.models.scope import ScopeRule
from packages.common.exceptions import (
    BadRequestError,
    ProjectAuthorizationExpiredError,
    ResourceNotFoundError
)
from packages.schemas.agent import (
    AgentDecisionResponse,
    AgentStatusResponse,
    ApprovalRequestResponse,
    WorkflowStatusResponse
)
from services.orchestrator.state import PentestWorkflowState


class WorkflowSupervisor:
    """Supervises and checkpoints the multi-agent penetration testing workflow DAG."""

    def __init__(self, session: AsyncSession, llm_provider: Optional[BaseLLMProvider] = None):
        self.session = session
        self.llm = llm_provider or get_default_llm_provider()

    async def get_active_workflow(self, project_id: uuid.UUID) -> Optional[WorkflowExecution]:
        """Fetch the latest workflow execution for a project."""
        stmt = (
            select(WorkflowExecution)
            .where(WorkflowExecution.project_id == project_id)
            .order_by(desc(WorkflowExecution.created_at))
            .limit(1)
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def start_workflow(
        self,
        project_id: uuid.UUID,
        user_id: Optional[uuid.UUID] = None,
        phases: Optional[List[str]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> WorkflowExecution:
        """Initialize, validate project authorization, and execute multi-agent workflow DAG."""
        # 1. Verify project exists and authorization is active
        proj_stmt = select(Project).where(Project.id == project_id)
        project = (await self.session.execute(proj_stmt)).scalar_one_or_none()
        if not project:
            raise ResourceNotFoundError(f"Project {project_id} not found.")

        now = datetime.datetime.now(datetime.timezone.utc)
        auth_end = project.authorization_end
        if auth_end:
            if auth_end.tzinfo is None:
                auth_end = auth_end.replace(tzinfo=datetime.timezone.utc)
            if auth_end < now:
                raise ProjectAuthorizationExpiredError(
                    f"Engagement authorization window expired on {auth_end.isoformat()}."
                )

        # 2. Check for already running workflow
        active = await self.get_active_workflow(project_id)
        if active and active.status == "RUNNING":
            raise BadRequestError("A penetration testing workflow is already actively executing for this project.")

        # 3. Compile approved scope metadata
        scope_stmt = select(ScopeRule).where(ScopeRule.project_id == project_id)
        rules = (await self.session.execute(scope_stmt)).scalars().all()
        scope_summary = {
            "target_domains": project.target_domains or [],
            "allowed_cidrs": project.allowed_cidrs or [],
            "excluded_paths": project.excluded_paths or [],
            "rules_count": len(rules)
        }

        # 4. Create new WorkflowExecution
        workflow = WorkflowExecution(
            project_id=project_id,
            current_phase="PLANNING",
            status="RUNNING",
            state_data={"approved_scope": scope_summary}
        )
        self.session.add(workflow)
        await self.session.commit()
        await self.session.refresh(workflow)

        # Audit workflow start
        await record_audit_log(
            session=self.session,
            action="WORKFLOW_STARTED",
            resource_type="WorkflowExecution",
            resource_id=str(workflow.id),
            details={"phases": phases or "ALL", "scope": scope_summary},
            project_id=project_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        await self.session.commit()

        # 5. Initialize Workflow State
        state = PentestWorkflowState(
            project_id=project_id,
            current_phase="PLANNING",
            status="RUNNING",
            approved_scope=scope_summary
        )

        # 6. Execute Agent Sequence (Phase DAG)
        agents = [
            ProjectPlanningAgent(self.session, self.llm),
            ReconnaissanceAgent(self.session, self.llm),
            WSTGAssessmentAgent(self.session, self.llm),
            VulnerabilityAgent(self.session, self.llm),
            AuthorizationAgent(self.session, self.llm),
            ValidationAgent(self.session, self.llm),
            ReportingAgent(self.session, self.llm)
        ]

        for agent in agents:
            # Check if workflow was paused or stopped asynchronously
            await self.session.refresh(workflow)
            if workflow.status in ["PAUSED", "STOPPED"]:
                state.add_log("SUPERVISOR", f"Workflow execution interrupted with status: {workflow.status}")
                break

            state = await agent.run(state)

            # Checkpoint state diff
            workflow.current_phase = state.current_phase
            workflow.state_data = {
                "approved_scope": state.approved_scope,
                "discovered_subdomains": state.discovered_subdomains,
                "endpoints_count": len(state.endpoints_inventory),
                "candidate_findings_count": len(state.candidate_findings),
                "confirmed_findings_count": len(state.confirmed_findings),
                "false_positives_count": len(state.false_positives),
                "logs_count": len(state.execution_logs)
            }
            await self.session.commit()

        # Finalize workflow completion if finished
        if state.status == "COMPLETED":
            workflow.status = "COMPLETED"
            workflow.completed_at = datetime.datetime.now(datetime.timezone.utc)
            await self.session.commit()

        return workflow

    async def pause_workflow(
        self,
        project_id: uuid.UUID,
        user_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> WorkflowExecution:
        """Pause execution at current graph checkpoint."""
        workflow = await self.get_active_workflow(project_id)
        if not workflow or workflow.status != "RUNNING":
            raise BadRequestError("No running workflow found to pause.")

        workflow.status = "PAUSED"
        await self.session.commit()
        await self.session.refresh(workflow)

        await record_audit_log(
            session=self.session,
            action="WORKFLOW_PAUSED",
            resource_type="WorkflowExecution",
            resource_id=str(workflow.id),
            details={"current_phase": workflow.current_phase},
            project_id=project_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        await self.session.commit()
        return workflow

    async def resume_workflow(
        self,
        project_id: uuid.UUID,
        user_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> WorkflowExecution:
        """Resume paused workflow from its last checkpoint."""
        workflow = await self.get_active_workflow(project_id)
        if not workflow or workflow.status != "PAUSED":
            raise BadRequestError("No paused workflow found to resume.")

        workflow.status = "RUNNING"
        await self.session.commit()
        await self.session.refresh(workflow)

        await record_audit_log(
            session=self.session,
            action="WORKFLOW_RESUMED",
            resource_type="WorkflowExecution",
            resource_id=str(workflow.id),
            details={"resumed_at_phase": workflow.current_phase},
            project_id=project_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        await self.session.commit()
        return workflow

    async def stop_workflow(
        self,
        project_id: uuid.UUID,
        user_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> WorkflowExecution:
        """Emergency stop: aborts execution DAG and marks workflow STOPPED."""
        workflow = await self.get_active_workflow(project_id)
        if not workflow or workflow.status not in ["RUNNING", "PAUSED", "WAITING_APPROVAL"]:
            raise BadRequestError("No active workflow found to stop.")

        workflow.status = "STOPPED"
        workflow.completed_at = datetime.datetime.now(datetime.timezone.utc)
        await self.session.commit()
        await self.session.refresh(workflow)

        await record_audit_log(
            session=self.session,
            action="WORKFLOW_STOPPED",
            resource_type="WorkflowExecution",
            resource_id=str(workflow.id),
            details={"stopped_at_phase": workflow.current_phase},
            project_id=project_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        await self.session.commit()
        return workflow

    async def get_workflow_status(self, project_id: uuid.UUID) -> WorkflowStatusResponse:
        """Fetch current workflow status and real-time metrics for all agents."""
        workflow = await self.get_active_workflow(project_id)
        if not workflow:
            raise ResourceNotFoundError(f"No workflow execution found for project {project_id}.")

        # Query all agent executions for this project
        stmt = (
            select(AgentExecution)
            .options(selectinload(AgentExecution.decisions), selectinload(AgentExecution.tool_calls))
            .where(AgentExecution.project_id == project_id)
            .order_by(AgentExecution.started_at)
        )
        execs = (await self.session.execute(stmt)).scalars().all()

        agent_statuses = []
        for e in execs:
            agent_statuses.append(
                AgentStatusResponse(
                    agent_id=e.agent_id,
                    agent_name=e.agent_name,
                    phase=workflow.current_phase,
                    status=e.status,
                    prompt_tokens=e.prompt_tokens,
                    completion_tokens=e.completion_tokens,
                    total_cost_usd=e.total_cost_usd,
                    decisions_count=len(e.decisions),
                    tool_calls_count=len(e.tool_calls),
                    last_active=e.completed_at or e.started_at
                )
            )

        return WorkflowStatusResponse(
            id=workflow.id,
            project_id=workflow.project_id,
            current_phase=workflow.current_phase,
            status=workflow.status,
            started_at=workflow.created_at,
            completed_at=workflow.completed_at,
            state_data=workflow.state_data or {},
            active_agents=agent_statuses
        )

    async def list_agent_decisions(
        self,
        project_id: uuid.UUID,
        agent_id: Optional[str] = None,
        limit: int = 50
    ) -> List[AgentDecisionResponse]:
        """Query reasoning thought traces and intent formulations."""
        stmt = (
            select(AgentDecision)
            .join(AgentExecution, AgentDecision.agent_execution_id == AgentExecution.id)
            .where(AgentExecution.project_id == project_id)
        )
        if agent_id:
            stmt = stmt.where(AgentExecution.agent_id == agent_id)

        stmt = stmt.order_by(desc(AgentDecision.created_at)).limit(limit)
        results = (await self.session.execute(stmt)).scalars().all()

        return [
            AgentDecisionResponse(
                id=d.id,
                agent_execution_id=d.agent_execution_id,
                agent_id=agent_id or "AGT",
                agent_name="Agent",
                thought_trace=d.thought_trace,
                intent=d.intent,
                context_summary=d.context_summary,
                confidence=d.confidence,
                created_at=d.created_at
            )
            for d in results
        ]

    async def handle_approval(
        self,
        approval_id: uuid.UUID,
        project_id: uuid.UUID,
        decision: str,  # APPROVE or REJECT
        justification: str,
        user_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> ApprovalRequestResponse:
        """Process operator authorization decision for a suspended high-risk action."""
        stmt = select(ApprovalRequest).where(
            ApprovalRequest.id == approval_id,
            ApprovalRequest.project_id == project_id
        )
        req = (await self.session.execute(stmt)).scalar_one_or_none()
        if not req:
            raise ResourceNotFoundError(f"Approval request {approval_id} not found.")

        req.status = "APPROVED" if decision.upper() == "APPROVE" else "REJECTED"
        req.justification = justification
        req.decided_by = user_id
        req.decided_at = datetime.datetime.now(datetime.timezone.utc)
        await self.session.commit()
        await self.session.refresh(req)

        await record_audit_log(
            session=self.session,
            action=f"APPROVAL_{req.status}",
            resource_type="ApprovalRequest",
            resource_id=str(req.id),
            details={
                "decision": req.status,
                "justification": justification,
                "action": req.action,
                "target": req.target
            },
            project_id=project_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        await self.session.commit()

        return ApprovalRequestResponse.model_validate(req)
