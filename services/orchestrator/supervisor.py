"""Hierarchical Multi-Agent Supervisor and Pentest Workflow Orchestrator."""

import asyncio
import datetime
import uuid
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from agents.authorization.authz_agent import AuthorizationAgent
from agents.llm.provider import BaseLLMProvider, MockLLMProvider, get_default_llm_provider
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
    AgentToolCall,
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
    AgentToolCallResponse,
    ApprovalRequestResponse,
    WorkflowStatusResponse
)
from services.orchestrator.state import PentestWorkflowState


AGENT_PIPELINE_SPEC: List[Tuple[str, str, str]] = [
    ("AGT-01", "Project Planning Agent", "PLANNING"),
    ("AGT-03", "Reconnaissance & Surface Mapping Agent", "RECON"),
    ("AGT-05", "WSTG Assessment Agent", "WSTG_PLANNING"),
    ("AGT-09", "Vulnerability Detection Agent", "ACTIVE_ASSESSMENT"),
    ("AGT-07", "Authorization Testing Agent", "ACTIVE_ASSESSMENT"),
    ("AGT-11", "Vulnerability Validation & Quality Control Agent", "VALIDATION"),
    ("AGT-15", "PTES Reporting Agent", "REPORTING"),
]
AGENT_PHASE_MAP: Dict[str, str] = {aid: phase for aid, _, phase in AGENT_PIPELINE_SPEC}
AGENT_ORDER_MAP: Dict[str, int] = {aid: idx for idx, (aid, _, _) in enumerate(AGENT_PIPELINE_SPEC)}


class WorkflowSupervisor:
    """Supervises and checkpoints the multi-agent penetration testing workflow DAG."""

    def __init__(self, session: AsyncSession, llm_provider: Optional[BaseLLMProvider] = None):
        self.session = session
        self.llm = llm_provider or get_default_llm_provider()

    def _build_agents(self, llm_provider: BaseLLMProvider):
        return [
            ProjectPlanningAgent(self.session, llm_provider),
            ReconnaissanceAgent(self.session, llm_provider),
            WSTGAssessmentAgent(self.session, llm_provider),
            VulnerabilityAgent(self.session, llm_provider),
            AuthorizationAgent(self.session, llm_provider),
            ValidationAgent(self.session, llm_provider),
            ReportingAgent(self.session, llm_provider),
        ]

    async def get_active_workflow(self, project_id: uuid.UUID) -> Optional[WorkflowExecution]:
        """Fetch the latest workflow execution for a project."""
        stmt = (
            select(WorkflowExecution)
            .where(WorkflowExecution.project_id == project_id)
            .order_by(desc(WorkflowExecution.created_at))
            .limit(1)
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def prepare_workflow(
        self,
        project_id: uuid.UUID,
        user_id: Optional[uuid.UUID] = None,
        phases: Optional[List[str]] = None,
        scan_profile: str = "QUICK",
        auto_approve_medium: bool = True,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> WorkflowExecution:
        """Validate RoE, create WorkflowExecution, and pre-seed QUEUED AgentExecution rows."""
        normalized_profile = (scan_profile or "QUICK").upper()
        if normalized_profile not in ("QUICK", "FULL", "DEEP"):
            normalized_profile = "QUICK"

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

        # 2. Check for already running workflow (auto-recover stale ones > 3 min)
        active = await self.get_active_workflow(project_id)
        if active and active.status in ("RUNNING", "WAITING_APPROVAL"):
            created_at = active.created_at
            if created_at and created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=datetime.timezone.utc)
            if created_at and (now - created_at) > datetime.timedelta(minutes=3):
                active.status = "INTERRUPTED"
                stale_exec_stmt = select(AgentExecution).where(
                    AgentExecution.project_id == project_id,
                    AgentExecution.status.in_(["QUEUED", "RUNNING", "WAITING_APPROVAL"])
                )
                for ex in (await self.session.execute(stale_exec_stmt)).scalars().all():
                    ex.status = "INTERRUPTED"
                    ex.completed_at = now
                await self.session.commit()
            else:
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

        # 4. Pre-seed QUEUED AgentExecution rows for clean real-time telemetry
        exec_ids: Dict[str, str] = {}
        seeded_rows: List[AgentExecution] = []
        for aid, aname, _ in AGENT_PIPELINE_SPEC:
            row = AgentExecution(
                project_id=project_id,
                agent_id=aid,
                agent_name=aname,
                status="QUEUED",
                prompt_tokens=0,
                completion_tokens=0,
                total_cost_usd=0.0,
            )
            self.session.add(row)
            seeded_rows.append(row)
        await self.session.flush()
        for row in seeded_rows:
            exec_ids[row.agent_id] = str(row.id)

        # 5. Create new WorkflowExecution
        wf_id = uuid.uuid4()
        initial_state = PentestWorkflowState(
            project_id=project_id,
            workflow_id=wf_id,
            current_phase="PLANNING",
            status="RUNNING",
            scan_profile=normalized_profile,
            auto_approve_medium=auto_approve_medium,
            approved_scope=scope_summary
        )

        workflow = WorkflowExecution(
            id=wf_id,
            project_id=project_id,
            current_phase="PLANNING",
            status="RUNNING",
            state_data={
                "approved_scope": scope_summary,
                "scan_profile": normalized_profile,
                "auto_approve_medium": auto_approve_medium,
                "agent_execution_ids": exec_ids,
                "completed_agent_ids": [],
                "workflow_snapshot": initial_state.model_dump(mode="json")
            }
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
            details={"phases": phases or "ALL", "scan_profile": normalized_profile, "scope": scope_summary},
            project_id=project_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        await self.session.commit()
        return workflow

    async def execute_workflow(
        self,
        workflow_id: uuid.UUID,
        step_delay_seconds: float = 0.0
    ) -> WorkflowExecution:
        """Run or resume a prepared WorkflowExecution through the 7-agent DAG."""
        wf_stmt = select(WorkflowExecution).where(WorkflowExecution.id == workflow_id)
        wf_refresh_stmt = wf_stmt.execution_options(populate_existing=True)
        workflow = (await self.session.execute(wf_refresh_stmt)).scalar_one_or_none()
        if not workflow:
            raise ResourceNotFoundError(f"Workflow {workflow_id} not found.")

        state_data = dict(workflow.state_data or {})
        scan_profile = (state_data.get("scan_profile") or "QUICK").upper()
        snapshot = state_data.get("workflow_snapshot")
        if snapshot:
            state = PentestWorkflowState.model_validate(snapshot)
        else:
            state = PentestWorkflowState(
                project_id=workflow.project_id,
                workflow_id=workflow.id,
                current_phase=workflow.current_phase or "PLANNING",
                status="RUNNING",
                scan_profile=scan_profile,
                auto_approve_medium=state_data.get("auto_approve_medium", True),
                approved_scope=state_data.get("approved_scope", {})
            )
        state.workflow_id = workflow.id
        state.status = "RUNNING"
        if workflow.status in ("NOT_STARTED", "PAUSED", "WAITING_APPROVAL"):
            workflow.status = "RUNNING"
            await self.session.commit()

        exec_ids: Dict[str, str] = dict(state_data.get("agent_execution_ids") or {})
        completed_agent_ids: List[str] = list(state_data.get("completed_agent_ids") or [])

        effective_llm = MockLLMProvider() if scan_profile == "QUICK" else self.llm
        agents = self._build_agents(effective_llm)

        # Load pre-seeded AgentExecution rows if present
        exec_map: Dict[str, AgentExecution] = {}
        if exec_ids:
            uuid_list = [uuid.UUID(v) for v in exec_ids.values()]
            exec_stmt = select(AgentExecution).where(AgentExecution.id.in_(uuid_list))
            for ex in (await self.session.execute(exec_stmt)).scalars().all():
                exec_map[ex.agent_id] = ex

        try:
            for agent in agents:
                if agent.agent_id in completed_agent_ids:
                    continue

                # Force fresh workflow status read from DB without expiring unrelated ORM objects
                workflow = (await self.session.execute(wf_refresh_stmt)).scalar_one()

                # Wait while paused until resumed or stopped
                while workflow.status == "PAUSED":
                    await asyncio.sleep(0.5)
                    workflow = (await self.session.execute(wf_refresh_stmt)).scalar_one()

                if workflow.status in ("STOPPED", "FAILED", "INTERRUPTED"):
                    state.add_log("SUPERVISOR", f"Workflow execution halted with status: {workflow.status}")
                    await self._mark_unfinished_agents_stopped(exec_map)
                    break

                # Transition workflow phase before executing agent
                op_phase = AGENT_PHASE_MAP.get(agent.agent_id, state.current_phase)
                workflow.current_phase = op_phase
                await self.session.commit()

                existing_exec = exec_map.get(agent.agent_id)
                state = await agent.run(state, existing_execution=existing_exec)

                # If agent triggered HITL approval gate, pause workflow at WAITING_APPROVAL
                if state.status == "WAITING_APPROVAL":
                    workflow.status = "WAITING_APPROVAL"
                    workflow.current_phase = op_phase
                    workflow.state_data = {
                        **state_data,
                        "approved_scope": state.approved_scope,
                        "scan_profile": scan_profile,
                        "auto_approve_medium": state.auto_approve_medium,
                        "agent_execution_ids": exec_ids,
                        "completed_agent_ids": completed_agent_ids,
                        "discovered_subdomains": state.discovered_subdomains,
                        "endpoints_count": len(state.endpoints_inventory),
                        "candidate_findings_count": len(state.candidate_findings),
                        "confirmed_findings_count": len(state.confirmed_findings),
                        "false_positives_count": len(state.false_positives),
                        "logs_count": len(state.execution_logs),
                        "workflow_snapshot": state.model_dump(mode="json")
                    }
                    await self.session.commit()
                    return workflow

                completed_agent_ids.append(agent.agent_id)
                state_data = {
                    **state_data,
                    "approved_scope": state.approved_scope,
                    "scan_profile": scan_profile,
                    "auto_approve_medium": state.auto_approve_medium,
                    "agent_execution_ids": exec_ids,
                    "completed_agent_ids": completed_agent_ids,
                    "discovered_subdomains": state.discovered_subdomains,
                    "endpoints_count": len(state.endpoints_inventory),
                    "candidate_findings_count": len(state.candidate_findings),
                    "confirmed_findings_count": len(state.confirmed_findings),
                    "false_positives_count": len(state.false_positives),
                    "logs_count": len(state.execution_logs),
                    "workflow_snapshot": state.model_dump(mode="json")
                }
                workflow.current_phase = state.current_phase
                workflow.state_data = state_data
                await self.session.commit()

                if step_delay_seconds > 0:
                    await asyncio.sleep(step_delay_seconds)

            # Finalize workflow completion if finished without interruptions
            workflow = (await self.session.execute(wf_refresh_stmt)).scalar_one()
            if workflow.status == "RUNNING":
                workflow.status = "COMPLETED"
                workflow.current_phase = "COMPLETED"
                workflow.completed_at = datetime.datetime.now(datetime.timezone.utc)
                await self.session.commit()

        except Exception as exc:
            workflow = (await self.session.execute(wf_refresh_stmt)).scalar_one()
            workflow.status = "FAILED"
            workflow.completed_at = datetime.datetime.now(datetime.timezone.utc)
            workflow.state_data = {
                **(workflow.state_data or {}),
                "error": str(exc)
            }
            await self._mark_unfinished_agents_stopped(exec_map, target_status="FAILED", err=str(exc))
            await self.session.commit()
            raise

        return workflow

    async def _mark_unfinished_agents_stopped(
        self,
        exec_map: Dict[str, AgentExecution],
        target_status: str = "STOPPED",
        err: Optional[str] = None
    ) -> None:
        now = datetime.datetime.now(datetime.timezone.utc)
        for ex in exec_map.values():
            await self.session.refresh(ex)
            if ex.status in ("QUEUED", "RUNNING", "WAITING_APPROVAL"):
                ex.status = target_status
                ex.completed_at = now
                if err and not ex.error_message:
                    ex.error_message = err
        await self.session.commit()

    async def start_workflow(
        self,
        project_id: uuid.UUID,
        user_id: Optional[uuid.UUID] = None,
        phases: Optional[List[str]] = None,
        scan_profile: str = "QUICK",
        auto_approve_medium: bool = True,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> WorkflowExecution:
        """Initialize, validate project authorization, and synchronously execute multi-agent workflow DAG."""
        workflow = await self.prepare_workflow(
            project_id=project_id,
            user_id=user_id,
            phases=phases,
            scan_profile=scan_profile,
            auto_approve_medium=auto_approve_medium,
            ip_address=ip_address,
            user_agent=user_agent
        )
        return await self.execute_workflow(workflow.id, step_delay_seconds=0.0)

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
        if not workflow or workflow.status not in ("PAUSED", "WAITING_APPROVAL"):
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

        now = datetime.datetime.now(datetime.timezone.utc)
        workflow.status = "STOPPED"
        workflow.completed_at = now

        # Stop any QUEUED/RUNNING AgentExecution records tied to this workflow
        exec_ids = (workflow.state_data or {}).get("agent_execution_ids") or {}
        if exec_ids:
            uuid_list = [uuid.UUID(v) for v in exec_ids.values()]
            exec_stmt = select(AgentExecution).where(AgentExecution.id.in_(uuid_list))
            for ex in (await self.session.execute(exec_stmt)).scalars().all():
                if ex.status in ("QUEUED", "RUNNING", "WAITING_APPROVAL"):
                    ex.status = "STOPPED"
                    ex.completed_at = now

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

    async def reset_workflow(
        self,
        project_id: uuid.UUID,
        user_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Optional[WorkflowExecution]:
        """Reset all active/running workflows and unfinished agent executions for project."""
        now = datetime.datetime.now(datetime.timezone.utc)
        stmt = (
            select(WorkflowExecution)
            .where(
                WorkflowExecution.project_id == project_id,
                WorkflowExecution.status.in_(["RUNNING", "PAUSED", "WAITING_APPROVAL"])
            )
        )
        active_list = (await self.session.execute(stmt)).scalars().all()
        for w in active_list:
            w.status = "STOPPED"
            w.completed_at = now

        exec_stmt = (
            select(AgentExecution)
            .where(
                AgentExecution.project_id == project_id,
                AgentExecution.status.in_(["RUNNING", "QUEUED", "WAITING_APPROVAL"])
            )
        )
        for ex in (await self.session.execute(exec_stmt)).scalars().all():
            ex.status = "STOPPED"
            ex.completed_at = now

        await self.session.commit()
        return await self.get_active_workflow(project_id)

    async def get_workflow_status(self, project_id: uuid.UUID) -> WorkflowStatusResponse:
        """Fetch current workflow status and real-time metrics for all agents."""
        workflow = await self.get_active_workflow(project_id)
        if not workflow:
            raise ResourceNotFoundError(f"No workflow execution found for project {project_id}.")

        exec_ids = (workflow.state_data or {}).get("agent_execution_ids") or {}
        if exec_ids:
            uuid_list = [uuid.UUID(v) for v in exec_ids.values()]
            stmt = (
                select(AgentExecution)
                .options(selectinload(AgentExecution.decisions), selectinload(AgentExecution.tool_calls))
                .where(AgentExecution.id.in_(uuid_list))
            )
            execs = (await self.session.execute(stmt)).scalars().all()
            latest_by_agent: Dict[str, AgentExecution] = {e.agent_id: e for e in execs}
        else:
            stmt = (
                select(AgentExecution)
                .options(selectinload(AgentExecution.decisions), selectinload(AgentExecution.tool_calls))
                .where(AgentExecution.project_id == project_id)
                .order_by(AgentExecution.started_at)
            )
            execs = (await self.session.execute(stmt)).scalars().all()
            latest_by_agent = {}
            for e in execs:
                latest_by_agent[e.agent_id] = e

        # Order agents deterministically by DAG execution sequence
        ordered_execs = sorted(
            latest_by_agent.values(),
            key=lambda x: AGENT_ORDER_MAP.get(x.agent_id, 99)
        )

        agent_statuses = []
        for e in ordered_execs:
            agent_statuses.append(
                AgentStatusResponse(
                    agent_id=e.agent_id,
                    agent_name=e.agent_name,
                    phase=AGENT_PHASE_MAP.get(e.agent_id, workflow.current_phase),
                    status=e.status,
                    prompt_tokens=e.prompt_tokens,
                    completion_tokens=e.completion_tokens,
                    total_cost_usd=e.total_cost_usd,
                    decisions_count=len(e.decisions),
                    tool_calls_count=len(e.tool_calls),
                    error_message=e.error_message,
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
        """Query reasoning thought traces and intent formulations with agent attribution."""
        stmt = (
            select(AgentDecision, AgentExecution.agent_id, AgentExecution.agent_name)
            .join(AgentExecution, AgentDecision.agent_execution_id == AgentExecution.id)
            .where(AgentExecution.project_id == project_id)
        )
        if agent_id:
            stmt = stmt.where(AgentExecution.agent_id == agent_id)

        stmt = stmt.order_by(desc(AgentDecision.created_at)).limit(limit)
        rows = (await self.session.execute(stmt)).all()

        return [
            AgentDecisionResponse(
                id=d.id,
                agent_execution_id=d.agent_execution_id,
                agent_id=exec_aid,
                agent_name=exec_aname,
                phase=AGENT_PHASE_MAP.get(exec_aid, "ASSESSMENT"),
                thought_trace=d.thought_trace,
                intent=d.intent,
                context_summary=d.context_summary,
                confidence=d.confidence,
                created_at=d.created_at
            )
            for d, exec_aid, exec_aname in rows
        ]

    async def list_agent_tool_calls(
        self,
        project_id: uuid.UUID,
        agent_id: Optional[str] = None,
        limit: int = 50
    ) -> List[AgentToolCallResponse]:
        """Query structured tool executions performed by autonomous agents."""
        stmt = (
            select(AgentToolCall, AgentExecution.agent_id, AgentExecution.agent_name)
            .join(AgentExecution, AgentToolCall.agent_execution_id == AgentExecution.id)
            .where(AgentExecution.project_id == project_id)
        )
        if agent_id:
            stmt = stmt.where(AgentExecution.agent_id == agent_id)

        stmt = stmt.order_by(desc(AgentToolCall.created_at)).limit(limit)
        rows = (await self.session.execute(stmt)).all()

        return [
            AgentToolCallResponse(
                id=tc.id,
                agent_execution_id=tc.agent_execution_id,
                agent_id=exec_aid,
                agent_name=exec_aname,
                phase=AGENT_PHASE_MAP.get(exec_aid, "ASSESSMENT"),
                tool_name=tc.tool_name,
                input_arguments=tc.input_arguments,
                output_result=tc.output_result,
                status=tc.status,
                duration_ms=tc.duration_ms,
                created_at=tc.created_at
            )
            for tc, exec_aid, exec_aname in rows
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
