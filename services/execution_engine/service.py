"""OWASP WSTG Execution Engine Service Orchestrator.

Integrates:
- Catalog management and search
- Project test matrix initialization and recalculation
- Finite state machine transition auditing
- Mathematical coverage reporting
- Test execution dispatching and log retrieval
"""

import uuid
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from database.models.discovery import Endpoint
from database.models.wstg import (
    TestExecution,
    TestExecutionLog,
    WSTGTestCatalog,
    WSTGTestInstance
)
from apps.api.dependencies import record_audit_log
from packages.common.exceptions import NotFoundException
from packages.schemas.wstg import (
    TestExecutionCreate,
    WSTGCoverageReport,
    WSTGTestInstanceUpdate
)
from services.execution_engine.coverage import calculate_project_wstg_coverage
from services.execution_engine.planner import (
    initialize_project_wstg_instances,
    recalculate_project_test_plan,
    seed_wstg_catalog,
    validate_status_transition
)
from services.execution_engine.runners import execute_wstg_test_run


class WSTGExecutionService:
    """Service layer for WSTG catalog, project test plan, and test runs."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def list_catalog(
        self,
        category_code: Optional[str] = None,
        automation_capability: Optional[str] = None,
        search: Optional[str] = None
    ) -> List[WSTGTestCatalog]:
        """Query master WSTG test catalog with filters."""
        stmt = select(WSTGTestCatalog)
        if category_code:
            stmt = stmt.where(WSTGTestCatalog.category_code == category_code)
        if automation_capability:
            stmt = stmt.where(WSTGTestCatalog.automation_capability == automation_capability)
        if search:
            pattern = f"%{search}%"
            stmt = stmt.where(
                (WSTGTestCatalog.id.ilike(pattern)) |
                (WSTGTestCatalog.name.ilike(pattern)) |
                (WSTGTestCatalog.description.ilike(pattern))
            )

        stmt = stmt.order_by(WSTGTestCatalog.id)
        result = await self.session.execute(stmt)
        items = list(result.scalars().all())

        if not items:
            # Seed catalog if empty
            await seed_wstg_catalog(self.session)
            return await self.list_catalog(category_code, automation_capability, search)

        return items

    async def get_project_plan(
        self,
        project_id: uuid.UUID,
        category_code: Optional[str] = None,
        status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve project-specific WSTG test plan with catalog details."""
        # Ensure project instances exist
        await initialize_project_wstg_instances(self.session, project_id)

        stmt = (
            select(WSTGTestInstance, WSTGTestCatalog)
            .join(WSTGTestCatalog, WSTGTestInstance.wstg_id == WSTGTestCatalog.id)
            .where(WSTGTestInstance.project_id == project_id)
        )

        if category_code:
            stmt = stmt.where(WSTGTestCatalog.category_code == category_code)
        if status:
            stmt = stmt.where(WSTGTestInstance.status == status)

        stmt = stmt.order_by(WSTGTestCatalog.id)
        result = await self.session.execute(stmt)
        rows = result.all()

        plan = []
        for instance, catalog in rows:
            plan.append({
                "id": instance.id,
                "project_id": instance.project_id,
                "wstg_id": instance.wstg_id,
                "category": catalog.category,
                "name": catalog.name,
                "status": instance.status,
                "notes": instance.notes,
                "justification": instance.justification,
                "applicable_endpoints_count": instance.applicable_endpoints_count,
                "automation_capability": catalog.automation_capability,
                "default_risk": catalog.default_risk,
                "updated_at": instance.updated_at
            })
        return plan

    async def update_test_instance(
        self,
        project_id: uuid.UUID,
        instance_id: uuid.UUID,
        payload: WSTGTestInstanceUpdate,
        user_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> WSTGTestInstance:
        """Update test instance status, notes, or justification with lifecycle validation."""
        stmt = (
            select(WSTGTestInstance)
            .where(
                WSTGTestInstance.id == instance_id,
                WSTGTestInstance.project_id == project_id
            )
        )
        instance = (await self.session.execute(stmt)).scalar_one_or_none()
        if not instance:
            raise NotFoundException(f"WSTG test instance {instance_id} not found.")

        old_status = instance.status
        if payload.status:
            # Validate state transition rules
            validate_status_transition(
                current_status=old_status,
                new_status=payload.status,
                justification=payload.justification or instance.justification
            )
            instance.status = payload.status

        if payload.notes is not None:
            instance.notes = payload.notes
        if payload.justification is not None:
            instance.justification = payload.justification

        await self.session.commit()
        await self.session.refresh(instance)

        # Audit log the status update
        await record_audit_log(
            session=self.session,
            action="WSTG_TEST_STATUS_UPDATED",
            resource_type="WSTGTestInstance",
            resource_id=str(instance.id),
            details={
                "wstg_id": instance.wstg_id,
                "old_status": old_status,
                "new_status": instance.status,
                "notes": instance.notes,
                "justification": instance.justification
            },
            project_id=project_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        await self.session.commit()

        return instance

    async def recalculate_plan(
        self,
        project_id: uuid.UUID,
        user_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """Recalculate WSTG test plan applicability against discovered attack surface."""
        summary = await recalculate_project_test_plan(self.session, project_id)

        await record_audit_log(
            session=self.session,
            action="WSTG_PLAN_RECALCULATED",
            resource_type="Project",
            resource_id=str(project_id),
            details=summary,
            project_id=project_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        await self.session.commit()

        return summary

    async def get_coverage_report(self, project_id: uuid.UUID) -> WSTGCoverageReport:
        """Calculate and return empirical mathematical coverage report."""
        # Ensure project has test instances initialized
        await initialize_project_wstg_instances(self.session, project_id)
        return await calculate_project_wstg_coverage(self.session, project_id)

    async def dispatch_execution(
        self,
        project_id: uuid.UUID,
        payload: TestExecutionCreate,
        user_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> TestExecution:
        """Create and execute a WSTG test execution run."""
        # Ensure instances are loaded
        await initialize_project_wstg_instances(self.session, project_id)

        # Find test instance
        inst_stmt = (
            select(WSTGTestInstance)
            .where(
                WSTGTestInstance.project_id == project_id,
                WSTGTestInstance.wstg_id == payload.wstg_id
            )
        )
        instance = (await self.session.execute(inst_stmt)).scalar_one_or_none()
        if not instance:
            raise NotFoundException(f"WSTG instance for {payload.wstg_id} not found in project.")

        # If endpoint_id provided, verify it exists and belongs to project
        if payload.endpoint_id:
            ep_stmt = (
                select(Endpoint)
                .where(
                    Endpoint.id == payload.endpoint_id,
                    Endpoint.project_id == project_id
                )
            )
            ep = (await self.session.execute(ep_stmt)).scalar_one_or_none()
            if not ep:
                raise NotFoundException(f"Endpoint {payload.endpoint_id} not found in project.")

        # Create execution record
        execution = TestExecution(
            project_id=project_id,
            wstg_instance_id=instance.id,
            endpoint_id=payload.endpoint_id,
            status="QUEUED",
            runner_type=payload.runner_type or "AUTOMATED"
        )
        self.session.add(execution)
        await self.session.commit()
        await self.session.refresh(execution)

        # Audit log dispatch
        await record_audit_log(
            session=self.session,
            action="WSTG_TEST_DISPATCHED",
            resource_type="TestExecution",
            resource_id=str(execution.id),
            details={
                "wstg_id": payload.wstg_id,
                "endpoint_id": str(payload.endpoint_id) if payload.endpoint_id else None,
                "runner_type": execution.runner_type
            },
            project_id=project_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        await self.session.commit()

        # Execute test run
        executed = await execute_wstg_test_run(self.session, execution.id)
        return executed

    async def get_execution(self, execution_id: uuid.UUID) -> TestExecution:
        """Retrieve test execution details."""
        stmt = (
            select(TestExecution)
            .where(TestExecution.id == execution_id)
        )
        execution = (await self.session.execute(stmt)).scalar_one_or_none()
        if not execution:
            raise NotFoundException(f"Test execution {execution_id} not found.")
        return execution

    async def get_execution_logs(self, execution_id: uuid.UUID) -> List[TestExecutionLog]:
        """Retrieve streaming logs for a test execution."""
        stmt = (
            select(TestExecutionLog)
            .where(TestExecutionLog.execution_id == execution_id)
            .order_by(TestExecutionLog.created_at)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
