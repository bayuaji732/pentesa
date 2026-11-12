"""Security tool execution orchestrator service."""

import shutil
import uuid
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.dependencies import record_audit_log
from database.models.finding import Finding, FindingEvidence
from database.models.tool import ToolConfiguration, ToolExecution
from integrations.ffuf.runner import FfufRunner
from integrations.nuclei.runner import NucleiRunner
from packages.common.exceptions import BadRequestError, ResourceNotFoundError
from packages.schemas.tool import ToolExecutionRequest, ToolInfoResponse
from services.evidence_engine.collector import build_forensic_evidence
from services.execution_engine.planner import sync_wstg_instance_for_finding


class ToolService:
    """Service orchestrating security tool execution, configurations, and finding ingestion."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.nuclei_runner = NucleiRunner()
        self.ffuf_runner = FfufRunner()

    def get_runner(self, tool_name: str):
        """Select appropriate runner instance by name."""
        name = tool_name.lower()
        if name == "nuclei":
            return self.nuclei_runner
        elif name == "ffuf":
            return self.ffuf_runner
        else:
            raise BadRequestError(f"Unsupported tool: {tool_name}. Supported tools: nuclei, ffuf")

    def list_tools(self) -> List[ToolInfoResponse]:
        """List registered security tools and their installation status."""
        tools = [
            ToolInfoResponse(
                name="nuclei",
                description="Fast vulnerability scanner for known CVEs, misconfigurations, and exposures.",
                installed=self.nuclei_runner.is_installed(),
                binary_path=self.nuclei_runner.get_binary_path()
            ),
            ToolInfoResponse(
                name="ffuf",
                description="Fast and controlled web fuzzer for discovering hidden paths and parameters.",
                installed=self.ffuf_runner.is_installed(),
                binary_path=self.ffuf_runner.get_binary_path()
            ),
            ToolInfoResponse(
                name="katana",
                description="Next-generation web crawler and spider.",
                installed=shutil.which("katana") is not None,
                binary_path=shutil.which("katana")
            ),
            ToolInfoResponse(
                name="httpx",
                description="Fast multi-purpose HTTP prober and technology detector.",
                installed=shutil.which("httpx") is not None,
                binary_path=shutil.which("httpx")
            )
        ]
        return tools

    async def execute_tool(
        self,
        project_id: uuid.UUID,
        payload: ToolExecutionRequest,
        user_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> ToolExecution:
        """Execute a tool with pre-flight scope validation and ingest findings into database."""
        runner = self.get_runner(payload.tool_name)

        # 1. Scope check before record creation
        await runner.validate_scope(self.session, project_id, payload.target_url)

        # 2. Build options
        opts = {
            "tags": payload.tags,
            "severity": payload.severity,
            "wordlist_path": payload.wordlist,
            "rate_limit": payload.rate_limit,
            "timeout": payload.timeout_seconds
        }

        # 3. Create execution record in QUEUED status
        argv = runner.build_argv(payload.target_url, opts)
        execution = ToolExecution(
            project_id=project_id,
            tool_name=payload.tool_name,
            target_url=payload.target_url,
            argv=argv,
            status="RUNNING"
        )
        self.session.add(execution)
        await self.session.commit()
        await self.session.refresh(execution)

        # 4. Audit log start
        await record_audit_log(
            session=self.session,
            action="TOOL_EXECUTION_DISPATCHED",
            resource_type="ToolExecution",
            resource_id=str(execution.id),
            details={
                "tool_name": payload.tool_name,
                "target_url": payload.target_url,
                "argv": argv
            },
            project_id=project_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        await self.session.commit()

        # 5. Execute runner
        result = await runner.execute(
            session=self.session,
            project_id=project_id,
            target_url=payload.target_url,
            options=opts,
            timeout_seconds=payload.timeout_seconds
        )

        execution.status = result.status
        execution.exit_code = result.exit_code
        execution.duration_ms = result.duration_ms
        execution.stdout_summary = result.stdout[:2000] if result.stdout else None
        execution.stderr_summary = result.stderr[:2000] if result.stderr else None

        # 6. Ingest any confirmed findings
        findings_count = 0
        synced_wstg_ids: set[str] = set()
        for f in result.findings:
            new_finding = Finding(
                project_id=project_id,
                title=f["title"],
                description=f["description"],
                severity=f["severity"],
                cwe_id=f.get("cwe_id"),
                wstg_id=f.get("wstg_id"),
                detection_source=payload.tool_name,
                confidence=f.get("confidence", "High"),
                status="Detected"
            )
            self.session.add(new_finding)
            await self.session.flush()
            if new_finding.wstg_id:
                synced_wstg_ids.add(new_finding.wstg_id)

            if f.get("raw_request") and f.get("raw_response"):
                ev = build_forensic_evidence(
                    method="GET",
                    url=f.get("matched_at", payload.target_url),
                    request_body=f.get("raw_request"),
                    response_body=f.get("raw_response")
                )
                evidence = FindingEvidence(
                    finding_id=new_finding.id,
                    raw_request=ev["raw_request"],
                    raw_response=ev["raw_response"],
                    reproduction_curl=f.get("reproduction_curl") or ev["reproduction_curl"],
                    request_hash_sha256=ev["request_hash_sha256"],
                    response_hash_sha256=ev["response_hash_sha256"]
                )
                self.session.add(evidence)
            findings_count += 1

        execution.findings_count = findings_count
        await self.session.commit()
        for wid in synced_wstg_ids:
            await sync_wstg_instance_for_finding(self.session, project_id, wid)
        await self.session.refresh(execution)

        return execution

    async def get_tool_execution(self, execution_id: uuid.UUID) -> ToolExecution:
        """Fetch tool execution details."""
        stmt = select(ToolExecution).where(ToolExecution.id == execution_id)
        execution = (await self.session.execute(stmt)).scalar_one_or_none()
        if not execution:
            raise ResourceNotFoundError(f"Tool execution {execution_id} not found.")
        return execution

    async def list_tool_executions(self, project_id: uuid.UUID) -> List[ToolExecution]:
        """List historical tool executions for a project."""
        stmt = (
            select(ToolExecution)
            .where(ToolExecution.project_id == project_id)
            .order_by(desc(ToolExecution.created_at))
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def cancel_tool_execution(
        self,
        execution_id: uuid.UUID,
        project_id: uuid.UUID,
        user_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> ToolExecution:
        """Cancel an ongoing tool execution."""
        stmt = (
            select(ToolExecution)
            .where(
                ToolExecution.id == execution_id,
                ToolExecution.project_id == project_id
            )
        )
        execution = (await self.session.execute(stmt)).scalar_one_or_none()
        if not execution:
            raise ResourceNotFoundError(f"Tool execution {execution_id} not found.")

        if execution.status == "RUNNING":
            execution.status = "CANCELLED"
            await self.session.commit()
            await self.session.refresh(execution)

            await record_audit_log(
                session=self.session,
                action="TOOL_EXECUTION_CANCELLED",
                resource_type="ToolExecution",
                resource_id=str(execution.id),
                details={"tool_name": execution.tool_name},
                project_id=project_id,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent
            )
            await self.session.commit()

        return execution

    async def set_tool_config(
        self,
        project_id: uuid.UUID,
        tool_name: str,
        config_json: Dict[str, Any]
    ) -> ToolConfiguration:
        """Set or update project-level tool configuration."""
        stmt = (
            select(ToolConfiguration)
            .where(
                ToolConfiguration.project_id == project_id,
                ToolConfiguration.tool_name == tool_name
            )
        )
        cfg = (await self.session.execute(stmt)).scalar_one_or_none()
        if cfg:
            cfg.config_json = config_json
        else:
            cfg = ToolConfiguration(
                project_id=project_id,
                tool_name=tool_name,
                config_json=config_json
            )
            self.session.add(cfg)

        await self.session.commit()
        await self.session.refresh(cfg)
        return cfg

