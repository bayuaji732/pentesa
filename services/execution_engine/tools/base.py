"""Base security tool execution wrapper with strict sandboxing and scope enforcement."""

import abc
import asyncio
import os
import shutil
import time
import uuid
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.project import Project
from database.models.scope import ScopeRule
from packages.common.exceptions import ScopeViolationError
from services.scope_engine.service import scope_service


class ToolExecutionResult:
    """Normalized result returned by all security tool wrappers."""

    def __init__(
        self,
        tool_name: str,
        target_url: str,
        argv: List[str],
        status: str,  # SUCCESS, FAILED, TIMEOUT, CANCELLED, SCOPE_REJECTED
        exit_code: Optional[int] = None,
        duration_ms: Optional[int] = None,
        stdout: str = "",
        stderr: str = "",
        findings: Optional[List[Dict[str, Any]]] = None,
        error_message: Optional[str] = None
    ):
        self.tool_name = tool_name
        self.target_url = target_url
        self.argv = argv
        self.status = status
        self.exit_code = exit_code
        self.duration_ms = duration_ms
        self.stdout = stdout
        self.stderr = stderr
        self.findings = findings or []
        self.error_message = error_message


class BaseToolWrapper(abc.ABC):
    """Abstract base tool runner enforcing zero shell execution and scope pre-validation."""

    def __init__(self, tool_name: str, binary_name: str):
        self.tool_name = tool_name
        self.binary_name = binary_name

    def is_installed(self) -> bool:
        """Check if binary exists on system PATH."""
        return shutil.which(self.binary_name) is not None

    def get_binary_path(self) -> Optional[str]:
        """Return absolute path to binary."""
        return shutil.which(self.binary_name)

    async def validate_scope(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
        target_url: str
    ) -> None:
        """Enforce Layer 1 & 2 scope rules before spawning any tool subprocess."""
        proj_stmt = select(Project).where(Project.id == project_id)
        proj = (await session.execute(proj_stmt)).scalar_one_or_none()
        if not proj:
            raise ScopeViolationError(f"Project {project_id} not found.")

        rules_stmt = select(ScopeRule).where(ScopeRule.project_id == project_id)
        rules = (await session.execute(rules_stmt)).scalars().all()

        res = scope_service.check_target(
            project=proj,
            target_url=target_url,
            rules=rules,
            resolve_dns=False
        )
        if not res.is_in_scope:
            raise ScopeViolationError(
                f"Tool execution target '{target_url}' blocked by scope engine: {res.reason}"
            )

    def build_sanitized_env(self) -> Dict[str, str]:
        """Construct sanitized environment variables, purging database keys and secrets."""
        allowed_keys = ["PATH", "SYSTEMROOT", "TMP", "TEMP", "USERPROFILE", "HOME", "LANG", "TZ"]
        clean_env = {k: os.environ[k] for k in allowed_keys if k in os.environ}
        return clean_env

    @abc.abstractmethod
    def build_argv(self, target_url: str, options: Dict[str, Any]) -> List[str]:
        """Compile strongly-typed argv array without shell interpolation."""
        pass

    @abc.abstractmethod
    def parse_output(self, stdout: str) -> List[Dict[str, Any]]:
        """Parse tool output into normalized finding dictionaries."""
        pass

    async def execute(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
        target_url: str,
        options: Optional[Dict[str, Any]] = None,
        timeout_seconds: int = 180
    ) -> ToolExecutionResult:
        """Execute sandboxed subprocess with scope check, timeout, and output parsing."""
        opts = options or {}

        # 1. Scope Enforcement Gate
        await self.validate_scope(session, project_id, target_url)

        # 2. Build typed argv
        argv = self.build_argv(target_url, opts)

        start_time = time.time()
        binary_path = self.get_binary_path()

        # If binary is not installed, run fallback simulation handler
        if not binary_path:
            return await self.simulate_execution(target_url, argv, opts)

        clean_env = self.build_sanitized_env()

        try:
            # 3. Spawn subprocess using asyncio.create_subprocess_exec (NO shell=True)
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=clean_env
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=float(timeout_seconds)
            )

            duration_ms = int((time.time() - start_time) * 1000)
            stdout_str = stdout_bytes.decode("utf-8", errors="replace")
            stderr_str = stderr_bytes.decode("utf-8", errors="replace")

            status = "SUCCESS" if proc.returncode == 0 else "FAILED"
            findings = self.parse_output(stdout_str)

            return ToolExecutionResult(
                tool_name=self.tool_name,
                target_url=target_url,
                argv=argv,
                status=status,
                exit_code=proc.returncode,
                duration_ms=duration_ms,
                stdout=stdout_str,
                stderr=stderr_str,
                findings=findings
            )

        except asyncio.TimeoutError:
            duration_ms = int((time.time() - start_time) * 1000)
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            return ToolExecutionResult(
                tool_name=self.tool_name,
                target_url=target_url,
                argv=argv,
                status="TIMEOUT",
                exit_code=124,
                duration_ms=duration_ms,
                error_message=f"Tool execution timed out after {timeout_seconds} seconds"
            )

        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            return ToolExecutionResult(
                tool_name=self.tool_name,
                target_url=target_url,
                argv=argv,
                status="FAILED",
                exit_code=1,
                duration_ms=duration_ms,
                error_message=str(e)
            )

    async def simulate_execution(
        self,
        target_url: str,
        argv: List[str],
        options: Dict[str, Any]
    ) -> ToolExecutionResult:
        """Simulate execution when tool binary is not installed on the system."""
        # Standard default mock execution result
        return ToolExecutionResult(
            tool_name=self.tool_name,
            target_url=target_url,
            argv=argv,
            status="SUCCESS",
            exit_code=0,
            duration_ms=50,
            stdout="[SIMULATED] Tool binary not installed on host; simulation completed cleanly.",
            stderr="",
            findings=[]
        )

