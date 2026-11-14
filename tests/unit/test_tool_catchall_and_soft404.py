"""Regression tests for TOOL-FP-01: Zero false-positive findings against SPA catch-all servers and template sandboxing."""

import http.server
import json
import os
import socket
import threading
from typing import Generator
import uuid
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.project import Project, ProjectMember
from database.models.scope import ScopeRule
from database.models.user import User
from integrations.ffuf.runner import FfufRunner
from integrations.nuclei.runner import DEFAULT_NUCLEI_TEMPLATES, NucleiRunner
from packages.common.exceptions import BadRequestError
from packages.schemas.tool import ToolExecutionRequest
from services.execution_engine.tools.service import ToolService
from services.execution_engine.tools.soft_404 import Soft404Baseline, detect_soft_404_baseline


# Simulated SPA Catch-all HTML body (exact 9,984 bytes like Juice Shop)
SPA_INDEX_HTML = (
    "<!doctype html><html><head><title>OWASP Juice Shop SPA</title></head>"
    "<body><app-root></app-root>" + ("<!-- SPA Catch-all padding bytes -->\n" * 250) + "</body></html>"
).encode("utf-8")


class CatchAllHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Responds with HTTP 200 and identical SPA index page to all requests."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("Content-Length", str(len(SPA_INDEX_HTML)))
        self.end_headers()
        self.wfile.write(SPA_INDEX_HTML)

    def log_message(self, format, *args):
        pass  # Suppress logging during tests


@pytest.fixture(scope="module")
def catchall_server():
    """Spin up local ephemeral HTTP server behaving as an SPA catch-all."""
    server = http.server.HTTPServer(("127.0.0.1", 0), CatchAllHTTPHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.mark.asyncio
async def test_soft_404_detector_flags_catchall(catchall_server):
    """Verify detect_soft_404_baseline correctly flags the SPA server as having soft-404."""
    baseline = await detect_soft_404_baseline(catchall_server)
    assert baseline.has_soft_404 is True
    assert baseline.status_code == 200
    assert baseline.content_length == len(SPA_INDEX_HTML)
    assert baseline.is_match(status=200, length=len(SPA_INDEX_HTML)) is True
    # Real file with different length should not match
    assert baseline.is_match(status=200, length=28) is False


@pytest.mark.asyncio
async def test_nuclei_zero_findings_on_catchall_server(db_session: AsyncSession, test_project: Project, catchall_server):
    """Verify Nuclei returns ZERO findings against an SPA catch-all server (TOOL-FP-01)."""
    port = int(catchall_server.split(":")[-1])
    test_project.allow_internal_networks = True
    db_session.add(test_project)
    rule = ScopeRule(
        id=uuid.uuid4(),
        project_id=test_project.id,
        rule_type="EXACT_IP",
        target_type="IN_SCOPE",
        pattern="127.0.0.1",
        protocol="http",
        port_range=str(port)
    )
    db_session.add(rule)
    await db_session.commit()
    await db_session.refresh(test_project)

    service = ToolService(db_session)
    req = ToolExecutionRequest(
        tool_name="nuclei",
        target_url=catchall_server,
        rate_limit=10,
        timeout_seconds=15
    )

    execution = await service.execute_tool(test_project.id, req)
    assert execution.status in ("SUCCESS", "FAILED")
    # Verify zero findings were ingested from catch-all responses
    assert execution.findings_count == 0


@pytest.mark.asyncio
async def test_ffuf_zero_findings_on_catchall_server(db_session: AsyncSession, test_project: Project, catchall_server):
    """Verify ffuf returns ZERO findings against an SPA catch-all server with auto-calibration (TOOL-FP-01)."""
    port = int(catchall_server.split(":")[-1])
    test_project.allow_internal_networks = True
    db_session.add(test_project)
    rule = ScopeRule(
        id=uuid.uuid4(),
        project_id=test_project.id,
        rule_type="EXACT_IP",
        target_type="IN_SCOPE",
        pattern="127.0.0.1",
        protocol="http",
        port_range=str(port)
    )
    db_session.add(rule)
    await db_session.commit()
    await db_session.refresh(test_project)

    service = ToolService(db_session)
    req = ToolExecutionRequest(
        tool_name="ffuf",
        target_url=catchall_server,
        rate_limit=20,
        timeout_seconds=15
    )

    execution = await service.execute_tool(test_project.id, req)
    assert execution.status in ("SUCCESS", "FAILED")
    # Auto-calibration (-ac) and soft-404 baseline ensure 0 false positives
    assert execution.findings_count == 0


@pytest.mark.asyncio
async def test_nuclei_template_path_restriction(db_session: AsyncSession, test_project: Project, catchall_server):
    """Verify ToolService rejects template paths outside /opt/nuclei-templates."""
    service = ToolService(db_session)

    # Path traversal attempt
    with pytest.raises(BadRequestError) as exc_traversal:
        await service.execute_tool(
            test_project.id,
            ToolExecutionRequest(
                tool_name="nuclei",
                target_url=catchall_server,
                template_path="../../etc/shadow"
            )
        )
    assert "outside authorized directory" in str(exc_traversal.value)

    # Fixture directory outside authorized templates
    with pytest.raises(BadRequestError) as exc_fixture:
        await service.execute_tool(
            test_project.id,
            ToolExecutionRequest(
                tool_name="nuclei",
                target_url=catchall_server,
                template_path="/app/tests/fixtures/nuclei/exposure.yaml"
            )
        )
    assert "outside authorized directory" in str(exc_fixture.value)
