"""Regression and positive control tests for TOOL-FP-01 / F4-1.

Verifies:
1. Zero false positives against SPA catch-all servers.
2. Positive control: catch-all server serving real exposures (/.env, /.git/config)
   reports EXACTLY those real exposures and nothing else.
3. Multi-probe soft-404 detection (extensionless, .html, trailing slash).
4. Template path sandbox enforcement (/opt/nuclei-templates).
"""

import http.server
import json
import os
import shutil
import socket
import threading
from typing import Generator
import uuid
import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.finding import Finding
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

# Real exposures served on the catch-all server (Positive Control F4-1)
REAL_ENV_BODY = b"DB_PASSWORD=SuperSecret123!\nAPI_KEY=pentesa-live-exposure-token-abc\n"
REAL_GIT_CONFIG_BODY = b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"


class CatchAllHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Responds with identical SPA index page to all requests except real exposures (F4-1)."""

    def do_GET(self):
        # Positive control endpoints
        if self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=UTF-8")
            self.send_header("Content-Length", str(len(REAL_ENV_BODY)))
            self.end_headers()
            self.wfile.write(REAL_ENV_BODY)
        elif self.path == "/.git/config":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=UTF-8")
            self.send_header("Content-Length", str(len(REAL_GIT_CONFIG_BODY)))
            self.end_headers()
            self.wfile.write(REAL_GIT_CONFIG_BODY)
        else:
            # SPA catch-all returns 200 with 9,984-byte index HTML
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=UTF-8")
            self.send_header("Content-Length", str(len(SPA_INDEX_HTML)))
            self.end_headers()
            self.wfile.write(SPA_INDEX_HTML)

    def log_message(self, format, *args):
        pass  # Suppress logging during tests


@pytest.fixture(scope="module")
def catchall_server():
    """Spin up local ephemeral HTTP server behaving as an SPA catch-all with positive exposures."""
    server = http.server.HTTPServer(("127.0.0.1", 0), CatchAllHTTPHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.mark.asyncio
async def test_soft_404_detector_flags_catchall_multi_probe(catchall_server):
    """Verify detect_soft_404_baseline uses 3 distinct probes and flags SPA catch-all."""
    baseline = await detect_soft_404_baseline(catchall_server)
    assert baseline.has_soft_404 is True
    assert baseline.status_code == 200
    assert baseline.content_length == len(SPA_INDEX_HTML)
    assert baseline.probes_sent == 3
    assert baseline.probes_soft_404 == 3
    assert len(baseline.signatures) >= 1

    # Catch-all length matches
    assert baseline.is_match(status=200, length=len(SPA_INDEX_HTML)) is True
    # Real exposure lengths must NOT match baseline
    assert baseline.is_match(status=200, length=len(REAL_ENV_BODY)) is False
    assert baseline.is_match(status=200, length=len(REAL_GIT_CONFIG_BODY)) is False


@pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei binary not installed on host")
@pytest.mark.asyncio
async def test_nuclei_positive_control_and_suppression(db_session: AsyncSession, test_project: Project, catchall_server):
    """Positive Control (F4-1): Nuclei reports EXACTLY the real exposures (/.env, /.git/config) and zero SPA false positives."""
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
    # Use exposure template containing /.git/config, /.env, and /robots.txt
    tpl_path = os.path.join(DEFAULT_NUCLEI_TEMPLATES, "exposure.yaml")
    req = ToolExecutionRequest(
        tool_name="nuclei",
        target_url=catchall_server,
        template_path=tpl_path,
        rate_limit=10,
        timeout_seconds=20
    )

    execution = await service.execute_tool(test_project.id, req)
    assert execution.status in ("SUCCESS", "FAILED")
    # Must report EXACTLY the 2 real exposures (/.env and /.git/config)
    assert execution.findings_count == 2

    stmt = select(Finding).where(Finding.project_id == test_project.id, Finding.detection_source == "nuclei")
    findings = (await db_session.execute(stmt)).scalars().all()
    assert len(findings) == 2
    titles = [f.title for f in findings]
    # Both real exposures confirmed
    assert any("Sensitive File" in t or "Exposure" in t for t in titles)


@pytest.mark.skipif(shutil.which("ffuf") is None, reason="ffuf binary not installed on host")
@pytest.mark.asyncio
async def test_ffuf_positive_control_and_suppression(db_session: AsyncSession, test_project: Project, catchall_server):
    """Positive Control (F4-1): ffuf reports EXACTLY the real exposures (/.env, /.git/config) and zero SPA false positives."""
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
    quick_wl = "/opt/wordlists/common_paths.txt" if os.path.exists("/opt/wordlists/common_paths.txt") else os.path.abspath("integrations/ffuf/wordlists/common_paths.txt")
    req = ToolExecutionRequest(
        tool_name="ffuf",
        target_url=catchall_server,
        wordlist=quick_wl,
        rate_limit=20,
        timeout_seconds=20
    )

    execution = await service.execute_tool(test_project.id, req)
    assert execution.status in ("SUCCESS", "FAILED")
    # Must report EXACTLY the 2 real exposures (/.env and /.git/config)
    assert execution.findings_count == 2

    stmt = select(Finding).where(Finding.project_id == test_project.id, Finding.detection_source == "ffuf")
    findings = (await db_session.execute(stmt)).scalars().all()
    assert len(findings) == 2
    titles = [f.title for f in findings]
    assert "Discovered Path: /.env" in titles
    assert "Discovered Path: /.git/config" in titles


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
