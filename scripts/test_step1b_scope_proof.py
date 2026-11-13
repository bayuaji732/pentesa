"""Empirical proof for Step 1b: Verify scope rejection on tool execution.

Tests:
(i) Project with NO scope rules -> Target rejected, NO subprocess spawned.
(ii) Project with out-of-scope rules -> Target rejected, NO subprocess spawned.
"""

import asyncio
import http.server
import os
import socketserver
import threading
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from database.base import Base
from database.models.project import Project
from database.models.scope import ScopeRule
from database.models.user import User
from packages.common.exceptions import ScopeViolationError
from packages.common.security import hash_password
from packages.schemas.tool import ToolExecutionRequest
from services.execution_engine.tools.service import ToolService

# Local test HTTP server to verify zero hits
REQUEST_LOG = []

class RecordingHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        REQUEST_LOG.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    def do_POST(self):
        REQUEST_LOG.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    def log_message(self, format, *args):
        pass  # silent

def start_server(port):
    server = socketserver.TCPServer(("127.0.0.1", port), RecordingHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server

async def main():
    print("=" * 60)
    print("STEP 1B: SCOPE CHECK PROOF ON TOOL EXECUTION PATH")
    print("=" * 60)

    server_port = 8899
    server = start_server(server_port)
    target_url = f"http://127.0.0.1:{server_port}/status"

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    Session = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    subprocess_spawned = False
    original_exec = asyncio.create_subprocess_exec

    async def mock_subprocess_exec(*args, **kwargs):
        nonlocal subprocess_spawned
        subprocess_spawned = True
        print(f"[ALERT] create_subprocess_exec was called with args: {args}")
        return await original_exec(*args, **kwargs)

    with patch("asyncio.create_subprocess_exec", side_effect=mock_subprocess_exec):
        async with Session() as session:
            now = datetime.now(timezone.utc)
            user = User(
                id=uuid.uuid4(),
                email="admin@example.test",
                full_name="Admin User",
                password_hash=hash_password("Pass123!"),
                role="ADMIN",
                is_active=True
            )
            session.add(user)

            # -------------------------------------------------------------
            # Case (i): Project with NO scope rules
            # -------------------------------------------------------------
            p_no_rules = Project(
                id=uuid.uuid4(),
                name="Project with No Rules",
                status="ACTIVE",
                authorization_start=now - timedelta(days=1),
                authorization_end=now + timedelta(days=1),
                created_by=user.id
            )
            session.add(p_no_rules)
            await session.commit()

            service = ToolService(session)
            payload = ToolExecutionRequest(
                tool_name="nuclei",
                target_url=target_url,
                rate_limit=10,
                timeout_seconds=10
            )

            print("\n[TEST (i)] Running tool against project with NO scope rules...")
            case_i_rejected = False
            try:
                await service.execute_tool(project_id=p_no_rules.id, payload=payload)
            except ScopeViolationError as exc:
                case_i_rejected = True
                print(f"[PASS] Correctly rejected by scope engine: {exc}")
            except Exception as e:
                print(f"[FAIL] Unexpected exception: {type(e).__name__}: {e}")

            assert case_i_rejected, "Case (i) failed: Out-of-scope target was NOT rejected!"
            assert not subprocess_spawned, "Case (i) P0-CRITICAL: Subprocess was spawned!"
            assert len(REQUEST_LOG) == 0, f"Case (i) P0-CRITICAL: HTTP server received requests: {REQUEST_LOG}"
            print("[VERIFIED] Case (i): Scope engine rejected execution. Subprocess spawned: FALSE. HTTP requests received: 0.")

            # Test (i-b): Hostname target with no rules
            payload_domain = ToolExecutionRequest(
                tool_name="nuclei",
                target_url="https://unauthorized.test/api",
                rate_limit=10,
                timeout_seconds=10
            )
            case_ib_rejected = False
            try:
                await service.execute_tool(project_id=p_no_rules.id, payload=payload_domain)
            except ScopeViolationError as exc:
                case_ib_rejected = True
                print(f"[PASS] Domain target rejected with NO rules: {exc}")
            assert case_ib_rejected
            assert not subprocess_spawned

            # -------------------------------------------------------------
            # Case (ii): Project whose scope does NOT include target
            # -------------------------------------------------------------
            subprocess_spawned = False
            REQUEST_LOG.clear()

            p_with_other_scope = Project(
                id=uuid.uuid4(),
                name="Project with Other Scope",
                status="ACTIVE",
                authorization_start=now - timedelta(days=1),
                authorization_end=now + timedelta(days=1),
                created_by=user.id
            )
            session.add(p_with_other_scope)
            rule = ScopeRule(
                id=uuid.uuid4(),
                project_id=p_with_other_scope.id,
                rule_type="DOMAIN_WILDCARD",
                target_type="IN_SCOPE",
                pattern="*.authorized-client.test",
                protocol="https,http",
                port_range="80,443"
            )
            session.add(rule)
            await session.commit()

            print("\n[TEST (ii)] Running tool against project with non-matching scope rules...")
            case_ii_rejected = False
            try:
                await service.execute_tool(project_id=p_with_other_scope.id, payload=payload)
            except ScopeViolationError as exc:
                case_ii_rejected = True
                print(f"[PASS] Correctly rejected by scope engine: {exc}")
            except Exception as e:
                print(f"[FAIL] Unexpected exception: {type(e).__name__}: {e}")

            assert case_ii_rejected, "Case (ii) failed: Out-of-scope target was NOT rejected!"
            assert not subprocess_spawned, "Case (ii) P0-CRITICAL: Subprocess was spawned!"
            assert len(REQUEST_LOG) == 0, f"Case (ii) P0-CRITICAL: HTTP server received requests: {REQUEST_LOG}"
            print("[VERIFIED] Case (ii): Scope engine rejected execution. Subprocess spawned: FALSE. HTTP requests received: 0.")

    print("\n" + "=" * 60)
    print("STEP 1B CONCLUSION: ALL CASES PASSED PROVABLY.")
    print("Zero subprocesses spawned. Zero HTTP requests reached target.")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
