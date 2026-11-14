"""Integration tests for Security Tools execution and HTTP testing endpoints."""

import http.server
import socketserver
import threading
from unittest.mock import AsyncMock, patch
import uuid
import httpx
import pytest

from database.models.scope import ScopeRule


@pytest.fixture(scope="module")
def local_test_server():
    """Runs a minimal local HTTP server on loopback to provide a deterministic target for tool execution."""
    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path in ("/", "/index.html", "/healthz"):
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK")
            else:
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Not Found")

        def do_POST(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")

        def log_message(self, format, *args):
            pass

    server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}", port
    server.shutdown()
    server.server_close()


@pytest.mark.asyncio
async def test_list_tools_catalog(client, admin_token):
    """Verify tool discovery endpoint lists supported binaries."""
    resp = await client.get(
        "/api/v1/tools",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    names = [t["name"] for t in data]
    assert "nuclei" in names
    assert "ffuf" in names


@pytest.mark.asyncio
async def test_tool_execution_scope_enforcement(client, admin_token, test_project):
    """Verify executing tool against out-of-scope target returns 403 Forbidden."""
    # Out-of-scope target using RFC-reserved name
    resp = await client.post(
        f"/api/v1/projects/{test_project.id}/tools/execute",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "tool_name": "nuclei",
            "target_url": "https://unauthorized.example.test",
            "rate_limit": 10
        }
    )
    assert resp.status_code == 403
    assert "blocked by scope engine" in resp.json()["detail"]

    # Excluded path
    resp_excluded = await client.post(
        f"/api/v1/projects/{test_project.id}/tools/execute",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "tool_name": "nuclei",
            "target_url": "https://target.com/logout",
            "rate_limit": 10
        }
    )
    assert resp_excluded.status_code == 403


@pytest.mark.asyncio
async def test_tool_execution_and_listing(client, admin_token, test_project, db_session, local_test_server):
    """Verify in-scope tool dispatch against local fixture server, strict status assertion, and retrieval."""
    local_url, local_port = local_test_server

    # Allow loopback for this controlled fixture test and add exact port rule
    test_project.allow_internal_networks = True
    rule = ScopeRule(
        id=uuid.uuid4(),
        project_id=test_project.id,
        rule_type="EXACT_IP",
        target_type="IN_SCOPE",
        pattern="127.0.0.1",
        protocol="http",
        port_range=str(local_port)
    )
    db_session.add(rule)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/projects/{test_project.id}/tools/execute",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "tool_name": "nuclei",
            "target_url": local_url,
            "template_path": "/opt/nuclei-templates/ping.yaml",
            "rate_limit": 20,
            "timeout_seconds": 10
        }
    )
    assert resp.status_code == 201
    exec_data = resp.json()
    assert exec_data["tool_name"] == "nuclei"
    assert exec_data["target_url"] == local_url
    # Strict status assertion: responsive local fixture server must complete with SUCCESS
    assert exec_data["status"] == "SUCCESS"
    assert exec_data["findings_count"] >= 1

    exec_id = exec_data["id"]

    # List executions
    list_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/tools/executions",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert list_resp.status_code == 200
    executions = list_resp.json()
    assert len(executions) >= 1
    assert any(e["id"] == exec_id for e in executions)

    # Get single execution details
    get_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/tools/executions/{exec_id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == exec_id


@pytest.mark.asyncio
async def test_tool_config_update(client, admin_token, test_project):
    """Verify updating tool settings for a project."""
    resp = await client.put(
        f"/api/v1/projects/{test_project.id}/tools/config",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "tool_name": "nuclei",
            "config": {
                "rate_limit": 15,
                "tags": ["misconfig", "exposure"]
            }
        }
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["tool_name"] == "nuclei"
    assert data["config"]["rate_limit"] == 15


@pytest.mark.asyncio
async def test_raw_http_test_endpoint(client, admin_token, test_project):
    """Verify raw HTTP testing endpoint with scope check and evidence response."""
    # Scope rejection on out-of-scope URL
    out_resp = await client.post(
        f"/api/v1/projects/{test_project.id}/tools/http-test",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "url": "https://unauthorized.example.test/steal",
            "method": "POST"
        }
    )
    assert out_resp.status_code == 403

    # In-scope execution with mock
    mock_resp = httpx.Response(
        status_code=200,
        headers={"Server": "nginx", "Content-Type": "application/json"},
        text='{"authenticated": true, "user": "tester"}',
        request=httpx.Request("POST", "https://target.com/api/test")
    )

    mock_client_instance = AsyncMock()
    mock_client_instance.__aenter__.return_value = mock_client_instance
    mock_client_instance.request.return_value = mock_resp

    with patch("services.execution_engine.tools.http_client.httpx.AsyncClient", return_value=mock_client_instance):
        in_resp = await client.post(
            f"/api/v1/projects/{test_project.id}/tools/http-test",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "url": "https://target.com/api/test",
                "method": "POST",
                "headers": {"Authorization": "Bearer super_secret_token_12345"},
                "body": '{"action": "ping"}'
            }
        )
        assert in_resp.status_code == 200
        data = in_resp.json()
        assert data["status_code"] == 200
        assert data["raw_request"] is not None
        assert "Bearer [REDACTED]" in data["raw_request"]
        assert len(data["request_hash_sha256"]) == 64
        assert len(data["response_hash_sha256"]) == 64
        assert "curl -i -s" in data["reproduction_curl"]
