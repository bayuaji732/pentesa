"""Unit tests for RawHttpClient: scope validation and forensic HTTP request execution."""

from unittest.mock import AsyncMock, patch
import httpx
import pytest

from packages.common.exceptions import ScopeViolationError
from packages.schemas.tool import HttpTestRequest
from services.execution_engine.tools.http_client import RawHttpClient


@pytest.mark.asyncio
async def test_raw_http_client_scope_enforcement(db_session, test_project):
    """Verify RawHttpClient rejects out-of-scope and excluded path targets."""
    client = RawHttpClient(db_session)

    # 1. Target on excluded path
    req_excluded = HttpTestRequest(
        url="https://target.com/logout",
        method="GET"
    )
    with pytest.raises(ScopeViolationError) as exc_info:
        await client.execute_request(test_project.id, req_excluded)
    assert "blocked by scope engine" in str(exc_info.value)

    # 2. Out-of-scope domain
    req_out_of_scope = HttpTestRequest(
        url="https://external-unauthorized.org/login",
        method="POST"
    )
    with pytest.raises(ScopeViolationError) as exc_info:
        await client.execute_request(test_project.id, req_out_of_scope)
    assert "blocked by scope engine" in str(exc_info.value)


@pytest.mark.asyncio
async def test_raw_http_client_successful_execution(db_session, test_project):
    """Verify in-scope HTTP dispatch with mock httpx response and evidence capture."""
    client = RawHttpClient(db_session)

    mock_resp = httpx.Response(
        status_code=200,
        headers={"Content-Type": "application/json", "Server": "nginx/1.24"},
        text='{"status": "ok", "user": "test_account"}',
        request=httpx.Request("GET", "https://api.target.com/v1/profile")
    )

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_request:
        mock_request.return_value = mock_resp

        payload = HttpTestRequest(
            url="https://api.target.com/v1/profile",
            method="GET",
            headers={"Authorization": "Bearer secret_jwt_token_12345"},
            timeout_seconds=5
        )

        response = await client.execute_request(test_project.id, payload)

        assert response.status_code == 200
        assert response.headers.get("content-type") == "application/json"
        assert response.body == '{"status": "ok", "user": "test_account"}'
        assert response.raw_request is not None
        assert "Authorization: Bearer [REDACTED]" in response.raw_request
        assert "secret_jwt_token_12345" not in response.raw_request
        assert response.raw_response is not None
        assert len(response.request_hash_sha256) == 64
        assert len(response.response_hash_sha256) == 64
        assert "curl -i -s" in response.reproduction_curl
