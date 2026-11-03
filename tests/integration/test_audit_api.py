"""Integration tests for Audit Log API endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_audit_logs_query_and_verify(
    client: AsyncClient,
    admin_token: str,
    test_project
):
    """Verify audit logs are recorded and the hash chain passes verification."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Query audit logs
    list_resp = await client.get("/api/v1/audit-logs", headers=headers)
    assert list_resp.status_code == 200
    logs = list_resp.json()
    assert isinstance(logs, list)

    # Verify cryptographic hash chain integrity
    verify_resp = await client.get("/api/v1/audit-logs/verify", headers=headers)
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert verify_data["is_valid"] is True
    assert verify_data["broken_index"] is None
