"""Integration tests for Audit Log API endpoints."""

import asyncio
import pytest
from httpx import AsyncClient

from apps.api.dependencies import record_audit_log
from tests.conftest import TestSessionLocal


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
    assert list_resp.headers.get("cache-control") == "no-store"
    logs = list_resp.json()
    assert isinstance(logs, list)

    # Verify cryptographic hash chain integrity
    verify_resp = await client.get("/api/v1/audit-logs/verify", headers=headers)
    assert verify_resp.status_code == 200
    assert verify_resp.headers.get("cache-control") == "no-store"
    verify_data = verify_resp.json()
    assert verify_data["is_valid"] is True
    assert verify_data["broken_index"] is None


@pytest.mark.asyncio
async def test_concurrent_audit_log_writes_preserve_hash_chain(
    client: AsyncClient,
    admin_token: str,
    admin_user,
    test_project
):
    """Concurrent sessions writing audit logs and long crawls must never fork prev_hash."""
    async def write_audit(idx: int, sleep_after: float = 0.0) -> None:
        async with TestSessionLocal() as sess:
            await record_audit_log(
                session=sess,
                action=f"CONCURRENT_EVENT_{idx}",
                resource_type="Project",
                resource_id=str(test_project.id),
                project_id=test_project.id,
                user_id=admin_user.id,
                details={"worker": idx},
            )
            if sleep_after > 0:
                await asyncio.sleep(sleep_after)

    await asyncio.gather(
        write_audit(0, sleep_after=0.05),
        *[write_audit(i) for i in range(1, 10)],
    )

    headers = {"Authorization": f"Bearer {admin_token}"}
    verify_resp = await client.get("/api/v1/audit-logs/verify", headers=headers)
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert verify_data["is_valid"] is True
    assert verify_data["broken_index"] is None
    assert verify_data["total_records"] >= 10


