"""Integration tests for OWASP WSTG API endpoints."""

import uuid
from unittest.mock import patch
import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.audit import AuditLog
from database.models.discovery import Endpoint
from database.models.wstg import WSTGTestInstance


@pytest.mark.asyncio
async def test_wstg_catalog_api(
    client: AsyncClient,
    admin_token: str
):
    """Verify master WSTG catalog retrieval and query filters."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Fetch entire catalog
    resp = await client.get("/api/v1/wstg/catalog", headers=headers)
    assert resp.status_code == 200
    catalog = resp.json()
    assert len(catalog) == 106

    # 2. Filter by category WSTG-INPV (Input Validation)
    cat_resp = await client.get("/api/v1/wstg/catalog?category_code=WSTG-INPV", headers=headers)
    assert cat_resp.status_code == 200
    inpv_tests = cat_resp.json()
    assert len(inpv_tests) == 19
    assert all(t["category_code"] == "WSTG-INPV" for t in inpv_tests)

    # 3. Search query
    search_resp = await client.get("/api/v1/wstg/catalog?search=SQL%20Injection", headers=headers)
    assert search_resp.status_code == 200
    sqli = search_resp.json()
    assert len(sqli) >= 1
    assert any(t["id"] == "WSTG-INPV-05" for t in sqli)


@pytest.mark.asyncio
async def test_project_wstg_plan_and_status_update(
    client: AsyncClient,
    admin_token: str,
    test_project,
    db_session: AsyncSession
):
    """Verify fetching project plan, invalid state transition rejection, and audit logging."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Fetch initial plan (auto-initializes 106 instances)
    plan_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/wstg/plan",
        headers=headers
    )
    assert plan_resp.status_code == 200
    plan = plan_resp.json()
    assert len(plan) == 106

    test_item = plan[0]
    test_id = test_item["id"]
    wstg_id = test_item["wstg_id"]
    assert test_item["status"] == "Not Started"

    # 2. Invalid state transition: Not Started -> Passed should return 400
    invalid_patch = await client.patch(
        f"/api/v1/projects/{test_project.id}/wstg/tests/{test_id}",
        json={"status": "Passed"},
        headers=headers
    )
    assert invalid_patch.status_code == 400
    assert "Invalid WSTG status transition" in invalid_patch.json()["detail"]

    # 3. Transition to Not Applicable without justification should return 400
    na_no_just = await client.patch(
        f"/api/v1/projects/{test_project.id}/wstg/tests/{test_id}",
        json={"status": "Not Applicable"},
        headers=headers
    )
    assert na_no_just.status_code == 400
    assert "requires an explicit justification" in na_no_just.json()["detail"]

    # 4. Valid transition: Not Started -> Planned
    valid_patch = await client.patch(
        f"/api/v1/projects/{test_project.id}/wstg/tests/{test_id}",
        json={"status": "Planned", "notes": "Scheduled for initial reconnaissance pass."},
        headers=headers
    )
    assert valid_patch.status_code == 200
    updated = valid_patch.json()
    assert updated["status"] == "Planned"
    assert updated["notes"] == "Scheduled for initial reconnaissance pass."

    # 5. Verify audit log entry was generated
    audit_stmt = (
        select(AuditLog)
        .where(
            AuditLog.project_id == test_project.id,
            AuditLog.action == "WSTG_TEST_STATUS_UPDATED"
        )
    )
    audit_entries = (await db_session.execute(audit_stmt)).scalars().all()
    assert len(audit_entries) >= 1
    latest_audit = audit_entries[-1]
    assert latest_audit.details["wstg_id"] == wstg_id
    assert latest_audit.details["new_status"] == "Planned"


@pytest.mark.asyncio
async def test_wstg_coverage_and_recalculate_api(
    client: AsyncClient,
    admin_token: str,
    test_project
):
    """Verify coverage report retrieval and recalculation API."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Fetch initial coverage
    cov_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/wstg/coverage",
        headers=headers
    )
    assert cov_resp.status_code == 200
    coverage = cov_resp.json()
    assert coverage["total_catalog_tests"] == 106
    assert "categories" in coverage
    assert "WSTG-INPV" in coverage["categories"]

    # 2. Add an endpoint to project inventory
    ep_payload = {
        "fqdn": "target.com",
        "url_path": "/api/v1/items",
        "http_method": "GET",
        "parameter_schema": {"query": ["search", "limit"]},
        "content_type": "application/json",
        "auth_required": False
    }
    ep_create = await client.post(
        f"/api/v1/projects/{test_project.id}/endpoints",
        json=ep_payload,
        headers=headers
    )
    assert ep_create.status_code == 201

    # 3. Trigger plan recalculation
    recalc_resp = await client.post(
        f"/api/v1/projects/{test_project.id}/wstg/recalculate",
        headers=headers
    )
    assert recalc_resp.status_code == 200
    recalc = recalc_resp.json()
    assert recalc["total_instances"] == 106
    assert recalc["planned_count"] >= 1


@pytest.mark.asyncio
async def test_wstg_execute_and_logs_api(
    client: AsyncClient,
    admin_token: str,
    test_project
):
    """Verify test execution dispatch, execution query, and log streaming endpoints."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Dispatch automated execution for WSTG-INFO-01
    exec_resp = await client.post(
        f"/api/v1/projects/{test_project.id}/wstg/execute/WSTG-INFO-01?runner_type=AUTOMATED",
        headers=headers
    )
    assert exec_resp.status_code == 201
    exec_data = exec_resp.json()
    assert exec_data["wstg_id"] == "WSTG-INFO-01"
    assert exec_data["status"] == "PASSED"
    execution_id = exec_data["id"]

    # Query execution details
    get_exec = await client.get(
        f"/api/v1/projects/{test_project.id}/wstg/executions/{execution_id}",
        headers=headers
    )
    assert get_exec.status_code == 200
    assert get_exec.json()["id"] == execution_id

    # Query execution logs
    logs_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/wstg/executions/{execution_id}/logs",
        headers=headers
    )
    assert logs_resp.status_code == 200
    logs = logs_resp.json()
    assert len(logs) >= 2
    assert any("Starting automated execution" in l["message"] for l in logs)


@pytest.mark.asyncio
async def test_wstg_plan_includes_enriched_metadata_counts_and_findings_sync(
    client: AsyncClient,
    admin_token: str,
    test_project,
):
    """Verify /wstg/plan includes category_code, description, applicable, execution_count, and findings_count."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Dispatch an execution for WSTG-INFO-01 and create a finding for WSTG-INPV-05
    exec_resp = await client.post(
        f"/api/v1/projects/{test_project.id}/wstg/execute/WSTG-INFO-01?runner_type=AUTOMATED",
        headers=headers,
    )
    assert exec_resp.status_code == 201

    finding_resp = await client.post(
        f"/api/v1/projects/{test_project.id}/findings",
        headers=headers,
        json={
            "title": "SQL Injection in Search",
            "description": "Error-based SQLi",
            "severity": "Critical",
            "cwe_id": "CWE-89",
            "wstg_id": "WSTG-INPV-05",
        },
    )
    assert finding_resp.status_code == 201

    plan_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/wstg/plan",
        headers=headers,
    )
    assert plan_resp.status_code == 200
    items = {item["wstg_id"]: item for item in plan_resp.json()}

    info01 = items["WSTG-INFO-01"]
    assert info01["category_code"] == "WSTG-INFO"
    assert len(info01["description"]) > 10
    assert info01["execution_count"] >= 1
    assert info01["applicable"] is True

    inpv05 = items["WSTG-INPV-05"]
    assert inpv05["status"] == "Failed"
    assert inpv05["findings_count"] == 1
    assert inpv05["applicable"] is True


@pytest.mark.asyncio
async def test_unhandled_exception_preserves_cors_headers(
    db_session: AsyncSession,
    admin_token: str,
    test_project,
):
    """Verify unhandled 500 responses preserve CORS headers instead of collapsing into browser Failed to fetch."""
    from httpx import ASGITransport
    from apps.api.main import app
    from database.session import get_db

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    try:
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as raw_client:
            with patch(
                "services.execution_engine.service.WSTGExecutionService.recalculate_plan",
                side_effect=RuntimeError("simulated unexpected failure"),
            ):
                resp = await raw_client.post(
                    f"/api/v1/projects/{test_project.id}/wstg/recalculate",
                    headers={
                        "Authorization": f"Bearer {admin_token}",
                        "Origin": "http://localhost:3000",
                    },
                )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 500
    assert resp.json()["error"] == "INTERNAL_SERVER_ERROR"
    assert "access-control-allow-origin" in {k.lower() for k in resp.headers.keys()}
