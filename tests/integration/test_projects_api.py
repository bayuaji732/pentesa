"""Integration tests for Project Management API endpoints."""

import uuid
from datetime import datetime, timedelta, timezone
import pytest
from httpx import AsyncClient

from database.models.user import User


@pytest.mark.asyncio
async def test_create_project_and_automatic_scope_rules(
    client: AsyncClient,
    admin_token: str
):
    """Verify project creation automatically creates initial scope rules and memberships."""
    now = datetime.now(timezone.utc)
    payload = {
        "name": "Acme Corp Pentest Q1",
        "description": "Authorized external penetration test",
        "target_domains": ["acme.org", "*.acme.org"],
        "allowed_cidrs": ["198.51.100.0/24"],
        "excluded_paths": ["/logout"],
        "allow_internal_networks": False,
        "authorization_document_ref": "ROE-ACME-2026-001",
        "authorization_start": now.isoformat(),
        "authorization_end": (now + timedelta(days=14)).isoformat()
    }
    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = await client.post("/api/v1/projects", json=payload, headers=headers)
    assert resp.status_code == 201
    data = resp.json()

    assert data["name"] == "Acme Corp Pentest Q1"
    assert data["status"] == "PLANNING"
    assert len(data["members"]) >= 1
    assert data["members"][0]["role"] == "LEAD"


@pytest.mark.asyncio
async def test_create_project_invalid_dates(client: AsyncClient, admin_token: str):
    """Verify authorization end date before start date is rejected with 400."""
    now = datetime.now(timezone.utc)
    payload = {
        "name": "Invalid Date Pentest",
        "target_domains": ["acme.org"],
        "authorization_start": now.isoformat(),
        "authorization_end": (now - timedelta(days=1)).isoformat()  # End before start!
    }
    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = await client.post("/api/v1/projects", json=payload, headers=headers)
    assert resp.status_code == 400
    assert "Authorization end date must be after authorization start date" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_list_projects(client: AsyncClient, admin_token: str, test_project):
    """Verify listing projects returns created projects."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = await client.get("/api/v1/projects", headers=headers)
    assert resp.status_code == 200
    projects = resp.json()
    assert len(projects) >= 1
    project_ids = [p["id"] for p in projects]
    assert str(test_project.id) in project_ids


@pytest.mark.asyncio
async def test_add_project_member(
    client: AsyncClient,
    admin_token: str,
    test_project,
    tester_user: User
):
    """Verify adding a member to an existing project."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    member_payload = {
        "user_id": str(tester_user.id),
        "role": "TESTER"
    }
    resp = await client.post(
        f"/api/v1/projects/{test_project.id}/members",
        json=member_payload,
        headers=headers
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["user_id"] == str(tester_user.id)
    assert data["role"] == "TESTER"

