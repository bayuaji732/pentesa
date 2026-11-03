"""Integration tests for Scope API endpoints."""

import uuid
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_and_add_scope_rules(
    client: AsyncClient,
    admin_token: str,
    test_project
):
    """Verify listing and creating new scope rules."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # List rules
    list_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/scope",
        headers=headers
    )
    assert list_resp.status_code == 200
    initial_count = len(list_resp.json())
    assert initial_count >= 1

    # Add a new rule
    new_rule = {
        "rule_type": "EXACT_DOMAIN",
        "target_type": "IN_SCOPE",
        "pattern": "portal.target.com",
        "port_range": "443"
    }
    create_resp = await client.post(
        f"/api/v1/projects/{test_project.id}/scope",
        json=new_rule,
        headers=headers
    )
    assert create_resp.status_code == 201
    created_data = create_resp.json()
    assert created_data["pattern"] == "portal.target.com"
    assert created_data["rule_type"] == "EXACT_DOMAIN"


@pytest.mark.asyncio
async def test_scope_check_endpoint(
    client: AsyncClient,
    admin_token: str,
    test_project
):
    """Verify /check endpoint evaluates target URLs against project scope."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Allowed in-scope target
    resp_ok = await client.post(
        f"/api/v1/projects/{test_project.id}/scope/check",
        json={"url": "https://api.target.com/users"},
        headers=headers
    )
    assert resp_ok.status_code == 200
    res_ok_data = resp_ok.json()
    assert res_ok_data["is_in_scope"] is True
    assert res_ok_data["status"] == "ALLOWED"

    # Out of scope domain
    resp_bad = await client.post(
        f"/api/v1/projects/{test_project.id}/scope/check",
        json={"url": "https://unauthorized-domain.com"},
        headers=headers
    )
    assert resp_bad.status_code == 200
    res_bad_data = resp_bad.json()
    assert res_bad_data["is_in_scope"] is False
    assert res_bad_data["status"] == "BLOCKED"

    # Excluded path
    resp_exc = await client.post(
        f"/api/v1/projects/{test_project.id}/scope/check",
        json={"url": "https://target.com/logout"},
        headers=headers
    )
    assert resp_exc.status_code == 200
    res_exc_data = resp_exc.json()
    assert res_exc_data["is_in_scope"] is False
    assert res_exc_data["status"] == "EXCLUDED"

