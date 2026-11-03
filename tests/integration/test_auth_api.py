"""Integration tests for Authentication API endpoints."""

import pytest
from httpx import AsyncClient

from database.models.user import User


@pytest.mark.asyncio
async def test_auth_login_success(client: AsyncClient, admin_user: User):
    """Verify login with correct credentials returns valid tokens."""
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": admin_user.email, "password": "AdminPass123!"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0


@pytest.mark.asyncio
async def test_auth_login_invalid_password(client: AsyncClient, admin_user: User):
    """Verify login with wrong password returns 401."""
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": admin_user.email, "password": "IncorrectPassword!"}
    )
    assert resp.status_code == 401
    assert "Invalid email or password" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_auth_refresh_token(client: AsyncClient, admin_user: User):
    """Verify refresh token endpoint issues new access token."""
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": admin_user.email, "password": "AdminPass123!"}
    )
    refresh_tok = login_resp.json()["refresh_token"]

    refresh_resp = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_tok}
    )
    assert refresh_resp.status_code == 200
    assert "access_token" in refresh_resp.json()


@pytest.mark.asyncio
async def test_auth_me_profile(client: AsyncClient, admin_user: User, admin_token: str):
    """Verify GET /api/v1/auth/me returns current user profile."""
    # With token
    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = await client.get("/api/v1/auth/me", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == admin_user.email
    assert data["role"] == "ADMIN"

    # Without token
    resp_anon = await client.get("/api/v1/auth/me")
    assert resp_anon.status_code == 401
