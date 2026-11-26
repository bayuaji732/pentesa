"""Unit tests for self-service password change API and token revocation (Phase 9 Wave 1b, SEC-PWD-02).

Verifies:
1. Successful password change updates hash and allows login with new password only.
2. Rejection of incorrect current password (HTTP 400).
3. Rejection of new password confirmation mismatch (HTTP 400).
4. Rejection of weak new passwords violating SEC-PWD-01 policy (HTTP 400).
5. Rejection of new password identical to current password (HTTP 400).
6. Immediate revocation of existing JWT tokens issued before password change (HTTP 401).
7. Audit log generation with correct metadata and zero password leakage.
"""

import asyncio
import uuid
from datetime import datetime, timezone
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.audit import AuditLog
from database.models.user import User
from packages.common.security import create_access_token, hash_password, verify_password


@pytest.fixture
async def sample_user(db_session: AsyncSession) -> User:
    """Fixture providing a test user with a known initial password."""
    user = User(
        id=uuid.uuid4(),
        email=f"pwdchange-{uuid.uuid4().hex[:6]}@pentesa.lab",
        password_hash=hash_password("InitialP@ssw0rd!2026"),
        full_name="Password Change Test User",
        role="TESTER",
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
def user_token(sample_user: User) -> str:
    """Issue valid JWT access token for sample user."""
    return create_access_token(
        subject=str(sample_user.id),
        claims={"role": sample_user.role, "email": sample_user.email},
    )


@pytest.mark.asyncio
async def test_change_password_success(client: AsyncClient, sample_user: User, user_token: str, db_session: AsyncSession):
    """SEC-PWD-02.1: Changing password updates credentials and enables login with new password."""
    new_pw = "BrandNew$ecurePass!99"
    resp = await client.post(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "current_password": "InitialP@ssw0rd!2026",
            "new_password": new_pw,
            "new_password_confirm": new_pw,
        },
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["message"] == "Password changed successfully"

    # Refresh user from DB
    await db_session.refresh(sample_user)
    assert verify_password(new_pw, sample_user.password_hash) is True
    assert sample_user.password_changed_at is not None

    # Old password login fails
    old_login = await client.post(
        "/api/v1/auth/login",
        json={"email": sample_user.email, "password": "InitialP@ssw0rd!2026"},
    )
    assert old_login.status_code == 401

    # New password login succeeds
    new_login = await client.post(
        "/api/v1/auth/login",
        json={"email": sample_user.email, "password": new_pw},
    )
    assert new_login.status_code == 200
    assert "access_token" in new_login.json()


@pytest.mark.asyncio
async def test_change_password_wrong_current(client: AsyncClient, sample_user: User, user_token: str):
    """SEC-PWD-02.2: Rejects incorrect current password with HTTP 400."""
    resp = await client.post(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "current_password": "WrongPassword123!",
            "new_password": "BrandNew$ecurePass!99",
            "new_password_confirm": "BrandNew$ecurePass!99",
        },
    )
    assert resp.status_code == 400
    assert "Current password is incorrect" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_change_password_mismatch(client: AsyncClient, sample_user: User, user_token: str):
    """SEC-PWD-02.3: Rejects mismatched confirmation password with HTTP 400."""
    resp = await client.post(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "current_password": "InitialP@ssw0rd!2026",
            "new_password": "BrandNew$ecurePass!99",
            "new_password_confirm": "DifferentBrandNew$ecurePass!99",
        },
    )
    assert resp.status_code == 400
    assert "do not match" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_change_password_same_as_current(client: AsyncClient, sample_user: User, user_token: str):
    """SEC-PWD-02.4: Rejects new password identical to current password with HTTP 400."""
    resp = await client.post(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "current_password": "InitialP@ssw0rd!2026",
            "new_password": "InitialP@ssw0rd!2026",
            "new_password_confirm": "InitialP@ssw0rd!2026",
        },
    )
    assert resp.status_code == 400
    assert "cannot be the same" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_change_password_weak_policy(client: AsyncClient, sample_user: User, user_token: str):
    """SEC-PWD-02.5: Rejects weak new password violating SEC-PWD-01 policy with HTTP 400."""
    # Prohibited common phrase
    resp = await client.post(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "current_password": "InitialP@ssw0rd!2026",
            "new_password": "PentesaAdminPass123!",
            "new_password_confirm": "PentesaAdminPass123!",
        },
    )
    assert resp.status_code == 400
    assert "Weak password" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_change_password_revokes_old_tokens(client: AsyncClient, sample_user: User, user_token: str):
    """SEC-PWD-02.6: JWT tokens issued before password change are immediately revoked."""
    # Verify token works initially
    pre_resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {user_token}"})
    assert pre_resp.status_code == 200

    # Wait 1.1s so token iat < password_changed_at
    await asyncio.sleep(1.1)

    # Change password
    new_pw = "BrandNew$ecurePass!99"
    change_resp = await client.post(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "current_password": "InitialP@ssw0rd!2026",
            "new_password": new_pw,
            "new_password_confirm": new_pw,
        },
    )
    assert change_resp.status_code == 200

    # Old token MUST now be rejected with 401
    post_resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {user_token}"})
    assert post_resp.status_code == 401
    assert "Token revoked" in post_resp.json()["detail"]

    # Newly issued token after password change works cleanly
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": sample_user.email, "password": new_pw},
    )
    assert login_resp.status_code == 200
    new_token = login_resp.json()["access_token"]
    me_resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {new_token}"})
    assert me_resp.status_code == 200


@pytest.mark.asyncio
async def test_change_password_audit_log(client: AsyncClient, sample_user: User, user_token: str, db_session: AsyncSession):
    """SEC-PWD-02.7: Password change generates audit log record without plaintext secrets."""
    new_pw = "BrandNew$ecurePass!99"
    await client.post(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "current_password": "InitialP@ssw0rd!2026",
            "new_password": new_pw,
            "new_password_confirm": new_pw,
        },
    )

    stmt = select(AuditLog).where(
        AuditLog.action == "PASSWORD_CHANGE",
        AuditLog.user_id == sample_user.id
    )
    result = await db_session.execute(stmt)
    audit_row = result.scalar_one_or_none()
    assert audit_row is not None
    assert audit_row.resource_type == "user"
    assert audit_row.resource_id == str(sample_user.id)
    assert audit_row.user_email == sample_user.email

    # Assert no secret leakage in audit details
    details_str = str(audit_row.details)
    assert "InitialP@ssw0rd" not in details_str
    assert "BrandNew$ecurePass" not in details_str
