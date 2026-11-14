"""Regression and unit tests for FIX-03 (SEC-PWD-01): Seeding and default credential defenses."""

import os
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.main import validate_encryption_key_startup
from database.models.user import User
from database.seeds.seed_data import is_strong_password, seed_initial_data
from packages.common.config import settings


def test_password_strength_validator():
    """Verify password strength validation rules."""
    assert is_strong_password("short")[0] is False
    assert is_strong_password("alllowercase123!")[0] is False
    assert is_strong_password("ALLUPPERCASE123!")[0] is False
    assert is_strong_password("NoSpecialChars12345")[0] is False
    assert is_strong_password("ContainsAdmin123!Secure")[0] is False
    assert is_strong_password("PentesaPass123!Safe")[0] is False
    assert is_strong_password("K9#mQ2$vL8!zW5")[0] is True


@pytest.mark.asyncio
async def test_seed_initial_data_no_unconditional_admin(db_session: AsyncSession, monkeypatch):
    """Verify seed_initial_data does not create admin@example.com when unconfigured."""
    monkeypatch.setattr(settings, "env", "production")
    monkeypatch.delenv("PENTESA_BOOTSTRAP_ADMIN_EMAIL", raising=False)
    monkeypatch.delenv("PENTESA_BOOTSTRAP_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("PENTESA_SEED_DEMO_DATA", "0")

    await seed_initial_data(db_session)

    stmt = select(User).where(User.role == "ADMIN")
    admins = (await db_session.execute(stmt)).scalars().all()
    assert len(admins) == 0, f"Expected 0 admins seeded, found: {admins}"


@pytest.mark.asyncio
async def test_seed_initial_data_rejects_weak_bootstrap_password(db_session: AsyncSession, monkeypatch):
    """Verify seed_initial_data rejects weak bootstrap password."""
    monkeypatch.setenv("PENTESA_BOOTSTRAP_ADMIN_EMAIL", "lead@company.test")
    monkeypatch.setenv("PENTESA_BOOTSTRAP_ADMIN_PASSWORD", "weakpass")

    with pytest.raises(ValueError) as exc:
        await seed_initial_data(db_session)
    assert "PENTESA_BOOTSTRAP_ADMIN_PASSWORD rejected" in str(exc.value)


@pytest.mark.asyncio
async def test_seed_initial_data_bootstraps_with_strong_password(db_session: AsyncSession, monkeypatch):
    """Verify seed_initial_data successfully bootstraps admin with strong password."""
    monkeypatch.setenv("PENTESA_BOOTSTRAP_ADMIN_EMAIL", "lead@company.test")
    monkeypatch.setenv("PENTESA_BOOTSTRAP_ADMIN_PASSWORD", "K9#mQ2$vL8!zW5")

    await seed_initial_data(db_session)

    stmt = select(User).where(User.email == "lead@company.test")
    admin = (await db_session.execute(stmt)).scalar_one_or_none()
    assert admin is not None
    assert admin.role == "ADMIN"
    assert admin.is_active is True


@pytest.mark.asyncio
async def test_seed_initial_data_demo_mode_in_development(db_session: AsyncSession, monkeypatch):
    """Verify demo admin is only seeded when PENTESA_ENV=development and PENTESA_SEED_DEMO_DATA=1."""
    monkeypatch.setattr(settings, "env", "development")
    monkeypatch.delenv("PENTESA_BOOTSTRAP_ADMIN_EMAIL", raising=False)
    monkeypatch.delenv("PENTESA_BOOTSTRAP_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("PENTESA_SEED_DEMO_DATA", "1")

    await seed_initial_data(db_session)

    stmt = select(User).where(User.email == "admin@example.com")
    admin = (await db_session.execute(stmt)).scalar_one_or_none()
    assert admin is not None
    assert admin.role == "ADMIN"


def test_startup_validation_refuses_default_db_password_in_production(monkeypatch):
    """Verify API startup fails closed in production when DB URL contains default password."""
    monkeypatch.setattr(settings, "env", "production")
    monkeypatch.setenv("PENTESA_ENCRYPTION_KEY", "a" * 32)
    monkeypatch.setenv("PENTESA_DATABASE_URL", "postgresql+asyncpg://pentesa_user:pentesa_password@db:5432/pentesa")
    monkeypatch.setenv("PENTESA_SECRET_KEY", "b" * 32)

    with pytest.raises(RuntimeError) as exc:
        validate_encryption_key_startup()
    assert "prohibited default password" in str(exc.value)


def test_startup_validation_refuses_default_jwt_secret_in_production(monkeypatch):
    """Verify API startup fails closed in production when JWT secret is weak/default."""
    monkeypatch.setattr(settings, "env", "production")
    monkeypatch.setenv("PENTESA_ENCRYPTION_KEY", "a" * 32)
    monkeypatch.setenv("PENTESA_DATABASE_URL", "postgresql+asyncpg://pentesa_user:StrongSecret123!@db:5432/pentesa")
    monkeypatch.setenv("PENTESA_SECRET_KEY", "change-this-in-production-0123456789abcdef0123456789abcdef")

    with pytest.raises(RuntimeError) as exc:
        validate_encryption_key_startup()
    assert "JWT signature secret key" in str(exc.value)
