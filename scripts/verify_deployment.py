#!/usr/bin/env python3
"""Pentesa Production Deployment Pre-Flight Verification Script.

Executes comprehensive validation across:
1. Environment Configuration, Secret Strength & Active LLM Provider
2. Persistent Disk Storage Mounts & Write Permissions
3. Redis Connectivity & Queue Readiness
4. Database Connectivity, Schema Health, WSTG Catalog & Audit Log Chain
"""

import asyncio
import os
import sys
import time
import uuid
from typing import List, Tuple
from urllib.parse import urlparse

import httpx

# Ensure repository root is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from database.models.audit import AuditLog
from database.models.user import User
from database.models.wstg import WSTGTestCatalog
from packages.common.audit import verify_audit_chain
from packages.common.config import settings


class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def print_check(name: str, passed: bool, message: str, warning: bool = False):
    if passed:
        badge = f"{Colors.GREEN}[PASS]{Colors.RESET}"
    elif warning:
        badge = f"{Colors.YELLOW}[WARN]{Colors.RESET}"
    else:
        badge = f"{Colors.RED}[FAIL]{Colors.RESET}"
    print(f" {badge} {Colors.BOLD}{name:<32}{Colors.RESET} {message}")


def _resolve_active_model(provider: str) -> str:
    p = (provider or "mock").lower().strip()
    if p == "litellm":
        return settings.litellm_model
    if p == "ollama":
        return settings.ollama_model
    if p == "openai":
        return settings.openai_model
    return "mock-gpt"


async def check_environment_configuration() -> Tuple[bool, List[str]]:
    """Validate environment variables, cryptographic secrets, and LLM gateway."""
    issues: List[str] = []

    env_mode = settings.env
    print_check("Environment Mode", True, f"Running in '{env_mode}' mode")

    secret = settings.secret_key
    if not secret or secret == "pentesa-super-secret-default-key-change-in-production-1234567890":
        if env_mode == "production":
            issues.append("Default or insecure JWT secret key detected in production mode!")
            print_check("JWT Secret Key", False, "Insecure default key in production mode")
        else:
            print_check("JWT Secret Key", True, "Default secret key (acceptable for dev/test)", warning=True)
    elif len(secret) < 32:
        issues.append("JWT Secret key is shorter than recommended 32 bytes.")
        print_check("JWT Secret Key", False, f"Key length is only {len(secret)} characters")
    else:
        print_check("JWT Secret Key", True, f"Cryptographically strong ({len(secret)} chars)")

    try:
        from apps.api.main import validate_encryption_key_startup
        validate_encryption_key_startup()
        print_check("Master Encryption Key", True, "Master AES-256 key configured (>=32 bytes)")
    except Exception as e:
        issues.append(str(e))
        print_check("Master Encryption Key", False, str(e))

    provider = (settings.llm_provider or "mock").lower().strip()
    active_model = _resolve_active_model(provider)
    if provider == "mock" and env_mode == "production":
        issues.append("Mock LLM provider cannot be active in production mode; configure 'litellm'.")
        print_check("LLM Provider", False, "Mock provider configured in production mode")
    else:
        print_check("LLM Provider", True, f"Configured as '{provider}' (Model: {active_model})")

    if provider == "litellm":
        base_url = (settings.litellm_base_url or "").rstrip("/")
        api_key = settings.litellm_api_key or ""
        if not base_url or not api_key or api_key == "sk-placeholder":
            issues.append("LiteLLM base URL or API key is missing/placeholder.")
            print_check("LiteLLM Gateway", False, "Missing PENTESA_LITELLM_BASE_URL or PENTESA_LITELLM_API_KEY")
        else:
            models_url = f"{base_url}/models" if base_url.endswith("/v1") else f"{base_url}/v1/models"
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(
                        models_url,
                        headers={"Authorization": f"Bearer {api_key}"},
                    )
                if resp.status_code == 200:
                    print_check("LiteLLM Gateway", True, f"Authenticated & reachable ({base_url})")
                elif resp.status_code in (401, 403):
                    issues.append(f"LiteLLM Gateway rejected credentials (HTTP {resp.status_code}).")
                    print_check("LiteLLM Gateway", False, f"Authentication rejected (HTTP {resp.status_code})")
                else:
                    print_check(
                        "LiteLLM Gateway",
                        False,
                        f"Returned HTTP {resp.status_code} at {models_url}",
                        warning=True,
                    )
            except Exception as exc:
                print_check(
                    "LiteLLM Gateway",
                    False,
                    f"Connectivity probe warning ({exc.__class__.__name__})",
                    warning=True,
                )

    return len(issues) == 0, issues


async def check_storage_volumes() -> Tuple[bool, List[str]]:
    """Verify read and write permissions on report and evidence storage directories."""
    issues: List[str] = []
    dirs_to_check = [
        ("Report Storage", settings.report_storage_dir),
        ("Evidence Storage", settings.evidence_storage_dir),
    ]

    for label, dir_path in dirs_to_check:
        try:
            os.makedirs(dir_path, exist_ok=True)
            test_file = os.path.join(dir_path, f".write_test_{uuid.uuid4().hex}.tmp")
            test_content = b"Pentesa storage permission probe"
            with open(test_file, "wb") as f:
                f.write(test_content)
            with open(test_file, "rb") as f:
                readback = f.read()
            os.remove(test_file)

            if readback == test_content:
                print_check(label, True, f"R/W verified: {dir_path}")
            else:
                issues.append(f"{label}: Data integrity mismatch during write-read probe")
                print_check(label, False, f"Data mismatch in {dir_path}")
        except Exception as e:
            issues.append(f"{label}: Permission error ({e})")
            print_check(label, False, f"Permission error: {e}")

    return len(issues) == 0, issues


async def check_redis_health() -> Tuple[bool, List[str]]:
    """Verify Redis broker TCP/RESP PING health."""
    issues: List[str] = []
    parsed = urlparse(settings.redis_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 6379
    password = parsed.password

    try:
        t0 = time.perf_counter()
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3.0)
        try:
            if password:
                pwd_bytes = password.encode("utf-8")
                auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$" + str(len(pwd_bytes)).encode("ascii") + b"\r\n" + pwd_bytes + b"\r\n"
                writer.write(auth_cmd)
                await writer.drain()
                auth_reply = await asyncio.wait_for(reader.readline(), timeout=3.0)
                if not auth_reply.startswith(b"+OK"):
                    raise RuntimeError(f"Redis AUTH rejected: {auth_reply.decode(errors='ignore').strip()}")

            writer.write(b"*1\r\n$4\r\nPING\r\n")
            await writer.drain()
            reply = await asyncio.wait_for(reader.readline(), timeout=3.0)
            latency_ms = (time.perf_counter() - t0) * 1000
            if reply.startswith(b"+PONG"):
                print_check("Redis Broker", True, f"PONG from {host}:{port} (Latency: {latency_ms:.1f}ms)")
            else:
                raise RuntimeError(f"Unexpected PING response: {reply.decode(errors='ignore').strip()}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception as exc:
        if settings.env == "production":
            issues.append(f"Redis connectivity failure ({host}:{port}): {exc}")
            print_check("Redis Broker", False, f"Connection failed ({host}:{port}): {exc}")
        else:
            print_check("Redis Broker", False, f"Not reachable ({host}:{port}) — OK for local dev", warning=True)

    return len(issues) == 0, issues


async def check_database_health() -> Tuple[bool, List[str]]:
    """Verify database connectivity, table schema, and master seed completeness."""
    issues: List[str] = []
    db_url = settings.database_url

    try:
        t0 = time.perf_counter()
        engine = create_async_engine(db_url, echo=False)
        async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        if "--init-db" in sys.argv:
            from database.seeds.seed_data import seed_initial_data
            from database.session import init_db

            await init_db(engine)
            async with async_session() as s:
                await seed_initial_data(s)
            print_check("Database Bootstrap", True, "Initialized schema & seeded master data")

        async with async_session() as session:
            await session.execute(text("SELECT 1"))
            latency_ms = (time.perf_counter() - t0) * 1000
            print_check("Database Connection", True, f"Connected (Latency: {latency_ms:.1f}ms)")

            catalog_count = (await session.execute(select(func.count(WSTGTestCatalog.id)))).scalar() or 0
            if catalog_count >= 106:
                print_check("OWASP WSTG Catalog", True, f"Complete: {catalog_count}/106 standard test definitions")
            else:
                issues.append(f"Incomplete WSTG catalog: found {catalog_count}/106 items. Run --init-db.")
                print_check("OWASP WSTG Catalog", False, f"Incomplete: {catalog_count}/106 test items found")

            user_count = (await session.execute(select(func.count(User.id)))).scalar() or 0
            if user_count >= 1:
                print_check("User Accounts", True, f"{user_count} user(s) provisioned")
            else:
                print_check("User Accounts", True, "Zero users provisioned (run --init-db)", warning=True)

            stmt = select(AuditLog).order_by(AuditLog.created_at.asc())
            records = (await session.execute(stmt)).scalars().all()
            if records:
                entries = [
                    {
                        "prev_hash": r.prev_hash,
                        "hash": r.hash,
                        "timestamp": r.created_at,
                        "user_id": str(r.user_id) if r.user_id else None,
                        "action": r.action,
                        "resource_type": r.resource_type,
                        "resource_id": r.resource_id,
                        "details": r.details,
                        "ip_address": r.ip_address,
                    }
                    for r in records
                ]
                is_valid, reason, _ = verify_audit_chain(entries)
                if is_valid:
                    print_check("Audit Log Hash Chain", True, f"Verified intact across {len(records)} entries")
                else:
                    issues.append(f"Audit log hash chain compromised: {reason}")
                    print_check("Audit Log Hash Chain", False, f"Integrity failure: {reason}")
            else:
                print_check("Audit Log Hash Chain", True, "Empty chain (genesis state valid)")

        await engine.dispose()
    except Exception as e:
        issues.append(f"Database verification failure: {e}")
        print_check("Database Connection", False, f"Connection failed: {e}")

    return len(issues) == 0, issues


async def main():
    print(f"\n{Colors.BOLD}{Colors.BLUE}================================================================{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}   PENTESA PLATFORM — PRODUCTION PRE-FLIGHT VERIFICATION        {Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}================================================================{Colors.RESET}\n")

    overall_passed = True
    all_issues: List[str] = []

    print(f"{Colors.BOLD}[1/4] Environment, Security & LLM Configuration{Colors.RESET}")
    env_ok, env_issues = await check_environment_configuration()
    overall_passed = overall_passed and env_ok
    all_issues.extend(env_issues)
    print()

    print(f"{Colors.BOLD}[2/4] Persistent Volume Storage Access{Colors.RESET}")
    stor_ok, stor_issues = await check_storage_volumes()
    overall_passed = overall_passed and stor_ok
    all_issues.extend(stor_issues)
    print()

    print(f"{Colors.BOLD}[3/4] Redis Task Broker Connectivity{Colors.RESET}")
    redis_ok, redis_issues = await check_redis_health()
    overall_passed = overall_passed and redis_ok
    all_issues.extend(redis_issues)
    print()

    print(f"{Colors.BOLD}[4/4] Database Schema & Cryptographic State{Colors.RESET}")
    db_ok, db_issues = await check_database_health()
    overall_passed = overall_passed and db_ok
    all_issues.extend(db_issues)
    print()

    print(f"{Colors.BOLD}----------------------------------------------------------------{Colors.RESET}")
    if overall_passed:
        print(f"{Colors.BOLD}{Colors.GREEN}[SUCCESS] All pre-flight deployment checks PASSED!{Colors.RESET}")
        print("Platform is ready for production autonomous security testing operations.\n")
        sys.exit(0)
    else:
        print(f"{Colors.BOLD}{Colors.RED}[CRITICAL] Pre-flight deployment verification FAILED with {len(all_issues)} issue(s):{Colors.RESET}")
        for idx, issue in enumerate(all_issues, 1):
            print(f"  {idx}. {issue}")
        print()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
