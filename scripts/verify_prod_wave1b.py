"""Verification script for Wave 1b-i acceptance on production stack.

Adheres strictly to ENV RULES v2:
- Never prints, logs, or leaks passwords or tokens.
- Uses throwaway users with prefix p9test-.
- Deactivates all throwaway accounts upon completion.
- Recomputes and cryptographically verifies the production audit log chain from genesis.
"""

import asyncio
import datetime
import os
import pathlib
import sys
import uuid
import httpx
from sqlalchemy import select

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from database.models.audit import AuditLog
from database.session import AsyncSessionLocal
from packages.common.audit import verify_audit_chain

PROD_ENV_FILE = REPO_ROOT / ".env.production"
API_BASE = "http://127.0.0.1:8000"
THROWAWAY_PASS = "P9Test_Pass123!Aa"


def get_bootstrap_credentials():
    creds = {
        "PENTESA_BOOTSTRAP_ADMIN_EMAIL": os.getenv("PENTESA_BOOTSTRAP_ADMIN_EMAIL"),
        "PENTESA_BOOTSTRAP_ADMIN_PASSWORD": os.getenv("PENTESA_BOOTSTRAP_ADMIN_PASSWORD"),
    }
    if not creds.get("PENTESA_BOOTSTRAP_ADMIN_EMAIL") and PROD_ENV_FILE.exists():
        for line in PROD_ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                creds[k.strip()] = v.strip().strip("\"'")
    return creds


async def verify_audit_chain_from_genesis():
    print("\n--- Cryptographic Audit Chain Verification ---")
    async with AsyncSessionLocal() as session:
        stmt = select(AuditLog).order_by(AuditLog.created_at.asc())
        rows = (await session.execute(stmt)).scalars().all()
        print(f"Total audit records retrieved from DB: {len(rows)}")
        entries = []
        for r in rows:
            entries.append({
                "prev_hash": r.prev_hash,
                "created_at": r.created_at,
                "user_id": str(r.user_id) if r.user_id else None,
                "user_email": r.user_email,
                "action": r.action,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "details": r.details,
                "ip_address": r.ip_address,
                "hash": r.hash,
                "hash_version": getattr(r, "hash_version", 1) or 1,
            })
        valid, err, idx = verify_audit_chain(entries)
        print(f"Audit chain verification result: valid={valid}, err={err}, index={idx}")
        assert valid is True, f"Audit chain verification failed at index {idx}: {err}"
        print("[+] Audit chain from genesis is 100% cryptographically valid.")


async def run_acceptance():
    creds = get_bootstrap_credentials()
    admin_email = creds.get("PENTESA_BOOTSTRAP_ADMIN_EMAIL")
    admin_pass = creds.get("PENTESA_BOOTSTRAP_ADMIN_PASSWORD")
    assert admin_email and admin_pass, "Missing bootstrap admin credentials in .env.production"

    print("--- 1. Health & Readiness ---")
    async with httpx.AsyncClient(timeout=15.0) as client:
        r_health = await client.get(f"{API_BASE}/healthz")
        assert r_health.status_code == 200, f"/healthz failed: {r_health.status_code}"
        print("[+] /healthz -> 200 OK")

        r_ready = await client.get(f"{API_BASE}/readyz")
        assert r_ready.status_code == 200 and r_ready.json().get("status") == "ready"
        print("[+] /readyz -> 200 OK (PostgreSQL ready)")

        print("\n--- 2. Authentic Admin Login & Invariant Checks ---")
        # Ahmad login
        r_login = await client.post(
            f"{API_BASE}/api/v1/auth/login",
            json={"email": admin_email, "password": admin_pass},
        )
        assert r_login.status_code == 200, f"Admin login failed: {r_login.status_code}"
        admin_token = r_login.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        print(f"[+] Admin ({admin_email}) login -> HTTP 200 OK")

        r_me = await client.get(f"{API_BASE}/api/v1/auth/me", headers=admin_headers)
        assert r_me.status_code == 200 and r_me.json()["role"] == "ADMIN"
        print(f"[+] /auth/me -> HTTP 200 OK (Role: {r_me.json()['role']})")

        # Inactive benchmark-admin -> 401/403
        r_bench = await client.post(
            f"{API_BASE}/api/v1/auth/login",
            json={"email": "benchmark-admin@pentesa.lab", "password": "AnyPassword123!"},
        )
        assert r_bench.status_code in (401, 403)
        print(f"[+] benchmark-admin@pentesa.lab login -> HTTP {r_bench.status_code} (Rejected)")

        # Non-existent admin -> 401
        r_def = await client.post(
            f"{API_BASE}/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "AdminPassword123!"},
        )
        assert r_def.status_code == 401
        print(f"[+] admin@example.com login -> HTTP {r_def.status_code} (Rejected)")

        print("\n--- 3. Provisioning Throwaway Users for RBAC & IDOR Verification ---")
        created_users = []
        user_specs = [
            (f"p9test-lead-{uuid.uuid4().hex[:4]}@pentesa.lab", "LEAD", "P9Test Lead"),
            (f"p9test-tester-{uuid.uuid4().hex[:4]}@pentesa.lab", "TESTER", "P9Test Tester"),
            (f"p9test-viewer-{uuid.uuid4().hex[:4]}@pentesa.lab", "VIEWER", "P9Test Viewer"),
            (f"p9test-tenant-b-{uuid.uuid4().hex[:4]}@pentesa.lab", "LEAD", "P9Test Tenant B Lead"),
        ]

        tokens = {}
        for email, role, full_name in user_specs:
            r_create = await client.post(
                f"{API_BASE}/api/v1/users",
                headers=admin_headers,
                json={"email": email, "password": THROWAWAY_PASS, "full_name": full_name, "role": role, "is_active": True},
            )
            assert r_create.status_code in (200, 201), f"Failed creating {email}: {r_create.text}"
            uid = r_create.json()["id"]
            created_users.append((uid, email, role))

            r_l = await client.post(f"{API_BASE}/api/v1/auth/login", json={"email": email, "password": THROWAWAY_PASS})
            assert r_l.status_code == 200, f"Login failed for {email}: {r_l.text}"
            tokens[email] = r_l.json()["access_token"]
        print(f"[+] Provisioned and authenticated {len(created_users)} throwaway users.")

        print("\n--- 4. RBAC Matrix Verification ---")
        now = datetime.datetime.now(datetime.timezone.utc)
        auth_start = (now - datetime.timedelta(hours=1)).isoformat()
        auth_end = (now + datetime.timedelta(days=7)).isoformat()

        # Create Project A
        r_proj_a = await client.post(
            f"{API_BASE}/api/v1/projects",
            headers=admin_headers,
            json={
                "name": f"p9test-project-alpha-{uuid.uuid4().hex[:4]}",
                "description": "Throwaway RBAC Project A",
                "target_domains": ["target-juiceshop"],
                "allowed_cidrs": ["172.21.0.0/16"],
                "allow_internal_networks": True,
                "authorization_start": auth_start,
                "authorization_end": auth_end,
            },
        )
        assert r_proj_a.status_code in (200, 201)
        proj_a_id = r_proj_a.json()["id"]

        # Add Lead, Tester, Viewer to Project A
        for uid, email, role in created_users[:3]:
            r_mem = await client.post(
                f"{API_BASE}/api/v1/projects/{proj_a_id}/members",
                headers=admin_headers,
                json={"user_id": uid, "role": role},
            )
            assert r_mem.status_code in (200, 201)

        viewer_email = created_users[2][1]
        vh = {"Authorization": f"Bearer {tokens[viewer_email]}"}

        # RBAC Check 1: Viewer cannot list users
        r1 = await client.get(f"{API_BASE}/api/v1/users", headers=vh)
        assert r1.status_code == 403, f"Unexpected: {r1.status_code}"
        print(f"[+] RBAC: Viewer list users -> HTTP {r1.status_code} (403 Forbidden)")

        # RBAC Check 2: Viewer can read Project A
        r2 = await client.get(f"{API_BASE}/api/v1/projects/{proj_a_id}", headers=vh)
        assert r2.status_code == 200, f"Unexpected: {r2.status_code}"
        print(f"[+] RBAC: Viewer read Project A -> HTTP {r2.status_code} (200 OK)")

        # RBAC Check 3: Viewer cannot delete Project A
        r3 = await client.delete(f"{API_BASE}/api/v1/projects/{proj_a_id}", headers=vh)
        assert r3.status_code == 403, f"Unexpected: {r3.status_code}"
        print(f"[+] RBAC: Viewer delete Project A -> HTTP {r3.status_code} (403 Forbidden)")

        # RBAC Check 4: Viewer cannot add members
        r4 = await client.post(
            f"{API_BASE}/api/v1/projects/{proj_a_id}/members",
            headers=vh,
            json={"user_id": str(uuid.uuid4()), "role": "VIEWER"},
        )
        assert r4.status_code == 403, f"Unexpected: {r4.status_code}"
        print(f"[+] RBAC: Viewer add member -> HTTP {r4.status_code} (403 Forbidden)")

        print("\n--- 5. IDOR Matrix Verification ---")
        # Create Project B for Tenant B Lead
        r_proj_b = await client.post(
            f"{API_BASE}/api/v1/projects",
            headers=admin_headers,
            json={
                "name": f"p9test-project-beta-{uuid.uuid4().hex[:4]}",
                "description": "Throwaway IDOR Project B",
                "target_domains": ["target-juiceshop"],
                "allowed_cidrs": ["172.21.0.0/16"],
                "allow_internal_networks": True,
                "authorization_start": auth_start,
                "authorization_end": auth_end,
            },
        )
        assert r_proj_b.status_code in (200, 201)
        proj_b_id = r_proj_b.json()["id"]

        tenant_b_uid, tenant_b_email, _ = created_users[3]
        r_b_mem = await client.post(
            f"{API_BASE}/api/v1/projects/{proj_b_id}/members",
            headers=admin_headers,
            json={"user_id": tenant_b_uid, "role": "LEAD"},
        )
        assert r_b_mem.status_code in (200, 201)

        tb_h = {"Authorization": f"Bearer {tokens[tenant_b_email]}"}

        # IDOR 1: Tenant B cannot read Project A
        r_i1 = await client.get(f"{API_BASE}/api/v1/projects/{proj_a_id}", headers=tb_h)
        assert r_i1.status_code in (403, 404), f"Unexpected: {r_i1.status_code}"
        print(f"[+] IDOR: Tenant B Lead read Project A -> HTTP {r_i1.status_code}")

        # IDOR 2: Tenant B cannot delete Project A
        r_i2 = await client.delete(f"{API_BASE}/api/v1/projects/{proj_a_id}", headers=tb_h)
        assert r_i2.status_code in (403, 404), f"Unexpected: {r_i2.status_code}"
        print(f"[+] IDOR: Tenant B Lead delete Project A -> HTTP {r_i2.status_code}")

        # IDOR 3: Tenant B cannot read Project A findings
        r_i3 = await client.get(f"{API_BASE}/api/v1/projects/{proj_a_id}/findings", headers=tb_h)
        assert r_i3.status_code in (403, 404), f"Unexpected: {r_i3.status_code}"
        print(f"[+] IDOR: Tenant B Lead read Project A findings -> HTTP {r_i3.status_code}")

        # Assert zero 5xx errors
        for r in [r1, r2, r3, r4, r_i1, r_i2, r_i3]:
            assert r.status_code < 500, f"5xx Error detected: {r.status_code}"
        print("[+] Zero 5xx errors observed across all RBAC and IDOR operations.")

        print("\n--- 6. Cleanup of Throwaway Objects (ENV RULES v2) ---")
        # Delete Project A & B
        del_a = await client.delete(f"{API_BASE}/api/v1/projects/{proj_a_id}", headers=admin_headers)
        del_b = await client.delete(f"{API_BASE}/api/v1/projects/{proj_b_id}", headers=admin_headers)
        print(f"[+] Deleted Project A ({del_a.status_code}) and Project B ({del_b.status_code})")

        # Deactivate all throwaway users
        for uid, email, _ in created_users:
            r_deact = await client.put(f"{API_BASE}/api/v1/users/{uid}", headers=admin_headers, json={"is_active": False})
            assert r_deact.status_code == 200, f"Deactivation failed: {r_deact.text}"
            print(f"[+] Deactivated throwaway user {email}")

    # Verify audit chain
    await verify_audit_chain_from_genesis()
    print("\n============================================================")
    print("ALL PRODUCTION ACCEPTANCE CHECKS PASSED WITH 100% INTEGRITY")
    print("============================================================")


if __name__ == "__main__":
    asyncio.run(run_acceptance())
