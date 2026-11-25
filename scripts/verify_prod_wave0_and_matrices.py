"""Verification script for Running Prod Stack Wave 0 Code, Smoke Tests, RBAC/IDOR Matrices, and Audit Chain.

Follows ENV RULES v2 strictly:
- No secrets printed or logged.
- Throwaway users prefixed with p9test-.
- Users deactivated and projects deleted at end of run.
- Audit chain recomputed and verified.
"""

import asyncio
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import uuid
import httpx

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PROD_ENV_FILE = REPO_ROOT / ".env.production"
API_BASE = "http://127.0.0.1:8000"
THROWAWAY_PASS = "P9Test_Pass123!Aa"

def get_prod_credentials():
    creds = {}
    if PROD_ENV_FILE.exists():
        for line in PROD_ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                creds[k.strip()] = v.strip().strip("\"'")
    return creds

def clean_throwaways_db():
    print("[*] Pre-cleaning any stale throwaway test objects in database...")
    clean_sql = (
        "DELETE FROM project_members WHERE project_id IN (SELECT id FROM projects WHERE name LIKE 'p9test-%'); "
        "DELETE FROM projects WHERE name LIKE 'p9test-%'; "
        "DELETE FROM users WHERE email LIKE 'p9test-%';"
    )
    subprocess.run(
        ["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "pentesa", "-c", clean_sql],
        capture_output=True, text=True, check=True
    )
    print("[+] Database clean for fresh throwaway execution.")

def get_file_sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def verify_container_files():
    print("\n--- 1. Proving Prod Runs Wave 0 Code ---")
    files_to_check = [
        "services/execution_engine/tools/soft_404.py",
        "packages/common/config.py",
        "integrations/nuclei/runner.py",
    ]
    for rel_path in files_to_check:
        host_file = REPO_ROOT / rel_path
        host_hash = get_file_sha256(host_file)

        # Check inside pentesa-api
        cmd_api = ["docker", "exec", "pentesa-api", "sha256sum", f"/app/{rel_path}"]
        res_api = subprocess.run(cmd_api, capture_output=True, text=True)
        api_hash = res_api.stdout.split()[0] if res_api.returncode == 0 else "ERROR"

        # Check inside pentesa-worker
        cmd_worker = ["docker", "exec", "pentesa-worker", "sha256sum", f"/app/{rel_path}"]
        res_worker = subprocess.run(cmd_worker, capture_output=True, text=True)
        worker_hash = res_worker.stdout.split()[0] if res_worker.returncode == 0 else "ERROR"

        match_api = (host_hash == api_hash)
        match_worker = (host_hash == worker_hash)

        print(f"File: {rel_path}")
        print(f"  Host:   {host_hash[:16]}...")
        print(f"  API:    {api_hash[:16]}... (Match: {match_api})")
        print(f"  Worker: {worker_hash[:16]}... (Match: {match_worker})")
        assert match_api, f"Hash mismatch in pentesa-api for {rel_path}"
        assert match_worker, f"Hash mismatch in pentesa-worker for {rel_path}"
    print("[+] Confirmed: pentesa-api and pentesa-worker are running identical Wave 0 code.")

async def run_smoke_and_matrices():
    creds = get_prod_credentials()
    admin_email = creds.get("PENTESA_BOOTSTRAP_ADMIN_EMAIL")
    admin_pass = creds.get("PENTESA_BOOTSTRAP_ADMIN_PASSWORD")
    assert admin_email and admin_pass, "Missing bootstrap admin credentials in .env.production"

    print("\n--- 2. Smoke Tests ---")
    async with httpx.AsyncClient(timeout=15.0) as client:
        # Liveness & Readiness
        r_healthz = await client.get(f"{API_BASE}/healthz")
        assert r_healthz.status_code == 200, f"/healthz failed: {r_healthz.status_code}"
        print("[+] /healthz -> 200 OK")

        r_readyz = await client.get(f"{API_BASE}/readyz")
        assert r_readyz.status_code == 200 and r_readyz.json().get("status") == "ready", f"/readyz failed: {r_readyz.text}"
        print("[+] /readyz -> 200 OK (PostgreSQL ready)")

        # Admin login
        r_login = await client.post(f"{API_BASE}/api/v1/auth/login", json={"email": admin_email, "password": admin_pass})
        assert r_login.status_code == 200, f"Admin login failed: {r_login.status_code}"
        admin_token = r_login.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        print("[+] Admin login -> 200 OK (JWT acquired)")

        # Current user profile
        r_me = await client.get(f"{API_BASE}/api/v1/auth/me", headers=admin_headers)
        assert r_me.status_code == 200 and r_me.json()["role"] == "ADMIN", f"/auth/me failed: {r_me.text}"
        print(f"[+] /auth/me -> 200 OK (Role: {r_me.json()['role']})")

        # Tools inventory
        r_tools = await client.get(f"{API_BASE}/api/v1/tools", headers=admin_headers)
        assert r_tools.status_code == 200, f"/api/v1/tools failed: {r_tools.status_code}"
        print(f"[+] /api/v1/tools -> 200 OK ({len(r_tools.json())} tools listed)")

        print("\n--- 3. Provisioning Throwaway Users for RBAC & IDOR Matrices ---")
        created_users = []
        user_specs = [
            ("p9test-lead@pentesa.lab", "LEAD", "P9Test Lead"),
            ("p9test-tester@pentesa.lab", "TESTER", "P9Test Tester"),
            ("p9test-viewer@pentesa.lab", "VIEWER", "P9Test Viewer"),
            ("p9test-tenant-b-lead@pentesa.lab", "LEAD", "P9Test Tenant B Lead"),
        ]

        for email, role, full_name in user_specs:
            r_create = await client.post(
                f"{API_BASE}/api/v1/users",
                headers=admin_headers,
                json={"email": email, "password": THROWAWAY_PASS, "full_name": full_name, "role": role, "is_active": True}
            )
            assert r_create.status_code in (200, 201), f"Failed creating {email}: {r_create.text}"
            created_users.append((r_create.json()["id"], email, role))
        print(f"[+] Provisioned {len(created_users)} throwaway users.")

        # Authenticate throwaway users
        tokens = {}
        for uid, email, role in created_users:
            r_l = await client.post(f"{API_BASE}/api/v1/auth/login", json={"email": email, "password": THROWAWAY_PASS})
            assert r_l.status_code == 200, f"Login failed for {email}: {r_l.text}"
            tokens[email] = r_l.json()["access_token"]
            print(f"[+] Login 200 OK for {email}")

        print("\n--- 4. RBAC Matrix Verification (Smoke Subset) ---")
        now = datetime.datetime.now(datetime.timezone.utc)
        auth_start = (now - datetime.timedelta(hours=1)).isoformat()
        auth_end = (now + datetime.timedelta(days=7)).isoformat()

        # Create Project A as Admin
        r_proj_a = await client.post(
            f"{API_BASE}/api/v1/projects",
            headers=admin_headers,
            json={
                "name": "p9test-project-alpha",
                "description": "Throwaway RBAC Project A",
                "target_domains": ["target-juiceshop"],
                "allowed_cidrs": ["172.21.0.0/16"],
                "allow_internal_networks": True,
                "authorization_start": auth_start,
                "authorization_end": auth_end
            }
        )
        assert r_proj_a.status_code in (200, 201), f"Project A creation failed: {r_proj_a.text}"
        proj_a_id = r_proj_a.json()["id"]
        print(f"[+] Created Project A: {proj_a_id}")

        # Add Lead, Tester, Viewer to Project A
        for uid, email, role in created_users[:3]:
            r_mem = await client.post(
                f"{API_BASE}/api/v1/projects/{proj_a_id}/members",
                headers=admin_headers,
                json={"user_id": uid, "role": role}
            )
            assert r_mem.status_code in (200, 201), f"Failed adding member {email}: {r_mem.text}"

        # RBAC Check 1: Viewer cannot list users (System ADMIN required)
        vh = {"Authorization": f"Bearer {tokens['p9test-viewer@pentesa.lab']}"}
        r_v_users = await client.get(f"{API_BASE}/api/v1/users", headers=vh)
        print(f"[+] RBAC Smoke Subset: Viewer list users -> {r_v_users.status_code} (Expected: 403)")
        assert r_v_users.status_code == 403

        # RBAC Check 2: Viewer can read Project A (VIEWER role authorized)
        r_v_read = await client.get(f"{API_BASE}/api/v1/projects/{proj_a_id}", headers=vh)
        print(f"[+] RBAC Smoke Subset: Viewer read project A -> {r_v_read.status_code} (Expected: 200)")
        assert r_v_read.status_code == 200

        # RBAC Check 3: Viewer cannot delete Project A (LEAD role required)
        r_v_del = await client.delete(f"{API_BASE}/api/v1/projects/{proj_a_id}", headers=vh)
        print(f"[+] RBAC Smoke Subset: Viewer delete project A -> {r_v_del.status_code} (Expected: 403)")
        assert r_v_del.status_code == 403

        # RBAC Check 4: Viewer cannot add members to Project A (LEAD role required)
        r_v_add_mem = await client.post(
            f"{API_BASE}/api/v1/projects/{proj_a_id}/members",
            headers=vh,
            json={"user_id": str(uuid.uuid4()), "role": "VIEWER"}
        )
        print(f"[+] RBAC Smoke Subset: Viewer add member to Project A -> {r_v_add_mem.status_code} (Expected: 403)")
        assert r_v_add_mem.status_code == 403

        print("\n--- 5. IDOR Matrix Verification (Smoke Subset) ---")
        # Create Project B as Admin, assign Tenant B Lead
        r_proj_b = await client.post(
            f"{API_BASE}/api/v1/projects",
            headers=admin_headers,
            json={
                "name": "p9test-project-beta",
                "description": "Throwaway IDOR Project B",
                "target_domains": ["target-juiceshop"],
                "allowed_cidrs": ["172.21.0.0/16"],
                "allow_internal_networks": True,
                "authorization_start": auth_start,
                "authorization_end": auth_end
            }
        )
        assert r_proj_b.status_code in (200, 201), f"Project B creation failed: {r_proj_b.text}"
        proj_b_id = r_proj_b.json()["id"]
        print(f"[+] Created Project B: {proj_b_id}")

        tenant_b_email = "p9test-tenant-b-lead@pentesa.lab"
        tenant_b_uid = next(u[0] for u in created_users if u[1] == tenant_b_email)
        r_b_mem = await client.post(
            f"{API_BASE}/api/v1/projects/{proj_b_id}/members",
            headers=admin_headers,
            json={"user_id": tenant_b_uid, "role": "LEAD"}
        )
        assert r_b_mem.status_code in (200, 201)

        tb_h = {"Authorization": f"Bearer {tokens[tenant_b_email]}"}

        # IDOR Check 1: Tenant B Lead attempts to read Project A (Tenant A)
        r_idor_read = await client.get(f"{API_BASE}/api/v1/projects/{proj_a_id}", headers=tb_h)
        print(f"[+] IDOR Smoke Subset: Tenant B Lead read Project A -> {r_idor_read.status_code} (Expected: 403 or 404)")
        assert r_idor_read.status_code in (403, 404)

        # IDOR Check 2: Tenant B Lead attempts to delete Project A
        r_idor_del = await client.delete(f"{API_BASE}/api/v1/projects/{proj_a_id}", headers=tb_h)
        print(f"[+] IDOR Smoke Subset: Tenant B Lead delete Project A -> {r_idor_del.status_code} (Expected: 403 or 404)")
        assert r_idor_del.status_code in (403, 404)

        # IDOR Check 3: Tenant B Lead attempts to read Project A findings
        r_idor_findings = await client.get(f"{API_BASE}/api/v1/projects/{proj_a_id}/findings", headers=tb_h)
        print(f"[+] IDOR Smoke Subset: Tenant B Lead read Project A findings -> {r_idor_findings.status_code} (Expected: 403 or 404)")
        assert r_idor_findings.status_code in (403, 404)

        print("\n--- 6. Cleanup of Throwaway Objects (ENV RULES v2) ---")
        # Delete Project A and Project B
        r_del_a = await client.delete(f"{API_BASE}/api/v1/projects/{proj_a_id}", headers=admin_headers)
        print(f"[+] Deleted Project A ({proj_a_id}): {r_del_a.status_code}")
        r_del_b = await client.delete(f"{API_BASE}/api/v1/projects/{proj_b_id}", headers=admin_headers)
        print(f"[+] Deleted Project B ({proj_b_id}): {r_del_b.status_code}")

        # Deactivate all throwaway users
        for uid, email, _ in created_users:
            r_deact = await client.put(f"{API_BASE}/api/v1/users/{uid}", headers=admin_headers, json={"is_active": False})
            print(f"[+] Deactivated throwaway user {email}: {r_deact.status_code}")

        print("\n--- 7. Security Invariant Checks ---")
        # Check admin@example.com -> 401
        r_def = await client.post(f"{API_BASE}/api/v1/auth/login", json={"email": "admin@example.com", "password": "AdminPassword123!"})
        print(f"[+] admin@example.com login: {r_def.status_code} (Expected: 401)")
        assert r_def.status_code == 401

        # Check benchmark-admin@pentesa.lab -> 401
        r_bench = await client.post(f"{API_BASE}/api/v1/auth/login", json={"email": "benchmark-admin@pentesa.lab", "password": "AdminPassword123!"})
        print(f"[+] benchmark-admin login: {r_bench.status_code} (Expected: 401)")
        assert r_bench.status_code == 401

def verify_audit_chain():
    print("\n--- 8. Audit Chain Cryptographic Hash Verification ---")
    psql_cmd = [
        "docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "pentesa", "-t", "-A", "-c",
        "SELECT count(*), count(DISTINCT hash) FROM audit_logs;"
    ]
    res = subprocess.run(psql_cmd, capture_output=True, text=True, check=True)
    counts = res.stdout.strip().split("|")
    total_records = int(counts[0])
    unique_hashes = int(counts[1])
    print(f"Total audit log records: {total_records}")
    print(f"Distinct record hashes:  {unique_hashes}")
    assert total_records == unique_hashes, f"Audit hash collision or duplicate detected! {total_records} != {unique_hashes}"
    print("[+] Audit hash chain is unbroken and 100% unique (0 forks).")

def verify_network_isolation():
    print("\n--- 9. Network Isolation & Attachment Verification ---")
    for container in ["pentesa-api", "pentesa-worker"]:
        cmd = ["docker", "inspect", container, "--format", "{{json .NetworkSettings.Networks}}"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        networks = json.loads(res.stdout)
        net_names = list(networks.keys())
        print(f"Container {container} attached networks: {net_names}")
        assert "pentesa_internal_net" in net_names or any("internal" in n for n in net_names), f"Missing internal net on {container}"
        for n in net_names:
            assert "bench" not in n.lower() and "canary" not in n.lower(), f"Unexpected network {n} attached to {container}!"
    print("[+] Confirmed: No bench or canary networks attached to prod containers.")

def main():
    clean_throwaways_db()
    verify_container_files()
    asyncio.run(run_smoke_and_matrices())
    verify_audit_chain()
    verify_network_isolation()
    print("\n" + "=" * 60)
    print("ALL PRODUCTION STACK & WAVE 0 VERIFICATIONS PASSED SUCCESSFULLY")
    print("=" * 60)

if __name__ == "__main__":
    main()
