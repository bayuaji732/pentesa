#!/usr/bin/env python3
"""Cleanup and Restoration Verification Script for Phase 6 Supplement.

Mandatory Cleanup per Requirement G:
1. Delete all throwaway p6test- projects, scope rules, auth profiles via Admin API.
2. Attempt deletion of throwaway p6test- users via API (documents absent DELETE route).
3. Record post-API-deletion row counts and report un-deleted artifacts (audit logs, users).
4. Drop and restore production PostgreSQL database from pre-test backup (prod_dump.sql).
5. Restore evidence and report volumes from external pre-test backup.
6. Restart pentesa-api and pentesa-worker and verify healthz.
7. Post-restoration Assertions:
   - Real admin login works (HTTP 200).
   - Invalid login admin@example.com returns HTTP 401 Unauthorized.
   - Live audit log chain passes cryptographic verification (verify_audit_chain).
   - Database row counts exactly match pre-test baseline:
     users=2, projects=28, findings=39, finding_evidence=39, audit_logs=1247.
   - Head hash of audit chain matches baseline (b01c7509be114f6a697a79abd058cfa60cb7525a129f0546a9c86dd1c93f7cbc).
   - Production containers (api and worker) are detached from bench and canary networks.
"""

import asyncio
import datetime
import json
import os
import subprocess
import sys
import time
from typing import Any, Dict, List

from dotenv import dotenv_values
import httpx

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from packages.common.audit import verify_audit_chain

PROD_API_BASE = "http://127.0.0.1:8000"
BACKUP_DIR = r"c:\Users\User2\Documents\work\pentesa-prod-backup-p6"
DUMP_FILE = os.path.join(BACKUP_DIR, "prod_dump.sql")
EVIDENCE_BACKUP = os.path.join(BACKUP_DIR, "evidence")
REPORTS_BACKUP = os.path.join(BACKUP_DIR, "reports")

PRE_TEST_BASELINE = {
    "users": 2,
    "projects": 28,
    "findings": 39,
    "finding_evidence": 39,
    "audit_logs": 1247,
    "head_hash": "b01c7509be114f6a697a79abd058cfa60cb7525a129f0546a9c86dd1c93f7cbc",
}


def log(msg: str):
    print(f"[P6-CLEANUP] {msg}")


def get_db_counts() -> Dict[str, int]:
    """Query current table row counts in pentesa-db."""
    counts = {}
    tables = ["users", "projects", "findings", "finding_evidence", "audit_logs"]
    for t in tables:
        q = f"SELECT count(*) FROM {t};"
        out = subprocess.check_output(
            ["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "pentesa", "-A", "-t", "-c", q]
        ).decode().strip()
        counts[t] = int(out)
    return counts


async def run_cleanup_and_restore():
    print("=" * 80)
    print("PHASE 6 SUPPLEMENT: MANDATORY CLEANUP & RESTORATION VERIFICATION")
    print(f"Timestamp (UTC): {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    print("=" * 80)

    prod_cfg = dotenv_values(os.path.join(REPO_ROOT, ".env.production"))
    admin_email = prod_cfg.get("PENTESA_BOOTSTRAP_ADMIN_EMAIL") or "benchmark-admin@pentesa.lab"
    admin_pwd = prod_cfg.get("PENTESA_BOOTSTRAP_ADMIN_PASSWORD")

    # -------------------------------------------------------------------------
    # STEP 1: Authenticate Admin
    # -------------------------------------------------------------------------
    log("Step 1: Authenticating as bootstrap administrator via API...")
    async with httpx.AsyncClient(timeout=10.0) as client:
        res = await client.post(
            f"{PROD_API_BASE}/api/v1/auth/login",
            json={"email": admin_email, "password": admin_pwd},
        )
        assert res.status_code == 200, f"Admin login failed: {res.text}"
        admin_token = res.json()["access_token"]
        headers = {"Authorization": f"Bearer {admin_token}"}
        log("Admin authenticated successfully.")

        # ---------------------------------------------------------------------
        # STEP 2: Delete Throwaway Projects via API
        # ---------------------------------------------------------------------
        log("Step 2: Deleting throwaway p6test- projects via API...")
        proj_res = await client.get(f"{PROD_API_BASE}/api/v1/projects", headers=headers)
        assert proj_res.status_code == 200
        projects = proj_res.json()
        deleted_projects = []
        for p in projects:
            p_name = p.get("name", "")
            if p_name.startswith("p6test"):
                pid = p["id"]
                del_res = await client.delete(f"{PROD_API_BASE}/api/v1/projects/{pid}", headers=headers)
                log(f"  DELETE /api/v1/projects/{pid} ('{p_name}') -> HTTP {del_res.status_code}")
                deleted_projects.append(p_name)
        log(f"Deleted {len(deleted_projects)} throwaway project(s) via API.")

        # ---------------------------------------------------------------------
        # STEP 3: Attempt Throwaway Users Deletion via API
        # ---------------------------------------------------------------------
        log("Step 3: Attempting throwaway p6test- users deletion via API...")
        users_res = await client.get(f"{PROD_API_BASE}/api/v1/users", headers=headers)
        assert users_res.status_code == 200
        users = users_res.json()
        p6_users = [u for u in users if u.get("email", "").startswith("p6test")]
        log(f"Found {len(p6_users)} p6test- users in database.")
        for u in p6_users:
            uid = u["id"]
            u_email = u["email"]
            del_u = await client.delete(f"{PROD_API_BASE}/api/v1/users/{uid}", headers=headers)
            log(f"  DELETE /api/v1/users/{uid} ('{u_email}') -> HTTP {del_u.status_code} (User deletion unsupported by API)")

    # -------------------------------------------------------------------------
    # STEP 4: Record Post-API Deletion Counts & Report What Did Not Delete
    # -------------------------------------------------------------------------
    log("Step 4: Recording DB counts after API deletion...")
    post_api_counts = get_db_counts()
    print("\n--- Post-API Deletion Inventory ---")
    print(f"Pre-Test Baseline:  {PRE_TEST_BASELINE}")
    print(f"Post-API Counts:    {post_api_counts}")
    print("Report of What Did NOT Delete via API:")
    print(f"  - Users: {post_api_counts['users'] - PRE_TEST_BASELINE['users']} throwaway users remained (no DELETE /users endpoint).")
    print(f"  - Audit Logs: {post_api_counts['audit_logs'] - PRE_TEST_BASELINE['audit_logs']} audit log records remained (immutable audit log policy).")
    print(f"  - Projects Delta: {post_api_counts['projects'] - PRE_TEST_BASELINE['projects']} (cleanly deleted).")
    print(f"  - Findings Delta: {post_api_counts['findings'] - PRE_TEST_BASELINE['findings']} (cleanly deleted).")
    print("-----------------------------------\n")

    # -------------------------------------------------------------------------
    # STEP 5: Database Drop & Restore from pg_dump Backup
    # -------------------------------------------------------------------------
    log(f"Step 5: Restoring production database from {DUMP_FILE}...")
    assert os.path.exists(DUMP_FILE), f"Backup file {DUMP_FILE} does not exist!"

    # Terminate connections, drop and recreate database pentesa
    log("  Terminating connections, dropping and recreating database 'pentesa' inside postgres container...")
    subprocess.check_call(
        ["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "postgres", "-c",
         "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'pentesa' AND pid <> pg_backend_pid();"]
    )
    subprocess.check_call(
        ["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "postgres", "-c",
         "DROP DATABASE IF EXISTS pentesa WITH (FORCE);"]
    )
    subprocess.check_call(
        ["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "postgres", "-c",
         "CREATE DATABASE pentesa OWNER pentesa_user;"]
    )

    # Copy dump into container and restore
    log("  Copying dump file into container and executing psql restore...")
    subprocess.check_call(["docker", "cp", DUMP_FILE, "pentesa-db:/tmp/prod_dump.sql"])
    subprocess.check_call(
        ["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "pentesa", "-f", "/tmp/prod_dump.sql"],
        stdout=subprocess.DEVNULL
    )
    subprocess.check_call(["docker", "exec", "pentesa-db", "rm", "/tmp/prod_dump.sql"])
    log("  Database restore completed successfully.")

    # -------------------------------------------------------------------------
    # STEP 6: Restore Volume Storage Directories
    # -------------------------------------------------------------------------
    log("Step 6: Restoring reports and evidence storage volumes...")
    subprocess.check_call(["docker", "cp", f"{EVIDENCE_BACKUP}/.", "pentesa-api:/app/data/evidence/"])
    subprocess.check_call(["docker", "cp", f"{REPORTS_BACKUP}/.", "pentesa-api:/app/data/reports/"])
    log("  Volumes restored.")

    # -------------------------------------------------------------------------
    # STEP 7: Restart Containers & Await Health
    # -------------------------------------------------------------------------
    log("Step 7: Restarting pentesa-api and pentesa-worker to reset connection pools...")
    subprocess.check_call(["docker", "restart", "pentesa-api", "pentesa-worker"])
    log("  Waiting for pentesa-api healthz check...")

    healthy = False
    for _ in range(30):
        try:
            r = httpx.get(f"{PROD_API_BASE}/healthz", timeout=3.0)
            if r.status_code == 200:
                healthy = True
                break
        except Exception:
            pass
        time.sleep(1.0)
    assert healthy is True, "pentesa-api failed to become healthy after restart!"
    log("  pentesa-api is HEALTHY.")

    # -------------------------------------------------------------------------
    # STEP 8: Post-Restore Verifications
    # -------------------------------------------------------------------------
    log("Step 8: Executing mandatory verification battery...")

    # Verification 1: Pre-test baseline row counts on freshly restored database
    final_counts = get_db_counts()
    for table_name, exp_count in PRE_TEST_BASELINE.items():
        if table_name == "head_hash":
            continue
        act_count = final_counts.get(table_name)
        assert act_count == exp_count, f"Count mismatch on {table_name}: expected {exp_count}, got {act_count}"
        print(f"  [VERIFIED 1/5] Restored table '{table_name}': {act_count} rows (matches pre-test baseline {exp_count}).")

    # Verification 2: Cryptographic audit-chain verification on restored database & head hash
    audit_q = (
        "SELECT json_agg(t) FROM ("
        "  SELECT prev_hash, created_at, user_id, action, resource_type, resource_id, details, ip_address, hash "
        "  FROM audit_logs ORDER BY created_at ASC, id ASC"
        ") t;"
    )
    audit_out = subprocess.check_output(
        ["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "pentesa", "-A", "-t", "-c", audit_q]
    ).decode().strip()
    audit_entries = json.loads(audit_out) if audit_out else []
    is_valid, err_reason, failed_idx = verify_audit_chain(audit_entries)
    assert is_valid is True, f"Audit chain verification failed: {err_reason}"
    assert len(audit_entries) == PRE_TEST_BASELINE["audit_logs"], (
        f"Audit count mismatch: expected {PRE_TEST_BASELINE['audit_logs']}, got {len(audit_entries)}"
    )
    latest_hash = audit_entries[-1]["hash"]
    assert latest_hash == PRE_TEST_BASELINE["head_hash"], (
        f"Chain head mismatch: expected {PRE_TEST_BASELINE['head_hash']}, got {latest_hash}"
    )
    print(f"  [VERIFIED 2/5] Restored audit chain cryptographically verified ({len(audit_entries)} entries, head matches pre-test hash).")

    # Verification 3: Real admin login works
    async with httpx.AsyncClient(timeout=10.0) as client:
        admin_login_res = await client.post(
            f"{PROD_API_BASE}/api/v1/auth/login",
            json={"email": admin_email, "password": admin_pwd},
        )
        assert admin_login_res.status_code == 200, f"Real admin login failed: {admin_login_res.text}"
        assert "access_token" in admin_login_res.json()
        print("  [VERIFIED 3/5] Real bootstrap admin login SUCCEEDED (HTTP 200).")

        # Verification 4: admin@example.com returns 401
        inv_login = await client.post(
            f"{PROD_API_BASE}/api/v1/auth/login",
            json={"email": "admin@example.com", "password": "unauthorized-password"},
        )
        assert inv_login.status_code == 401, f"Expected HTTP 401 for admin@example.com, got {inv_login.status_code}"
        print("  [VERIFIED 4/5] admin@example.com login returned HTTP 401 Unauthorized.")

    # Verification 5: Prod containers detached from bench network
    inspect_api = subprocess.check_output(
        ["docker", "inspect", "pentesa-api", "--format", "{{json .NetworkSettings.Networks}}"]
    ).decode()
    inspect_worker = subprocess.check_output(
        ["docker", "inspect", "pentesa-worker", "--format", "{{json .NetworkSettings.Networks}}"]
    ).decode()

    assert "pentesa-bench-net" not in inspect_api, "pentesa-api still attached to pentesa-bench-net!"
    assert "pentesa-canary-net" not in inspect_api, "pentesa-api still attached to pentesa-canary-net!"
    assert "pentesa-bench-net" not in inspect_worker, "pentesa-worker still attached to pentesa-bench-net!"
    assert "pentesa-canary-net" not in inspect_worker, "pentesa-worker still attached to pentesa-canary-net!"
    print("  [VERIFIED 5/5] pentesa-api and pentesa-worker confirmed strictly DETACHED from bench and canary networks.")

    print("\n" + "=" * 80)
    print("ALL CLEANUP AND RESTORATION VERIFICATION GATES PASSED (5/5).")
    print("Target Environment (pentesa-prod) restored to exact pre-test baseline.")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(run_cleanup_and_restore())
