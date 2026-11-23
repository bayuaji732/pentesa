#!/usr/bin/env python3
"""Phase 7 Mandatory Cleanup & Restoration Proof Script.

Restores pentesa-prod cleanly to the encrypted demo-known-good baseline snapshot:
  users=2, projects=28, findings=39, finding_evidence=39, reports=1, audit_logs=1258
  head_hash=97e166a6108be5ef0e5983ad45e9d7fd2f3c6f7efeafd702939327a08208ade4
Verifies all 6 mandatory restoration gates.
"""

import asyncio
import datetime
import json
import os
import subprocess
import sys
import tempfile
import time
from typing import Dict

from dotenv import dotenv_values
import httpx

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from benchmark.p6b.hotfix_cleanup_and_demo_prep import DEMO_BACKUP_DIR, PASSPHRASE_FILE, decrypt_aes256_gcm, get_db_counts
from packages.common.audit import verify_audit_chain

PROD_API_BASE = "http://127.0.0.1:8000"
DEMO_BASELINE = {
    "users": 2,
    "projects": 28,
    "findings": 39,
    "finding_evidence": 39,
    "reports": 1,
    "audit_logs": 1258,
    "head_hash": "97e166a6108be5ef0e5983ad45e9d7fd2f3c6f7efeafd702939327a08208ade4",
}


async def main() -> int:
    git_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT).decode().strip()
    git_dirty = "DIRTY" if subprocess.check_output(["git", "status", "--porcelain"], cwd=REPO_ROOT).decode().strip() else "CLEAN"

    print("=" * 80)
    print("PHASE 7: MANDATORY CLEANUP & RESTORATION PROOF (demo-known-good BASELINE)")
    print(f"Timestamp (UTC): {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    print(f"Git Commit: {git_sha} ({git_dirty})")
    print("Target Stack: http://127.0.0.1:8000 (pentesa-prod)")
    print("=" * 80)

    prod_cfg = dotenv_values(os.path.join(REPO_ROOT, ".env.production"))
    admin_email = prod_cfg["PENTESA_BOOTSTRAP_ADMIN_EMAIL"]
    admin_pwd = prod_cfg["PENTESA_BOOTSTRAP_ADMIN_PASSWORD"]

    # Step 1: Delete p7test- projects via Admin API first
    async with httpx.AsyncClient(timeout=15.0) as client:
        r_login = await client.post(f"{PROD_API_BASE}/api/v1/auth/login", json={"email": admin_email, "password": admin_pwd})
        assert r_login.status_code == 200
        headers = {"Authorization": f"Bearer {r_login.json()['access_token']}"}
        projs = (await client.get(f"{PROD_API_BASE}/api/v1/projects", headers=headers)).json()
        for p in projs:
            if p.get("name", "").startswith("p7test"):
                dr = await client.delete(f"{PROD_API_BASE}/api/v1/projects/{p['id']}", headers=headers)
                print(f"  DELETE /api/v1/projects/{p['id']} ({p['name']}) -> HTTP {dr.status_code}")

    post_api_counts = get_db_counts("pentesa")
    print(f"  Post-API deletion counts (before DB restore): {post_api_counts}")

    # Step 2: Decrypt demo-known-good.sql.enc and restore DB + volumes
    enc_dump = os.path.join(DEMO_BACKUP_DIR, "demo-known-good.sql.enc")
    assert os.path.exists(enc_dump), f"Missing {enc_dump}"
    assert os.path.exists(PASSPHRASE_FILE), "Missing external passphrase file"
    passphrase_bytes = open(PASSPHRASE_FILE, "r", encoding="utf-8").read().strip().encode("utf-8")

    with tempfile.NamedTemporaryFile(suffix=".sql", delete=False) as tf:
        tmp_sql = tf.name
    try:
        decrypt_aes256_gcm(enc_dump, tmp_sql, passphrase_bytes)
        subprocess.check_call(
            ["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "postgres", "-c",
             "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'pentesa' AND pid <> pg_backend_pid();"],
            stdout=subprocess.DEVNULL,
        )
        subprocess.check_call(
            ["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "postgres", "-c",
             "DROP DATABASE IF EXISTS pentesa WITH (FORCE);"],
            stdout=subprocess.DEVNULL,
        )
        subprocess.check_call(
            ["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "postgres", "-c",
             "CREATE DATABASE pentesa OWNER pentesa_user;"],
            stdout=subprocess.DEVNULL,
        )
        subprocess.check_call(["docker", "cp", tmp_sql, "pentesa-db:/tmp/demo_restore.sql"])
        subprocess.check_call(
            ["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "pentesa", "-f", "/tmp/demo_restore.sql"],
            stdout=subprocess.DEVNULL,
        )
        subprocess.check_call(["docker", "exec", "pentesa-db", "rm", "/tmp/demo_restore.sql"])
    finally:
        if os.path.exists(tmp_sql):
            os.remove(tmp_sql)

    # Restore reports & evidence volumes cleanly (clear stale throwaway report files first)
    subprocess.check_call(["docker", "exec", "pentesa-api", "sh", "-c", "rm -rf /app/data/reports/* /app/data/evidence/*"])
    subprocess.check_call(["docker", "cp", os.path.join(DEMO_BACKUP_DIR, "evidence") + "/.", "pentesa-api:/app/data/evidence/"])
    subprocess.check_call(["docker", "cp", os.path.join(DEMO_BACKUP_DIR, "reports") + "/.", "pentesa-api:/app/data/reports/"])
    subprocess.check_call(["docker", "restart", "pentesa-api", "pentesa-worker"], stdout=subprocess.DEVNULL)

    healthy = False
    for _ in range(30):
        try:
            if httpx.get(f"{PROD_API_BASE}/healthz", timeout=3.0).status_code == 200:
                healthy = True
                break
        except Exception:
            pass
        time.sleep(1.0)
    assert healthy, "pentesa-api failed to recover after restore"

    # Step 3: Mandatory 6-Gate Verification Battery
    restored = get_db_counts("pentesa")
    for k in ("users", "projects", "findings", "finding_evidence", "reports", "audit_logs"):
        assert restored[k] == DEMO_BASELINE[k], f"Mismatch {k}: {restored[k]} != {DEMO_BASELINE[k]}"
    print(f"  [VERIFIED 1/6] Restored DB counts exact match to demo-known-good: {restored}")

    audit_q = "SELECT json_agg(t) FROM (SELECT prev_hash, created_at, user_id, action, resource_type, resource_id, details, ip_address, hash FROM audit_logs ORDER BY created_at ASC, id ASC) t;"
    audit_entries = json.loads(
        subprocess.check_output(["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "pentesa", "-A", "-t", "-c", audit_q]).decode().strip()
    )
    ok_chain, err_chain, _ = verify_audit_chain(audit_entries)
    assert ok_chain, f"Audit chain invalid: {err_chain}"
    head = audit_entries[-1]["hash"]
    assert head == DEMO_BASELINE["head_hash"], f"Head mismatch: {head} != {DEMO_BASELINE['head_hash']}"
    print(f"  [VERIFIED 2/6] Audit chain verified intact ({len(audit_entries)} rows, head={head})")

    async with httpx.AsyncClient(timeout=10.0) as client:
        r_ok = await client.post(f"{PROD_API_BASE}/api/v1/auth/login", json={"email": admin_email, "password": admin_pwd})
        assert r_ok.status_code == 200
        tok = r_ok.json()["access_token"]
        print("  [VERIFIED 3/6] Real bootstrap admin login -> HTTP 200")

        r_ex = await client.post(f"{PROD_API_BASE}/api/v1/auth/login", json={"email": "admin@example.com", "password": "wrong"})
        assert r_ex.status_code == 401
        print("  [VERIFIED 4/6] admin@example.com login -> HTTP 401")

        users_list = (await client.get(f"{PROD_API_BASE}/api/v1/users", headers={"Authorization": f"Bearer {tok}"})).json()
        ba = next((u for u in users_list if u["email"] == "benchmark-admin@pentesa.lab"), None)
        assert ba is not None and ba["is_active"] is False
        print("  [VERIFIED 5/6] benchmark-admin@pentesa.lab confirmed is_active=False")

    api_nets = subprocess.check_output(["docker", "inspect", "pentesa-api", "--format", "{{json .NetworkSettings.Networks}}"]).decode()
    wrk_nets = subprocess.check_output(["docker", "inspect", "pentesa-worker", "--format", "{{json .NetworkSettings.Networks}}"]).decode()
    assert "pentesa-bench-net" not in api_nets and "pentesa-canary-net" not in api_nets
    assert "pentesa-bench-net" not in wrk_nets and "pentesa-canary-net" not in wrk_nets
    print("  [VERIFIED 6/6] pentesa-api & pentesa-worker confirmed strictly detached from bench/canary networks.")

    print("=" * 80)
    print("PHASE 7 CLEANUP & RESTORATION PROOF PASSED (6/6 GATES).")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
