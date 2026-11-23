#!/usr/bin/env python3
"""Part 1 Step 5 & Step 6: Post-Hotfix Cleanup/Restore Proof + Demo Prep & AES-256 Encrypted Backup."""

import asyncio
import datetime
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from typing import Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import dotenv_values
import httpx

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from packages.common.audit import verify_audit_chain

PROD_API_BASE = "http://127.0.0.1:8000"
PRE_HOTFIX_BACKUP_DIR = r"c:\Users\User2\Documents\work\pentesa-prod-backup-hotfix-pre"
DEMO_BACKUP_DIR = r"c:\Users\User2\Documents\work\pentesa-prod-backup-demo-known-good"
PASSPHRASE_FILE = os.path.join(os.path.expanduser("~"), ".pentesa_demo_known_good_passphrase")

PRE_HOTFIX_BASELINE = {
    "users": 2,
    "projects": 28,
    "findings": 39,
    "finding_evidence": 39,
    "reports": 0,
    "audit_logs": 1254,
    "head_hash": "82889e3dce1ca2eb5d7c1f05677d16e3efddf7c1e3f58447e9a8685495f86f14",
}


def get_db_counts(db_name: str = "pentesa") -> Dict[str, int]:
    counts = {}
    for t in ("users", "projects", "findings", "finding_evidence", "reports", "audit_logs"):
        out = subprocess.check_output(
            ["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", db_name, "-A", "-t", "-c", f"SELECT count(*) FROM {t};"]
        ).decode().strip()
        counts[t] = int(out)
    return counts


def derive_key(passphrase_bytes: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    return kdf.derive(passphrase_bytes)


def encrypt_aes256_gcm(src_path: str, dst_path: str, passphrase_bytes: bytes) -> str:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(passphrase_bytes, salt)
    aesgcm = AESGCM(key)
    with open(src_path, "rb") as f:
        plaintext = f.read()
    ciphertext = aesgcm.encrypt(nonce, plaintext, b"pentesa-demo-known-good-v1")
    with open(dst_path, "wb") as f:
        f.write(b"PNT1" + salt + nonce + ciphertext)
    return hashlib.sha256(open(dst_path, "rb").read()).hexdigest()


def decrypt_aes256_gcm(src_path: str, dst_path: str, passphrase_bytes: bytes) -> None:
    with open(src_path, "rb") as f:
        blob = f.read()
    assert blob[:4] == b"PNT1", "Invalid encrypted backup magic header"
    salt = blob[4:20]
    nonce = blob[20:32]
    ciphertext = blob[32:]
    key = derive_key(passphrase_bytes, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, b"pentesa-demo-known-good-v1")
    with open(dst_path, "wb") as f:
        f.write(plaintext)


async def main() -> int:
    git_sha = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()
    git_dirty = "DIRTY" if subprocess.check_output(["git", "status", "--porcelain"]).decode().strip() else "CLEAN"
    print("=" * 80)
    print("PART 1 STEP 5 & STEP 6: CLEANUP/RESTORE PROOF & DEMO-KNOWN-GOOD BACKUP")
    print(f"Timestamp (UTC): {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    print(f"Git Commit: {git_sha} ({git_dirty})")
    print("Target Stack: http://127.0.0.1:8000 (pentesa-prod)")
    print("=" * 80)

    prod_cfg = dotenv_values(os.path.join(REPO_ROOT, ".env.production"))
    admin_email = prod_cfg["PENTESA_BOOTSTRAP_ADMIN_EMAIL"]
    admin_pwd = prod_cfg["PENTESA_BOOTSTRAP_ADMIN_PASSWORD"]

    # =========================================================================
    # STEP 5: CLEANUP VIA API & RESTORE FROM PRE-HOTFIX BACKUP
    # =========================================================================
    print("\n--- [STEP 5] API CLEANUP & RESTORE TO PRE-HOTFIX BASELINE ---")
    async with httpx.AsyncClient(timeout=15.0) as client:
        r_login = await client.post(f"{PROD_API_BASE}/api/v1/auth/login", json={"email": admin_email, "password": admin_pwd})
        assert r_login.status_code == 200
        headers = {"Authorization": f"Bearer {r_login.json()['access_token']}"}
        projs = (await client.get(f"{PROD_API_BASE}/api/v1/projects", headers=headers)).json()
        for p in projs:
            if p.get("name", "").startswith("p6test"):
                dr = await client.delete(f"{PROD_API_BASE}/api/v1/projects/{p['id']}", headers=headers)
                print(f"  DELETE /api/v1/projects/{p['id']} ({p['name']}) -> HTTP {dr.status_code}")

    dump_file = os.path.join(PRE_HOTFIX_BACKUP_DIR, "prod_dump.sql")
    assert os.path.exists(dump_file), f"Missing {dump_file}"
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
    subprocess.check_call(["docker", "cp", dump_file, "pentesa-db:/tmp/pre_hotfix_dump.sql"])
    subprocess.check_call(
        ["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "pentesa", "-f", "/tmp/pre_hotfix_dump.sql"],
        stdout=subprocess.DEVNULL,
    )
    subprocess.check_call(["docker", "exec", "pentesa-db", "rm", "/tmp/pre_hotfix_dump.sql"])
    subprocess.check_call(["docker", "cp", os.path.join(PRE_HOTFIX_BACKUP_DIR, "evidence") + "/.", "pentesa-api:/app/data/evidence/"])
    subprocess.check_call(["docker", "cp", os.path.join(PRE_HOTFIX_BACKUP_DIR, "reports") + "/.", "pentesa-api:/app/data/reports/"])
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
    assert healthy, "pentesa-api failed health check after restore"

    # Mandatory Verification Battery (Step 5)
    restored_counts = get_db_counts("pentesa")
    for k in ("users", "projects", "findings", "finding_evidence", "reports", "audit_logs"):
        assert restored_counts[k] == PRE_HOTFIX_BASELINE[k], f"Mismatch {k}: {restored_counts[k]} != {PRE_HOTFIX_BASELINE[k]}"
    print(f"  [VERIFIED 1/6] Restored DB counts exact match: {restored_counts}")

    audit_q = "SELECT json_agg(t) FROM (SELECT prev_hash, created_at, user_id, action, resource_type, resource_id, details, ip_address, hash FROM audit_logs ORDER BY created_at ASC, id ASC) t;"
    audit_entries = json.loads(
        subprocess.check_output(["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "pentesa", "-A", "-t", "-c", audit_q]).decode().strip()
    )
    valid, err, _ = verify_audit_chain(audit_entries)
    assert valid, f"Audit chain invalid: {err}"
    head = audit_entries[-1]["hash"]
    assert head == PRE_HOTFIX_BASELINE["head_hash"], f"Head mismatch: {head}"
    print(f"  [VERIFIED 2/6] Audit chain verified intact ({len(audit_entries)} rows, head={head})")

    async with httpx.AsyncClient(timeout=10.0) as client:
        r_ok = await client.post(f"{PROD_API_BASE}/api/v1/auth/login", json={"email": admin_email, "password": admin_pwd})
        assert r_ok.status_code == 200
        admin_token = r_ok.json()["access_token"]
        headers = {"Authorization": f"Bearer {admin_token}"}
        print("  [VERIFIED 3/6] Real bootstrap admin login -> HTTP 200")

        r_ex = await client.post(f"{PROD_API_BASE}/api/v1/auth/login", json={"email": "admin@example.com", "password": "wrong"})
        assert r_ex.status_code == 401
        print("  [VERIFIED 4/6] admin@example.com login -> HTTP 401")

        users_list = (await client.get(f"{PROD_API_BASE}/api/v1/users", headers=headers)).json()
        ba = next((u for u in users_list if u["email"] == "benchmark-admin@pentesa.lab"), None)
        assert ba is not None and ba["is_active"] is False, f"benchmark-admin unexpected state: {ba}"
        r_ba = await client.post(f"{PROD_API_BASE}/api/v1/auth/login", json={"email": "benchmark-admin@pentesa.lab", "password": "wrong"})
        assert r_ba.status_code == 401
        print("  [VERIFIED 5/6] benchmark-admin@pentesa.lab confirmed is_active=False and login -> HTTP 401")

    api_nets = subprocess.check_output(["docker", "inspect", "pentesa-api", "--format", "{{json .NetworkSettings.Networks}}"]).decode()
    wrk_nets = subprocess.check_output(["docker", "inspect", "pentesa-worker", "--format", "{{json .NetworkSettings.Networks}}"]).decode()
    assert "pentesa-bench-net" not in api_nets and "pentesa-canary-net" not in api_nets
    assert "pentesa-bench-net" not in wrk_nets and "pentesa-canary-net" not in wrk_nets
    print("  [VERIFIED 6/6] pentesa-api & pentesa-worker confirmed strictly detached from bench/canary networks.")

    # =========================================================================
    # STEP 6: DEMO PREP (GENERATE ONE REPORT + DOWNLOAD + ENCRYPTED DEMO BACKUP)
    # =========================================================================
    print("\n--- [STEP 6] DEMO PREP: GENERATE 1 REPORT FOR PROJECT WITH CONFIRMED FINDINGS ---")
    async with httpx.AsyncClient(timeout=60.0) as client:
        projs = (await client.get(f"{PROD_API_BASE}/api/v1/projects", headers=headers)).json()
        chosen_proj = None
        chosen_confirmed_count = 0
        for p in projs:
            flist = (await client.get(f"{PROD_API_BASE}/api/v1/projects/{p['id']}/findings", headers=headers)).json()
            conf = [f for f in flist if str(f.get("status", "")).lower() == "confirmed"]
            if len(conf) > chosen_confirmed_count:
                chosen_proj = p
                chosen_confirmed_count = len(conf)
        assert chosen_proj is not None and chosen_confirmed_count > 0, "No project with confirmed findings found!"
        print(f"  Selected project: {chosen_proj['name']} ({chosen_proj['id']}) with {chosen_confirmed_count} confirmed finding(s)")

        # Generate one HTML report (and confirm download) via normal API
        gen_res = await client.post(
            f"{PROD_API_BASE}/api/v1/projects/{chosen_proj['id']}/reports/generate",
            json={
                "format": "HTML",
                "template_name": "ptes_standard",
                "title": f"PTES Penetration Test Report - {chosen_proj['name']}",
            },
            headers=headers,
        )
        assert gen_res.status_code in (200, 201), f"Report generation failed: {gen_res.status_code} {gen_res.text}"
        rep = gen_res.json()
        rep_id = rep["id"]
        rep_sha = rep["file_hash_sha256"]
        print(f"  Generated report: id={rep_id}, format={rep['format']}, sha256={rep_sha}")

        dl_res = await client.get(f"{PROD_API_BASE}/api/v1/reports/{rep_id}/download", headers=headers)
        assert dl_res.status_code == 200, f"Report download failed: {dl_res.status_code}"
        dl_bytes = dl_res.content
        dl_sha = hashlib.sha256(dl_bytes).hexdigest()
        assert len(dl_bytes) > 500, f"Report too small: {len(dl_bytes)} bytes"
        assert dl_sha == rep_sha, f"Download SHA-256 mismatch: {dl_sha} != {rep_sha}"
        print(f"  Confirmed download: HTTP 200, size={len(dl_bytes)} bytes, SHA-256 matched ({dl_sha[:16]}...)")

    # Take fresh pg_dump labelled demo-known-good + volumes
    print("\n--- [STEP 6b] FRESH PG_DUMP (demo-known-good) + AES-256 ENCRYPTION + SCRATCH RESTORE ---")
    os.makedirs(os.path.join(DEMO_BACKUP_DIR, "evidence"), exist_ok=True)
    os.makedirs(os.path.join(DEMO_BACKUP_DIR, "reports"), exist_ok=True)
    plain_dump = os.path.join(DEMO_BACKUP_DIR, "demo-known-good.sql")
    enc_dump = os.path.join(DEMO_BACKUP_DIR, "demo-known-good.sql.enc")

    subprocess.check_call(["docker", "exec", "pentesa-db", "pg_dump", "-U", "pentesa_user", "-d", "pentesa", "-f", "/tmp/demo-known-good.sql"])
    subprocess.check_call(["docker", "cp", "pentesa-db:/tmp/demo-known-good.sql", plain_dump])
    subprocess.check_call(["docker", "exec", "pentesa-db", "rm", "/tmp/demo-known-good.sql"])
    subprocess.check_call(["docker", "cp", "pentesa-api:/app/data/evidence/.", os.path.join(DEMO_BACKUP_DIR, "evidence")])
    subprocess.check_call(["docker", "cp", "pentesa-api:/app/data/reports/.", os.path.join(DEMO_BACKUP_DIR, "reports")])

    demo_counts = get_db_counts("pentesa")
    demo_head = subprocess.check_output(
        ["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "pentesa", "-A", "-t", "-c",
         "SELECT hash FROM audit_logs ORDER BY created_at DESC, id DESC LIMIT 1;"]
    ).decode().strip()
    plain_size = os.path.getsize(plain_dump)
    plain_sha = hashlib.sha256(open(plain_dump, "rb").read()).hexdigest()

    # Generate strong random passphrase stored strictly outside repo (NEVER printed)
    passphrase_str = secrets.token_urlsafe(48)
    with open(PASSPHRASE_FILE, "w", encoding="utf-8") as pf:
        pf.write(passphrase_str)
    passphrase_bytes = passphrase_str.encode("utf-8")

    enc_sha = encrypt_aes256_gcm(plain_dump, enc_dump, passphrase_bytes)
    enc_size = os.path.getsize(enc_dump)
    # Remove plaintext SQL so only AES-256 encrypted backup remains on disk
    os.remove(plain_dump)
    print(f"  Created AES-256-GCM encrypted backup: {enc_dump}")
    print(f"  Plaintext SQL size={plain_size} bytes (SHA-256={plain_sha[:16]}...); removed after encryption.")
    print(f"  Encrypted artifact size={enc_size} bytes (SHA-256={enc_sha}); passphrase stored outside repo at user profile (NOT printed).")
    print(f"  demo-known-good DB counts: {demo_counts}")
    print(f"  demo-known-good audit head: {demo_head}")

    # Verify decrypt + restore into scratch database
    scratch_db = "pentesa_scratch_verify"
    with tempfile.NamedTemporaryFile(suffix=".sql", delete=False) as tf:
        tmp_dec_path = tf.name
    try:
        decrypt_aes256_gcm(enc_dump, tmp_dec_path, passphrase_bytes)
        dec_sha = hashlib.sha256(open(tmp_dec_path, "rb").read()).hexdigest()
        assert dec_sha == plain_sha, "Decrypted SQL SHA-256 mismatch!"
        subprocess.check_call(
            ["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "postgres", "-c",
             f"DROP DATABASE IF EXISTS {scratch_db} WITH (FORCE);"],
            stdout=subprocess.DEVNULL,
        )
        subprocess.check_call(
            ["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "postgres", "-c",
             f"CREATE DATABASE {scratch_db} OWNER pentesa_user;"],
            stdout=subprocess.DEVNULL,
        )
        subprocess.check_call(["docker", "cp", tmp_dec_path, f"pentesa-db:/tmp/{scratch_db}.sql"])
        subprocess.check_call(
            ["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", scratch_db, "-f", f"/tmp/{scratch_db}.sql"],
            stdout=subprocess.DEVNULL,
        )
        subprocess.check_call(["docker", "exec", "pentesa-db", "rm", f"/tmp/{scratch_db}.sql"])
        scratch_counts = get_db_counts(scratch_db)
        assert scratch_counts == demo_counts, f"Scratch restore count mismatch: {scratch_counts} != {demo_counts}"
        print(f"  [VERIFIED SCRATCH RESTORE] Decrypted AES-256 dump restored cleanly into '{scratch_db}': {scratch_counts}")
    finally:
        if os.path.exists(tmp_dec_path):
            os.remove(tmp_dec_path)
        subprocess.run(
            ["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "postgres", "-c",
             f"DROP DATABASE IF EXISTS {scratch_db} WITH (FORCE);"],
            stdout=subprocess.DEVNULL,
            check=False,
        )
        print(f"  Dropped scratch database '{scratch_db}'.")

    # List all backup folders in parent directory (DO NOT DELETE)
    print("\n--- [STEP 6c] BACKUP FOLDERS INVENTORY (NO DELETIONS PERFORMED) ---")
    parent = os.path.dirname(DEMO_BACKUP_DIR)
    for name in sorted(os.listdir(parent)):
        if "backup" in name.lower():
            full = os.path.join(parent, name)
            total_sz = sum(
                os.path.getsize(os.path.join(dp, fn))
                for dp, _, fns in os.walk(full)
                for fn in fns
            )
            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(full)).isoformat()
            print(f"  - {full} | size={total_sz:,} bytes | modified={mtime}")

    print("=" * 80)
    print("PART 1 COMPLETE: ALL HOTFIX, CLEANUP, DEMO PREP, AND ENCRYPTED BACKUP CHECKS PASSED.")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
