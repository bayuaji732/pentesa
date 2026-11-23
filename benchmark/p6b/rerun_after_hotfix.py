#!/usr/bin/env python3
"""Post-Hotfix Re-Verification Runner for DEFECT-API-02 (tag: hotfix-api-02).

Executes Part 1 Step 4 against live pentesa-prod without touching original Phase 6/6b files:
1. Real-admin smoke test (all project detail calls 200 + live pentesa-db audit chain check).
2. Throwaway p6test- users provisioning (Rules A-H).
3. Project detail (GET /api/v1/projects/{id}) verification for admin, lead, tester, viewer (all 200).
4. Full 76-operation x 5-role OpenAPI RBAC matrix rerun -> zero 5xx asserted.
5. Full 10-resource IDOR matrix rerun with positive controls -> zero 5xx asserted.

Outputs saved strictly to p6b_rerun_after_hotfix_* artifacts.
"""

import asyncio
import datetime
import hashlib
import json
import os
import subprocess
import sys
import time
from typing import Any, Dict

import httpx

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import benchmark.p6b.test_runner_p6b as p6b_mod
from benchmark.p6b.demo_smoke_test import run_smoke_test
from benchmark.p6b.test_runner_p6b import PROD_API_BASE, Phase6bWireRunner, compute_file_sha256

EVIDENCE_DIR = os.path.join(REPO_ROOT, "docs/audit/evidence/phase6")
RBAC_OUT = os.path.join(EVIDENCE_DIR, "p6b_rerun_after_hotfix_rbac_matrix.json")
IDOR_OUT = os.path.join(EVIDENCE_DIR, "p6b_rerun_after_hotfix_idor_matrix.json")
RESULTS_OUT = os.path.join(EVIDENCE_DIR, "p6b_rerun_after_hotfix_results.json")


async def main() -> int:
    runner_sha = compute_file_sha256(os.path.abspath(__file__))
    p6b_sha = compute_file_sha256(os.path.abspath(p6b_mod.__file__))
    git_sha = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()
    git_dirty = "DIRTY" if subprocess.check_output(["git", "status", "--porcelain"]).decode().strip() else "CLEAN"

    print("=" * 80)
    print("PENTESA POST-HOTFIX RE-VERIFICATION (DEFECT-API-02 / hotfix-api-02)")
    print(f"Timestamp (UTC): {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    print(f"Git Commit: {git_sha} ({git_dirty})")
    print("Exact Command: .venv\\Scripts\\python.exe -u benchmark/p6b/rerun_after_hotfix.py")
    print(f"Runner SHA-256: {runner_sha}")
    print(f"Base P6b Runner SHA-256: {p6b_sha}")
    print(f"Target Stack: {PROD_API_BASE} (pentesa-prod)")
    print("Database Engine: PostgreSQL 16 Alpine (pentesa-db)")
    print("=" * 80)

    # 1. Verify prod network isolation before starting
    api_nets = subprocess.check_output(
        ["docker", "inspect", "pentesa-api", "--format", "{{json .NetworkSettings.Networks}}"]
    ).decode().strip()
    worker_nets = subprocess.check_output(
        ["docker", "inspect", "pentesa-worker", "--format", "{{json .NetworkSettings.Networks}}"]
    ).decode().strip()
    assert "pentesa-bench-net" not in api_nets and "pentesa-canary-net" not in api_nets, f"API attached to bench/canary: {api_nets}"
    assert "pentesa-bench-net" not in worker_nets and "pentesa-canary-net" not in worker_nets, f"Worker attached to bench/canary: {worker_nets}"
    print("[HOTFIX-VERIFY] Network isolation verified: pentesa-api & pentesa-worker detached from bench/canary.")

    # 2. Run read-only real-admin demo smoke test (fixed to query pentesa-db)
    print("\n--- [1/4] REAL-ADMIN DEMO SMOKE TEST ---")
    await run_smoke_test()

    # 3. Redirect P6b matrix output paths so original Phase 6b files remain untouched
    p6b_mod.RBAC_MATRIX_PATH = RBAC_OUT
    p6b_mod.IDOR_MATRIX_PATH = IDOR_OUT

    runner = Phase6bWireRunner(live_llm=False)
    await runner.initialize()

    # 4. Explicit GET /api/v1/projects/{id} check for real admin, lead, tester, viewer
    print("\n--- [2/4] PROJECT DETAIL 200 CHECK ACROSS ALL AUTHORIZED ROLES ---")
    proj_a_id = runner.p6_projects["alpha"]["id"]
    role_checks = {}
    role_tokens = {
        "real_admin": runner.admin_token,
        "lead": runner.p6_tokens["p6test-tenant-a-lead@pentesa.lab"],
        "tester": runner.p6_tokens["p6test-tenant-a-member@pentesa.lab"],
        "viewer": runner.p6_tokens["p6test-tenant-a-viewer@pentesa.lab"],
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        for role_name, tok in role_tokens.items():
            t0 = time.time()
            r = await client.get(
                f"{PROD_API_BASE}/api/v1/projects/{proj_a_id}",
                headers={"Authorization": f"Bearer {tok}"},
            )
            lat = round((time.time() - t0) * 1000, 2)
            body = r.json() if r.status_code == 200 else {"error": r.text[:200]}
            members_with_user = sum(1 for m in body.get("members", []) if isinstance(m, dict) and m.get("user")) if r.status_code == 200 else 0
            role_checks[role_name] = {
                "status_code": r.status_code,
                "latency_ms": lat,
                "members_count": len(body.get("members", [])) if r.status_code == 200 else 0,
                "members_with_user": members_with_user,
            }
            print(f"  [ROLE-DETAIL] {role_name:<12} -> GET /api/v1/projects/{proj_a_id} : HTTP {r.status_code} ({lat}ms, members={role_checks[role_name]['members_count']}, users_loaded={members_with_user})")
            assert r.status_code == 200, f"Expected HTTP 200 for {role_name}, got {r.status_code}: {r.text}"
            assert members_with_user >= 1, f"Expected eager-loaded member.user for {role_name}"

    # 5. Rerun RBAC matrix (must have 0 5xx)
    print("\n--- [3/4] RBAC MATRIX RERUN (ZERO 5XX REQUIRED) ---")
    t0 = time.time()
    rbac_res = await runner.test_rbac_matrix()
    rbac_res["duration_seconds"] = round(time.time() - t0, 3)
    print(f"[{rbac_res['verdict']}] {rbac_res['test_id']} - {rbac_res['details']} ({rbac_res['duration_seconds']}s)")

    # 6. Rerun IDOR matrix with positive controls (must have 0 5xx)
    print("\n--- [4/4] IDOR MATRIX RERUN WITH POSITIVE CONTROLS (ZERO 5XX REQUIRED) ---")
    t0 = time.time()
    idor_res = await runner.test_idor_matrix()
    idor_res["duration_seconds"] = round(time.time() - t0, 3)
    print(f"[{idor_res['verdict']}] {idor_res['test_id']} - {idor_res['details']} ({idor_res['duration_seconds']}s)")

    summary = {
        "metadata": {
            "purpose": "Post-hotfix re-verification for DEFECT-API-02 (tag hotfix-api-02)",
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "git_commit": git_sha,
            "git_status": git_dirty,
            "runner_sha256": runner_sha,
            "target_environment": "pentesa-prod (docker-compose.yml)",
        },
        "project_detail_role_checks": role_checks,
        "rbac_matrix_result": rbac_res,
        "idor_matrix_result": idor_res,
    }
    with open(RESULTS_OUT, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    assert rbac_res["verdict"] == "PASS", f"RBAC rerun did not pass: {rbac_res}"
    assert idor_res["verdict"] == "PASS", f"IDOR rerun did not pass: {idor_res}"
    print("=" * 80)
    print(f"POST-HOTFIX RE-VERIFICATION PASSED: 0 5xx across smoke, role-detail, RBAC, and IDOR.")
    print(f"Saved: {RESULTS_OUT}")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
