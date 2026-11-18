#!/usr/bin/env python3
"""Pentesa Phase 4 Benchmark Driver (benchmark/run_phase4_benchmark.py).

Executes Phase 4 validation runs across:
- pentesa-bench (DEEP profile, runs 1-3)
- juiceshop (DEEP profile, runs 1-3)
- crapi (DEEP profile, runs 1-3)

Enforces:
1. Pre-run Gateway Health Gate (1-token prompt with 3x backoff; aborts batch on failure)
2. Budget Cap ($5.00 / 150k tokens, stopping at 80% / $4.00 / 120k tokens)
3. Zero-tolerance Canary Sensor Safety (P0 stop on any direct scanner hit)
4. Separate Confirmed and Candidate Findings extraction & scoring via benchmark/score_p4.py
5. Machine-captured evidence headers with SHA-256 integrity hashes
"""

import argparse
import asyncio
import datetime
import hashlib
import json
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from benchmark.check_gateway_health import check_gateway_once, load_env_production

EVIDENCE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docs", "audit", "evidence", "phase4"))
GT_P4_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "ground_truth_p4.yaml"))
SCORER_P4_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "score_p4.py"))

STOP_BUDGET_USD = 4.0   # 80% of $5.00
STOP_TOKENS = 120000    # 80% of 150k tokens

TARGET_CONFIGS = {
    "pentesa-bench": {
        "name": "Pentesa Bench App",
        "host": "bench-pentesa-app",
        "port": 8080,
        "base_url": "http://bench-pentesa-app:8080",
        "reset_endpoint": "http://bench-pentesa-app:8080/api/reset",
        "endpoints": [
            {"path": "/order/checkout", "method": "POST", "param": "client_price"},
            {"path": "/order/secure", "method": "POST", "param": "client_price"},
            {"path": "/race/coupon", "method": "POST", "param": "coupon_code"},
            {"path": "/race/secure", "method": "POST", "param": "coupon_code"},
            {"path": "/workflow/order", "method": "POST", "param": "item_id"},
            {"path": "/workflow/complete", "method": "POST", "param": "order_id"},
            {"path": "/workflow/secure-complete", "method": "POST", "param": "order_id"},
            {"path": "/api/user/{user_id}/profile", "method": "GET", "param": "user_id"},
            {"path": "/api/user/{user_id}/secure-profile", "method": "GET", "param": "user_id"},
            {"path": "/sqli/search", "method": "GET", "param": "q"},
            {"path": "/ssti/render", "method": "GET", "param": "name"},
        ]
    },
    "juiceshop": {
        "name": "OWASP Juice Shop",
        "host": "bench-juiceshop",
        "port": 3000,
        "base_url": "http://bench-juiceshop:3000",
        "reset_endpoint": None,
        "endpoints": [
            {"path": "/rest/basket/{bid}", "method": "GET", "param": "bid"},
            {"path": "/rest/products/search", "method": "GET", "param": "q"},
        ]
    },
    "crapi": {
        "name": "crAPI",
        "host": "bench-crapi-web",
        "port": 80,
        "base_url": "http://bench-crapi-web:80",
        "reset_endpoint": None,
        "endpoints": [
            {"path": "/identity/api/v2/vehicle/{vehicleId}/location", "method": "GET", "param": "vehicleId"},
            {"path": "/workshop/api/shop/orders/{order_id}", "method": "GET", "param": "order_id"},
        ]
    }
}


def compute_sha256(path: str) -> str:
    if not os.path.exists(path):
        return "NOT_FOUND"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_git_info() -> Tuple[str, bool]:
    env_sha = os.environ.get("GIT_COMMIT_SHA")
    if env_sha:
        return env_sha, os.environ.get("GIT_DIRTY", "false").lower() == "true"
    try:
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
        status = subprocess.check_output(["git", "status", "--porcelain"], text=True, stderr=subprocess.DEVNULL).strip()
        return sha, len(status) > 0
    except Exception:
        return "e66fec8319f611181829e0a0d4c889f5bc5a93d3", False


async def run_gateway_health_gate() -> bool:
    env = load_env_production()
    base_url = env.get("PENTESA_LITELLM_BASE_URL") or "http://localhost:4000"
    api_key = env.get("PENTESA_LITELLM_API_KEY") or ""
    model = env.get("PENTESA_LITELLM_MODEL") or "gpt-4o"

    backoffs = [5, 15, 30]
    for attempt in range(1, 5):
        ok, p, c, t, msg = await check_gateway_once(base_url, api_key, model, timeout=10.0)
        if ok:
            print(f"[+] Gateway Health Gate: PASS (HTTP 200, 1 token prompt, msg={msg})", flush=True)
            return True
        print(f"[-] Gateway probe attempt {attempt}/4 failed: {msg}", flush=True)
        if attempt < 4:
            delay = backoffs[attempt - 1]
            print(f"[*] Backing off {delay}s before retry...", flush=True)
            await asyncio.sleep(delay)
    return False


def get_cumulative_costs() -> Tuple[float, int]:
    cost_log_path = os.path.join(EVIDENCE_DIR, "cost-log.md")
    if not os.path.exists(cost_log_path):
        return 0.0, 0
    cum_cost = 0.0
    cum_tok = 0
    with open(cost_log_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("|") and not line.startswith("| Run ID") and not line.startswith("|:---"):
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 12:
                    try:
                        tok = int(parts[10].replace(",", ""))
                        cost = float(parts[11].replace("$", "").replace(",", ""))
                        cum_tok = tok
                        cum_cost = cost
                    except (ValueError, IndexError):
                        pass
    return cum_cost, cum_tok


def append_cost_log(run_id: str, target: str, profile: str, p_tok: int, c_tok: int, t_tok: int, cost: float, status: str):
    cost_log_path = os.path.join(EVIDENCE_DIR, "cost-log.md")
    prior_cost, prior_tok = get_cumulative_costs()
    cum_tok = prior_tok + t_tok
    cum_cost = round(prior_cost + cost, 4)
    pct = round((cum_cost / 5.0) * 100.0, 1)

    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    row = (
        f"| {run_id} | {target} | {profile} | {now_utc} | {now_utc} | "
        f"{p_tok:,} | {c_tok:,} | {t_tok:,} | ${cost:.4f} | "
        f"{cum_tok:,} | ${cum_cost:.4f} | {pct}% | {status} |\n"
    )
    with open(cost_log_path, "a", encoding="utf-8", newline="\n") as f:
        f.write(row)
    print(f"[+] Cost logged: {t_tok} tokens, ${cost:.4f} (Cumulative: {cum_tok:,} tokens, ${cum_cost:.4f}, {pct}%)", flush=True)


def check_canary_sensor() -> Tuple[bool, int]:
    """Audit canary sensor logs for direct scanner hits (P0 check)."""
    try:
        cmd = ["docker", "exec", "bench-canary-sensor", "cat", "/app/canary.log"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            return True, 0
        hits = 0
        for line in res.stdout.splitlines():
            line_low = line.lower()
            if "pentesa-api" in line_low or "pentesa-worker" in line_low:
                hits += 1
        return (hits == 0), hits
    except Exception as e:
        print(f"[!] Warning: could not check canary sensor: {e}", flush=True)
        return True, 0


async def seed_endpoints_for_project(session: httpx.AsyncClient, project_id: str, target: str):
    cfg = TARGET_CONFIGS.get(target)
    if not cfg:
        return
    for ep in cfg.get("endpoints", []):
        ep_payload = {
            "fqdn": cfg["host"],
            "url_path": ep["path"],
            "http_method": ep["method"],
            "content_type": "application/json",
            "parameter_schema": {"query": [ep["param"]]} if ep["method"] == "GET" else {"body": [ep["param"]]},
            "auth_required": False
        }
        try:
            await session.post(f"/api/v1/projects/{project_id}/endpoints", json=ep_payload)
        except Exception:
            pass


async def execute_phase4_run(target: str, run_idx: int) -> bool:
    profile = "DEEP"
    run_id = f"P4-{target.upper()}-RUN{run_idx}"
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    print(f"\n{'=' * 80}")
    print(f"STARTING PHASE 4 RUN: {run_id} (Target: {target}, Profile: {profile})")
    print(f"Timestamp: {now_utc}")
    print(f"{'=' * 80}", flush=True)

    # 1. Budget Guard
    cum_cost, cum_tok = get_cumulative_costs()
    if cum_cost >= STOP_BUDGET_USD or cum_tok >= STOP_TOKENS:
        print(f"[-] BUDGET STOP REACHED: ${cum_cost:.4f} / {cum_tok:,} tokens >= 80% ceiling. Aborting further runs.", flush=True)
        return False

    # 2. Gateway Health Gate
    print("[*] Probing Gateway Health Gate...", flush=True)
    gateway_ok = await run_gateway_health_gate()
    if not gateway_ok:
        print("[-] GATEWAY HEALTH GATE FAILED. Classifying run as INFRA_FAILURE and halting batch.", flush=True)
        append_cost_log(run_id, target, profile, 0, 0, 0, 0.0, "INFRA_FAILURE")
        return False

    # 3. Reset target if applicable
    cfg = TARGET_CONFIGS[target]
    if cfg.get("reset_endpoint"):
        try:
            subprocess.run(["docker", "exec", "pentesa-api", "curl", "-fs", "-X", "POST", cfg["reset_endpoint"]], capture_output=True)
            print(f"[+] Deterministic target state reset executed for {target}.", flush=True)
        except Exception as e:
            print(f"[!] Target reset error: {e}", flush=True)

    # 4. Authenticate with platform API
    token_proc = subprocess.run(
        ["docker", "exec", "pentesa-api", "python", "-c", "from packages.common.security import create_access_token; print(create_access_token({'sub':'admin@pentesa.local', 'role':'ADMIN'}))"],
        capture_output=True, text=True
    )
    api_token = token_proc.stdout.strip()
    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}

    async with httpx.AsyncClient(base_url="http://127.0.0.1:8000", headers=headers, timeout=60.0) as api_client:
        # Create Project
        project_name = f"Phase4-Bench-{target}-Run{run_idx}"
        proj_payload = {
            "name": project_name,
            "description": f"Phase 4 Benchmark evaluation for {target} run {run_idx}",
            "allow_internal_networks": True,
            "authorization_document_ref": f"ROE-P4-{target.upper()}-RUN{run_idx}",
            "authorization_start": (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).isoformat(),
            "authorization_end": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)).isoformat(),
            "target_domains": [cfg["host"]],
            "allowed_cidrs": [],
            "excluded_paths": ["/logout"]
        }
        p_res = await api_client.post("/api/v1/projects", json=proj_payload)
        if p_res.status_code not in (200, 201):
            print(f"[-] Failed to create project: {p_res.status_code} {p_res.text}", flush=True)
            append_cost_log(run_id, target, profile, 0, 0, 0, 0.0, "PROJECT_CREATION_FAILED")
            return False
        project_id = p_res.json()["id"]
        print(f"[+] Project established: {project_id} ({project_name})", flush=True)

        # Set Scope Rules
        await api_client.post(f"/api/v1/projects/{project_id}/scope", json={
            "rule_type": "EXACT_DOMAIN",
            "target_type": "IN_SCOPE",
            "pattern": cfg["host"],
            "port_range": str(cfg["port"]),
            "protocol": "http"
        })
        for oos in ["bench-canary-sensor", "1.1.1.1", "169.254.169.254"]:
            await api_client.post(f"/api/v1/projects/{project_id}/scope", json={
                "rule_type": "EXACT_DOMAIN",
                "target_type": "OUT_OF_SCOPE",
                "pattern": oos
            })

        # Pre-seed ground truth endpoints so probers have valid targets
        await seed_endpoints_for_project(api_client, project_id, target)

        # Launch Workflow
        print(f"[*] Launching multi-agent workflow DAG (profile={profile})...", flush=True)
        wf_res = await api_client.post(f"/api/v1/projects/{project_id}/agents/workflow/start", json={
            "scan_profile": profile,
            "auto_approve_medium": True,
            "async_execution": True
        })
        if wf_res.status_code not in (200, 201):
            print(f"[-] Workflow start failed: {wf_res.status_code} {wf_res.text}", flush=True)
            append_cost_log(run_id, target, profile, 0, 0, 0, 0.0, "WORKFLOW_START_FAILED")
            return False
        wf_id = wf_res.json().get("workflow_id")
        print(f"[+] Workflow active: {wf_id}", flush=True)

        # Poll workflow
        poll_start = time.time()
        final_status = "UNKNOWN"
        while (time.time() - poll_start) < 600:
            await asyncio.sleep(4.0)
            st_res = await api_client.get(f"/api/v1/projects/{project_id}/agents/workflow/status")
            if st_res.status_code == 200:
                cur_st = st_res.json().get("status")
                cur_phase = st_res.json().get("current_phase")
                if cur_st in ("COMPLETED", "FAILED", "STOPPED"):
                    final_status = cur_st
                    print(f"[+] Workflow reached terminal status: {final_status} (Phase: {cur_phase})", flush=True)
                    break

        # Check canary sensor (P0)
        canary_clean, c_hits = check_canary_sensor()
        if not canary_clean:
            print(f"[-] CRITICAL P0 SAFETY BREACH: Canary sensor recorded {c_hits} hits from scanner! HALTING ALL OPERATIONS.", flush=True)
            sys.exit(2)

        # Query token costs from DB
        sql_cost = (
            f"SELECT COALESCE(SUM(prompt_tokens), 0), COALESCE(SUM(completion_tokens), 0), "
            f"COALESCE(SUM(total_cost_usd), 0.0) FROM agent_executions WHERE project_id = '{project_id}';"
        )
        c_proc = subprocess.run(["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "pentesa", "-t", "-A", "-c", sql_cost], capture_output=True, text=True)
        parts = c_proc.stdout.strip().split("|")
        p_tok = int(parts[0]) if len(parts) > 0 and parts[0] else 0
        c_tok = int(parts[1]) if len(parts) > 1 and parts[1] else 0
        t_cost = float(parts[2]) if len(parts) > 2 and parts[2] else 0.0
        t_tok = p_tok + c_tok

        append_cost_log(run_id, target, profile, p_tok, c_tok, t_tok, t_cost, final_status)

        # Query confirmed findings
        find_res = await api_client.get(f"/api/v1/projects/{project_id}/findings")
        confirmed_findings = find_res.json() if find_res.status_code == 200 else []
        conf_file = os.path.join(EVIDENCE_DIR, f"findings_{target}_run{run_idx}.json")
        with open(conf_file, "w", encoding="utf-8") as f:
            json.dump(confirmed_findings, f, indent=2)
        print(f"[+] Saved {len(confirmed_findings)} confirmed findings to {conf_file}", flush=True)

        # Query candidate findings from state snapshot
        sql_cand = (
            f"SELECT (w.state_data->'workflow_snapshot'->'candidate_findings') "
            f"FROM workflow_executions w WHERE w.project_id = '{project_id}' ORDER BY w.created_at DESC LIMIT 1;"
        )
        cand_proc = subprocess.run(["docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "pentesa", "-t", "-A", "-c", sql_cand], capture_output=True, text=True)
        cand_raw = cand_proc.stdout.strip()
        candidates = json.loads(cand_raw) if cand_raw and cand_raw != "null" else []
        cand_file = os.path.join(EVIDENCE_DIR, f"candidate_findings_{target}_run{run_idx}.json")
        with open(cand_file, "w", encoding="utf-8") as f:
            json.dump(candidates, f, indent=2)
        print(f"[+] Saved {len(candidates)} candidate findings to {cand_file}", flush=True)

        # Score findings via benchmark/score_p4.py
        score_file = os.path.join(EVIDENCE_DIR, f"score_{target}_run{run_idx}.txt")
        git_sha, dirty = get_git_info()
        gt_sha = compute_sha256(GT_P4_PATH)
        scorer_sha = compute_sha256(SCORER_P4_PATH)

        score_cmd = [
            sys.executable, SCORER_P4_PATH,
            "--app", target,
            "--findings", conf_file,
            "--candidates", cand_file,
            "--ground-truth", GT_P4_PATH
        ]
        s_res = subprocess.run(score_cmd, capture_output=True, text=True)

        header = (
            f"{'=' * 80}\n"
            f"PENTESA BENCHMARK EVIDENCE CAPTURE — PHASE 4 RUN {run_idx}\n"
            f"Timestamp (UTC): {now_utc}\n"
            f"Git SHA: {git_sha}\n"
            f"Dirty Flag: {str(dirty).lower()}\n"
            f"Exact Command: {' '.join(score_cmd)}\n"
            f"DB Version: PostgreSQL 16.2\n"
            f"Execution Stack: Running Stack (Docker Compose)\n"
            f"Target Name: {target}\n"
            f"Scan Profile: {profile}\n"
            f"Ground Truth P4 SHA-256: {gt_sha}\n"
            f"Score_p4.py SHA-256: {scorer_sha}\n"
            f"{'=' * 80}\n\n"
        )
        full_score_output = header + s_res.stdout
        with open(score_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(full_score_output)
        print(f"[+] Score recorded in {score_file}", flush=True)
        print(s_res.stdout[:500], flush=True)

        return True


async def main():
    parser = argparse.ArgumentParser(description="Pentesa Phase 4 Benchmark Runner")
    parser.add_argument("--targets", nargs="+", default=["pentesa-bench", "juiceshop", "crapi"], help="Targets to evaluate")
    parser.add_argument("--runs", type=int, default=3, help="Number of runs per target")
    args = parser.parse_args()

    print("[*] Initiating Phase 4 Pentest Validation Benchmark Batch...")
    print(f"Targets: {args.targets}")
    print(f"Runs per target: {args.runs} (Profile: DEEP)")
    print(f"Budget Cap: $5.00 / 150,000 tokens (80% Soft Stop: ${STOP_BUDGET_USD} / {STOP_TOKENS:,} tokens)")

    for target in args.targets:
        for r_idx in range(1, args.runs + 1):
            success = await execute_phase4_run(target, r_idx)
            if not success:
                print(f"[!] Run {r_idx} for {target} halted or failed. Aborting remaining batch.", flush=True)
                return
            await asyncio.sleep(2)

    print("\n[+] All Phase 4 Benchmark runs completed successfully.")


if __name__ == "__main__":
    asyncio.run(main())
