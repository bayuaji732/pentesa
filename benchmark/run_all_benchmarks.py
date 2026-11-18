#!/usr/bin/env python3
"""Comprehensive Benchmark Batch Runner with Gateway Health Guard and Candidate Scoring.

Orchestrates remaining Phase 3 benchmark scans with resilient HTTP polling:
- crapi run 3
- webgoat runs 1, 2, 3
"""

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
import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from benchmark.run_benchmark import BenchmarkDriver, BENCH_TARGETS, compute_file_sha256, get_git_info, generate_evidence_header

MANUAL_STOP_BUDGET_USD = 8.0
MANUAL_STOP_TOKENS = 240000


class ResilientBenchmarkDriver(BenchmarkDriver):
    async def execute_scan(self, target: str, profile: str = "DEEP", run_index: int = 1) -> bool:
        for attempt in range(1, 4):
            try:
                return await super().execute_scan(target=target, profile=profile, run_index=run_index)
            except (httpx.RemoteProtocolError, httpx.ConnectError, httpx.ReadTimeout) as e:
                print(f"\n[!] Warning: Transient HTTP polling error ({type(e).__name__}: {e}) on attempt {attempt}/3. Re-polling in 5s...", flush=True)
                await asyncio.sleep(5)
        return False


def check_gateway_gate() -> bool:
    """Execute Step 1 health gate check. Fails closed on gateway errors."""
    print("\n[*] Invoking Pre-Run Gateway Health Gate...", flush=True)
    res = subprocess.run([sys.executable, "benchmark/check_gateway_health.py"], capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[-] GATEWAY GATE FAILED:\n{res.stderr or res.stdout}", flush=True)
        return False
    print("[+] Gateway Health Gate: PASS (HTTP 200 OK)", flush=True)
    return True


def check_budget_limits(evidence_dir: str = "docs/audit/evidence/phase3") -> Tuple[bool, float, int]:
    cost_log_path = os.path.join(evidence_dir, "cost-log.md")
    if not os.path.exists(cost_log_path):
        return True, 0.0, 0
    total_cost = 0.0
    total_tokens = 0
    with open(cost_log_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("|") and not line.startswith("| Run ID") and not line.startswith("|---"):
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 12:
                    try:
                        total_tokens = int(parts[10].replace(",", ""))
                        total_cost = float(parts[11].replace("$", "").replace(",", ""))
                    except ValueError:
                        pass
    if total_cost >= MANUAL_STOP_BUDGET_USD or total_tokens >= MANUAL_STOP_TOKENS:
        return False, total_cost, total_tokens
    return True, total_cost, total_tokens


def extract_and_score_candidates(project_name: str, target: str, run_idx: int, evidence_dir: str):
    """Extract candidate findings from DB and score via benchmark/score_candidates.py."""
    print(f"[*] Extracting candidate findings for project '{project_name}'...", flush=True)
    sql_cmd = [
        "docker", "exec", "pentesa-db", "psql", "-U", "pentesa_user", "-d", "pentesa",
        "-t", "-A", "-c",
        f"SELECT (w.state_data->'workflow_snapshot'->'candidate_findings') FROM workflow_executions w JOIN projects p ON w.project_id = p.id WHERE p.name = '{project_name}' ORDER BY w.created_at DESC LIMIT 1;"
    ]
    res = subprocess.run(sql_cmd, capture_output=True, text=True)
    cands_raw = res.stdout.strip()
    if not cands_raw or cands_raw == "null":
        print(f"[!] No candidate findings found in state for {project_name}.")
        cands = []
    else:
        try:
            cands = json.loads(cands_raw)
        except Exception:
            cands = []

    cand_file = os.path.join(evidence_dir, f"candidate_findings_{target}_run{run_idx}.json")
    with open(cand_file, "w", encoding="utf-8") as f:
        json.dump(cands, f, indent=2)
    print(f"[+] Saved {len(cands)} candidate findings to {cand_file}", flush=True)

    # Score candidates
    cand_score_file = os.path.join(evidence_dir, f"score_candidates_{target}_run{run_idx}.txt")
    score_cmd = [
        sys.executable, "benchmark/score_candidates.py",
        "--candidates", cand_file,
        "--output", cand_score_file
    ]
    subprocess.run(score_cmd, capture_output=True, text=True)
    print(f"[+] Supplementary candidate score written to {cand_score_file}", flush=True)


async def execute_batch():
    evidence_dir = "docs/audit/evidence/phase3"
    driver = ResilientBenchmarkDriver(api_base_url="http://localhost:8000", evidence_dir=evidence_dir)

    # Remaining 4 runs to complete
    runs_to_execute = [
        {"target": "crapi", "profile": "DEEP", "run_index": 3, "seeded": False, "target_key": "crapi"},
        {"target": "webgoat", "profile": "DEEP", "run_index": 1, "seeded": False, "target_key": "webgoat"},
        {"target": "webgoat", "profile": "DEEP", "run_index": 2, "seeded": False, "target_key": "webgoat"},
        {"target": "webgoat", "profile": "DEEP", "run_index": 3, "seeded": False, "target_key": "webgoat"},
    ]

    total_runs = len(runs_to_execute)
    print(f"\n================================================================================")
    print(f"RESUMING BENCHMARK BATCH ({total_runs} RUNS REMAINING)")
    print(f"================================================================================", flush=True)

    for idx, r in enumerate(runs_to_execute, 1):
        target = r["target"]
        target_key = r["target_key"]
        profile = r["profile"]
        run_index = r["run_index"]
        run_id = f"RUN-{target.upper()}-{profile}-{run_index:02d}"

        # 1. Budget Gate
        ok_budget, cum_cost, cum_tokens = check_budget_limits(evidence_dir)
        if not ok_budget:
            print(f"[-] CRITICAL STOP: Budget ceiling exceeded! Cost=${cum_cost:.4f}, Tokens={cum_tokens:,}", flush=True)
            break

        # 2. Step 1 Gateway Health Gate
        if not check_gateway_gate():
            print(f"[-] GATEWAY HEALTH GATE FAILED FOR {run_id}. Halting batch to preserve budget.", flush=True)
            driver.append_cost_log(
                run_id=run_id,
                target=target,
                profile=profile,
                start_utc=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                end_utc=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                prompt_tokens=0,
                completion_tokens=0,
                total_tokens=0,
                cost_usd=0.0,
                cumulative_tokens=cum_tokens,
                cumulative_cost=cum_cost,
                status="INFRA_FAILURE (Gateway Outage)"
            )
            sys.exit(1)

        print(f"\n>>> [{idx}/{total_runs}] Executing {run_id} (Target={target}) <<<", flush=True)

        project_name = f"Phase3-Bench-{target}-Run{run_index}"
        success = await driver.execute_scan(target=target, profile=profile, run_index=run_index)
        if not success:
            print(f"[-] Execution failed for {run_id}", flush=True)

        # Extract and score candidate findings (Step 4a)
        extract_and_score_candidates(project_name, target, run_index, evidence_dir)

    print("\n=== BENCHMARK BATCH RUNNER FINISHED ===", flush=True)


if __name__ == "__main__":
    asyncio.run(execute_batch())
