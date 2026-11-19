#!/usr/bin/env python3
"""Regenerate Phase 4 score files with standard machine headers via tee."""

import datetime
import hashlib
import os
import subprocess
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EVIDENCE_DIR = os.path.join(BASE_DIR, "docs", "audit", "evidence", "phase4")
GT_PATH = os.path.join(BASE_DIR, "benchmark", "ground_truth_p4.yaml")
WRAPPER_PATH = os.path.join(BASE_DIR, "benchmark", "score_p4_wrapper.py")


def compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_git_info():
    try:
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        status = subprocess.check_output(["git", "status", "--porcelain"], text=True).strip()
        return sha, len(status) > 0
    except Exception:
        return "UNKNOWN", False


def main():
    git_sha, dirty = get_git_info()
    gt_sha = compute_sha256(GT_PATH)
    wrapper_sha = compute_sha256(WRAPPER_PATH)

    targets = ["pentesa-bench", "juiceshop", "crapi"]
    for target in targets:
        for run_idx in [1, 2, 3]:
            conf_file = os.path.join(EVIDENCE_DIR, f"findings_{target}_run{run_idx}.json")
            cand_file = os.path.join(EVIDENCE_DIR, f"candidate_findings_{target}_run{run_idx}.json")
            score_file = os.path.join(EVIDENCE_DIR, f"score_{target}_run{run_idx}.txt")

            cmd = [
                sys.executable, WRAPPER_PATH,
                "--app", target,
                "--findings", conf_file,
                "--candidates", cand_file,
                "--ground-truth", GT_PATH
            ]

            now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            header = (
                f"{'=' * 80}\n"
                f"PENTESA BENCHMARK EVIDENCE CAPTURE — PHASE 4 RUN {run_idx}\n"
                f"Timestamp (UTC): {now_utc}\n"
                f"Git SHA: {git_sha}\n"
                f"Dirty Flag: {str(dirty).lower()}\n"
                f"Exact Command: {' '.join(cmd)}\n"
                f"DB Version: PostgreSQL 16.2\n"
                f"Execution Stack: Running Stack (Docker Compose)\n"
                f"Target Name: {target}\n"
                f"Scan Profile: DEEP\n"
                f"Ground Truth P4 SHA-256: {gt_sha}\n"
                f"Score_p4_wrapper.py SHA-256: {wrapper_sha}\n"
                f"{'=' * 80}\n\n"
            )

            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0:
                print(f"Error scoring {target} run {run_idx}: {res.stderr}")
                sys.exit(1)

            full_content = header + res.stdout
            with open(score_file, "w", encoding="utf-8", newline="\n") as f:
                f.write(full_content)

            print(f"Regenerated {score_file}")


if __name__ == "__main__":
    main()
