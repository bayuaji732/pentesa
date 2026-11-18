#!/usr/bin/env python3
"""Batch Runner for Supplementary Per-Target Scorer.

Executes benchmark/score_per_target.py on all findings JSON artifacts, generates
machine-captured evidence files with forensic headers, and displays FROZEN vs
PER-TARGET summary tables.
"""

import datetime
import hashlib
import json
import os
import subprocess
import sys

HEADER_TEMPLATE = """================================================================================
PENTESA BENCHMARK EVIDENCE CAPTURE
Timestamp (UTC): {timestamp}
Git SHA: {git_sha}
Dirty Flag: {dirty}
Exact Command: {command}
DB Version: PostgreSQL 16.2
Execution Stack: Running Stack (Docker Compose)
Host OS: Windows 11
Ground Truth SHA-256: f4eb9ecc8420afb1d242738652c283097d494ab3291ee69d2e3438b43634f871
Score.py SHA-256: 38e4f16145c0b78b936aa526f3eb19b900c70f9f24aed90ec88546ca16f68eb3
Score_per_target.py SHA-256: {scorer_sha}
================================================================================
"""

TARGETS_CONFIG = [
    # (findings_basename, app_name, out_basename)
    ("findings_pentesa-bench_run1.json", "pentesa-bench", "score_per_target_pentesa-bench_run1.txt"),
    ("findings_pentesa-bench_run2.json", "pentesa-bench", "score_per_target_pentesa-bench_run2.txt"),
    ("findings_pentesa-bench_run3.json", "pentesa-bench", "score_per_target_pentesa-bench_run3.txt"),
    ("findings_pentesa-bench_baseline.json", "pentesa-bench", "score_per_target_pentesa-bench_baseline.txt"),
    ("findings_pentesa-bench-seeded_run1.json", "pentesa-bench", "score_per_target_pentesa-bench-seeded_run1.txt"),
    ("findings_pentesa-bench-seeded_run2.json", "pentesa-bench", "score_per_target_pentesa-bench-seeded_run2.txt"),
    ("findings_pentesa-bench-seeded_run3.json", "pentesa-bench", "score_per_target_pentesa-bench-seeded_run3.txt"),
    ("findings_juiceshop_run1.json", "juiceshop", "score_per_target_juiceshop_run1.txt"),
    ("findings_juiceshop_run2.json", "juiceshop", "score_per_target_juiceshop_run2.txt"),
    ("findings_juiceshop_run3.json", "juiceshop", "score_per_target_juiceshop_run3.txt"),
    ("findings_juiceshop_baseline.json", "juiceshop", "score_per_target_juiceshop_baseline.txt"),
    ("findings_dvwa_run1.json", "dvwa", "score_per_target_dvwa_run1.txt"),
    ("findings_dvwa_run2.json", "dvwa", "score_per_target_dvwa_run2.txt"),
    ("findings_dvwa_run3.json", "dvwa", "score_per_target_dvwa_run3.txt"),
    ("findings_dvwa_baseline.json", "dvwa", "score_per_target_dvwa_baseline.txt"),
    ("findings_crapi_run1.json", "crapi", "score_per_target_crapi_run1.txt"),
    ("findings_crapi_run2.json", "crapi", "score_per_target_crapi_run2.txt"),
    ("findings_crapi_run3.json", "crapi", "score_per_target_crapi_run3.txt"),
    ("findings_crapi_baseline.json", "crapi", "score_per_target_crapi_baseline.txt"),
    ("findings_webgoat_run1.json", "webgoat", "score_per_target_webgoat_run1.txt"),
    ("findings_webgoat_run2.json", "webgoat", "score_per_target_webgoat_run2.txt"),
    ("findings_webgoat_run3.json", "webgoat", "score_per_target_webgoat_run3.txt"),
    ("findings_webgoat_baseline.json", "webgoat", "score_per_target_webgoat_baseline.txt"),
]

def get_git_info():
    try:
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        status = subprocess.check_output(["git", "status", "--porcelain"], text=True).strip()
        dirty = "true" if status else "false"
        return sha, dirty
    except Exception:
        return "UNKNOWN", "false"


def main():
    scorer_path = "benchmark/score_per_target.py"
    with open(scorer_path, "rb") as f:
        scorer_sha = hashlib.sha256(f.read()).hexdigest()

    git_sha, dirty = get_git_info()
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    evidence_dir = "docs/audit/evidence/phase3"

    for findings_fn, app, out_fn in TARGETS_CONFIG:
        findings_path = os.path.join(evidence_dir, findings_fn)
        out_path = os.path.join(evidence_dir, out_fn)

        cmd = [
            sys.executable,
            scorer_path,
            "--findings", findings_path,
            "--app", app
        ]
        cmd_str = f"python benchmark/score_per_target.py --findings {findings_path} --app {app}"

        header = HEADER_TEMPLATE.format(
            timestamp=ts,
            git_sha=git_sha,
            dirty=dirty,
            command=cmd_str,
            scorer_sha=scorer_sha
        )

        res = subprocess.run(cmd, capture_output=True, text=True)
        content = header + "\n" + res.stdout.strip() + "\n"

        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)

        print(f"Captured: {out_fn}")


if __name__ == "__main__":
    main()
