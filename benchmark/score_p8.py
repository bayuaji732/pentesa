#!/usr/bin/env python3
"""Deterministic Authoritative Scorer for Phase 8: Reliability, Performance, Concurrency, and Resource Limits.

Frozen prior to Phase 8 test execution (committed and tagged: p8-design-complete).
Reads machine-captured results JSON from docs/audit/evidence/phase8/p8_test_results.json,
validates against benchmark/ground_truth_p8.yaml, computes deterministic metrics across all
10 Phase 8 sub-areas (a-j), and emits a forensic report with SHA-256 hashes in the header.
Status vocabulary follows Phase 10 standards: Verified, Partially Verified, Failed, Not Implemented, Not Tested.
"""

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional

import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_GT_PATH = os.path.join(REPO_ROOT, "benchmark/ground_truth_p8.yaml")
DEFAULT_RESULTS_PATH = os.path.join(REPO_ROOT, "docs/audit/evidence/phase8/p8_test_results.json")


def compute_sha256(filepath: str) -> str:
    if not os.path.exists(filepath):
        return "NOT_FOUND"
    return hashlib.sha256(open(filepath, "rb").read()).hexdigest()


def get_git_info() -> str:
    try:
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT).decode().strip()
        dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=REPO_ROOT).decode().strip()
        return f"{sha} ({'DIRTY' if dirty else 'CLEAN'})"
    except Exception:
        return "UNKNOWN"


def score_phase8(gt_path: str, results_path: str) -> Dict[str, Any]:
    with open(gt_path, "r", encoding="utf-8") as f:
        gt = yaml.safe_load(f)
    with open(results_path, "r", encoding="utf-8") as f:
        res_doc = json.load(f)

    gt_cases = gt.get("test_cases", [])
    raw_results = {r["test_id"]: r for r in res_doc.get("test_results", [])}
    meta = res_doc.get("metadata", {})

    scores = []
    category_summary = {
        "Verified": 0,
        "Partially Verified": 0,
        "Failed": 0,
        "Not Implemented": 0,
        "Not Tested": 0,
    }

    for case in gt_cases:
        cid = case["test_id"]
        sub_area = case.get("sub_area", "")
        title = case["title"]
        req_id = case.get("requirement_id", "")
        expected_status = case.get("expected_status", "Verified")

        res = raw_results.get(cid)
        if not res:
            assigned_status = "Not Tested"
            details = "Result record missing from p8_test_results.json"
            passed = False
        else:
            actual_status = res.get("status", "Failed")
            details = res.get("details", "")
            metrics = res.get("metrics", {})

            # Adjudicate status
            if actual_status == "Not Implemented":
                assigned_status = "Not Implemented"
                passed = (expected_status == "Not Implemented")
            elif actual_status in ("Verified", "PASS"):
                assigned_status = "Verified"
                passed = True
            elif actual_status in ("Partially Verified", "PARTIAL"):
                assigned_status = "Partially Verified"
                passed = (expected_status == "Partially Verified")
            elif actual_status in ("Failed", "FAIL"):
                assigned_status = "Failed"
                passed = False
            else:
                assigned_status = "Not Tested"
                passed = False

        category_summary[assigned_status] = category_summary.get(assigned_status, 0) + 1

        scores.append({
            "test_id": cid,
            "sub_area": sub_area,
            "title": title,
            "requirement_id": req_id,
            "expected_status": expected_status,
            "assigned_status": assigned_status,
            "passed": passed,
            "details": details,
            "metrics": res.get("metrics", {}) if res else {}
        })

    total_cases = len(gt_cases)
    pass_rate = (category_summary["Verified"] / total_cases * 100.0) if total_cases > 0 else 0.0

    return {
        "metadata": meta,
        "summary": {
            "total_test_cases": total_cases,
            "verified_count": category_summary["Verified"],
            "partially_verified_count": category_summary["Partially Verified"],
            "failed_count": category_summary["Failed"],
            "not_implemented_count": category_summary["Not Implemented"],
            "not_tested_count": category_summary["Not Tested"],
            "strict_pass_rate_percent": round(pass_rate, 2),
        },
        "scores": scores
    }


def print_forensic_report(report: Dict[str, Any], gt_path: str, results_path: str, output_path: Optional[str] = None):
    now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    gt_sha = compute_sha256(gt_path)
    res_sha = compute_sha256(results_path)
    git_rev = get_git_info()

    lines = [
        "=" * 80,
        "PENTESA PHASE 8: DETERMINISTIC SCORING AND AUDIT VERIFICATION REPORT",
        "=" * 80,
        f"Generated At (UTC):     {now_utc}",
        f"Git Revision:           {git_rev}",
        f"Ground Truth File:      {os.path.relpath(gt_path, REPO_ROOT)}",
        f"Ground Truth SHA-256:   {gt_sha}",
        f"Test Results File:      {os.path.relpath(results_path, REPO_ROOT)}",
        f"Test Results SHA-256:   {res_sha}",
        "-" * 80,
        "PHASE 8 OVERALL SUMMARY METRICS:",
        f"  Total Test Cases Evaluated:   {report['summary']['total_test_cases']}",
        f"  Verified (Full Pass):         {report['summary']['verified_count']}",
        f"  Partially Verified:           {report['summary']['partially_verified_count']}",
        f"  Failed:                       {report['summary']['failed_count']}",
        f"  Not Implemented:              {report['summary']['not_implemented_count']}",
        f"  Not Tested:                   {report['summary']['not_tested_count']}",
        f"  Strict Pass Rate:             {report['summary']['strict_pass_rate_percent']}%",
        "-" * 80,
        "SUB-AREA BREAKDOWN & TEST CASE ADJUDICATION:",
        f"{'Test ID':<16} {'Req ID':<14} {'Status':<20} {'Title'}",
        "-" * 80,
    ]

    for s in report["scores"]:
        status_display = s["assigned_status"]
        lines.append(f"{s['test_id']:<16} {s['requirement_id']:<14} {status_display:<20} {s['title']}")
        if s.get("metrics"):
            m_str = ", ".join(f"{k}={v}" for k, v in s["metrics"].items())
            lines.append(f"  -> Metrics: {m_str}")
        if s.get("details"):
            lines.append(f"  -> Evidence: {s['details']}")

    lines.extend([
        "-" * 80,
        "END OF FORENSIC SCORING REPORT",
        "=" * 80,
    ])

    report_text = "\n".join(lines)
    print(report_text)

    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_text + "\n")


def main():
    parser = argparse.ArgumentParser(description="Deterministic scorer for Phase 8.")
    parser.add_argument("--gt", default=DEFAULT_GT_PATH, help="Path to ground truth YAML")
    parser.add_argument("--results", default=DEFAULT_RESULTS_PATH, help="Path to results JSON")
    parser.add_argument("--output", default=None, help="Path to write score report")
    args = parser.parse_args()

    if not os.path.exists(args.gt):
        print(f"Error: Ground truth file not found: {args.gt}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(args.results):
        print(f"Error: Results file not found: {args.results}", file=sys.stderr)
        sys.exit(1)

    scored = score_phase8(args.gt, args.results)
    print_forensic_report(scored, args.gt, args.results, args.output)


if __name__ == "__main__":
    main()
