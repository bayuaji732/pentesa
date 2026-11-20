#!/usr/bin/env python3
"""Authoritative Scorer for Phase 6: Platform Security Audit.

Evaluates test execution results against frozen benchmark/ground_truth_p6.yaml.
Calculates pass rates across scope bypass, SSRF prevention, command injection,
container escape surface, credential leakage, authentication bypass, RBAC enforcement,
IDOR isolation, prompt injection, tool safety, evidence/audit tamper resistance,
file handling, dependency vulnerabilities, and network egress boundaries.
"""

import argparse
import datetime
import hashlib
import json
import os
import sys
from typing import Any, Dict, List
import yaml

DEFAULT_GROUND_TRUTH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "ground_truth_p6.yaml")
)
DEFAULT_RESULTS = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../docs/audit/evidence/phase6/p6_test_results.json")
)


def compute_sha256(filepath: str) -> str:
    """Compute sha256 hash of a file."""
    if not os.path.exists(filepath):
        return "NOT_FOUND"
    return hashlib.sha256(open(filepath, "rb").read()).hexdigest()


def score_phase6(ground_truth_path: str, results_path: str) -> Dict[str, Any]:
    """Score Phase 6 test results against ground truth."""
    if not os.path.exists(ground_truth_path):
        raise FileNotFoundError(f"Ground truth not found: {ground_truth_path}")
    if not os.path.exists(results_path):
        raise FileNotFoundError(f"Results file not found: {results_path}")

    with open(ground_truth_path, "r", encoding="utf-8") as f:
        gt_data = yaml.safe_load(f)

    with open(results_path, "r", encoding="utf-8") as f:
        res_data = json.load(f)

    gt_cases = {c["test_id"]: c for c in gt_data.get("test_cases", [])}
    run_results = {r["test_id"]: r for r in res_data.get("test_results", [])}
    metadata = res_data.get("metadata", {})

    total_cases = len(gt_cases)
    passed_cases = 0
    failed_cases = 0
    skipped_cases = 0

    dimension_stats: Dict[str, Dict[str, int]] = {}
    detailed_comparisons: List[Dict[str, Any]] = []

    for test_id, gt_case in gt_cases.items():
        dim = gt_case.get("dimension", "unknown")
        if dim not in dimension_stats:
            dimension_stats[dim] = {"total": 0, "passed": 0, "failed": 0, "skipped": 0}
        dimension_stats[dim]["total"] += 1

        actual_run = run_results.get(test_id)
        if not actual_run:
            verdict = "SKIPPED"
            details = "Test case not present in test results"
            duration = 0.0
        else:
            verdict = actual_run.get("verdict", "FAIL")
            details = actual_run.get("details", actual_run.get("error", "No details"))
            duration = actual_run.get("duration_seconds", 0.0)

        if verdict == "PASS":
            passed_cases += 1
            dimension_stats[dim]["passed"] += 1
        elif verdict == "SKIPPED":
            skipped_cases += 1
            dimension_stats[dim]["skipped"] += 1
        else:
            failed_cases += 1
            dimension_stats[dim]["failed"] += 1

        detailed_comparisons.append({
            "test_id": test_id,
            "dimension": dim,
            "title": gt_case.get("title", ""),
            "target_component": gt_case.get("target_component", ""),
            "expected_outcome": gt_case.get("expected_outcome", "SECURE"),
            "verdict": verdict,
            "duration": duration,
            "details": details,
        })

    pass_rate_pct = round((passed_cases / total_cases * 100), 1) if total_cases > 0 else 0.0

    return {
        "benchmark_metadata": {
            "benchmark_phase": "Phase 6 — Platform Security Audit",
            "ground_truth_sha256": compute_sha256(ground_truth_path),
            "results_sha256": compute_sha256(results_path),
            "scorer_sha256": compute_sha256(os.path.abspath(__file__)),
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "target_environment": "pentesa-sec (docker-compose.sec.yml)",
            "total_tokens": metadata.get("total_tokens", 0),
            "total_cost_usd": metadata.get("total_cost_usd", 0.0),
        },
        "summary_metrics": {
            "total_cases": total_cases,
            "passed_cases": passed_cases,
            "failed_cases": failed_cases,
            "skipped_cases": skipped_cases,
            "overall_pass_rate_pct": pass_rate_pct,
            "canary_sensor_hits": metadata.get("canary_hits", 0),
            "canary_invariant": "PASSED (0 hits)" if metadata.get("canary_hits", 0) == 0 else "FAILED",
        },
        "dimension_breakdown": {
            dim: {
                "total": s["total"],
                "passed": s["passed"],
                "failed": s["failed"],
                "skipped": s["skipped"],
                "pass_rate_pct": round((s["passed"] / s["total"] * 100), 1) if s["total"] > 0 else 0.0,
            }
            for dim, s in dimension_stats.items()
        },
        "detailed_results": detailed_comparisons,
    }


def print_score_report(score_dict: Dict[str, Any]):
    """Print standard formatted score report."""
    meta = score_dict["benchmark_metadata"]
    summary = score_dict["summary_metrics"]
    dim_breakdown = score_dict["dimension_breakdown"]
    detailed = score_dict["detailed_results"]

    print("=" * 80)
    print("PENTESA BENCHMARK SCORING REPORT — PHASE 6: PLATFORM SECURITY AUDIT")
    print(f"Timestamp (UTC): {meta['timestamp_utc']}")
    print(f"Ground Truth P6 SHA-256: {meta['ground_truth_sha256']}")
    print(f"Scorer SHA-256: {meta['scorer_sha256']}")
    print(f"Results SHA-256: {meta['results_sha256']}")
    print(f"Target Environment: {meta['target_environment']}")
    print(f"Live Tokens: {meta['total_tokens']:,} | Live Cost: ${meta['total_cost_usd']:.4f} USD")
    print(f"Canary Honeypot Invariant: {summary['canary_invariant']}")
    print("=" * 80)
    print()
    print("## 1. Summary Metrics")
    print(f"- Total Test Cases: {summary['total_cases']}")
    print(f"- Passed: {summary['passed_cases']}")
    print(f"- Failed: {summary['failed_cases']}")
    print(f"- Skipped: {summary['skipped_cases']}")
    print(f"- Overall Pass Rate: {summary['overall_pass_rate_pct']}%")
    print()
    print("## 2. Dimension Breakdown")
    print(f"{'Dimension':<32} {'Total':<8} {'Passed':<8} {'Failed':<8} {'Pass Rate':<10}")
    print("-" * 70)
    for dim, s in dim_breakdown.items():
        print(f"{dim:<32} {s['total']:<8} {s['passed']:<8} {s['failed']:<8} {s['pass_rate_pct']}%")
    print()
    print("## 3. Case-by-Case Security Evaluation")
    for r in detailed:
        status_tag = f"[{r['verdict']}]"
        print(f"{status_tag:<8} {r['test_id']:<18} ({r['dimension']:<28}) : {r['details']} ({r['duration']:.3f}s)")
    print()
    print("=" * 80)
    print(json.dumps(score_dict, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Score Phase 6 Platform Security Benchmark Results.")
    parser.add_argument("--ground-truth", default=DEFAULT_GROUND_TRUTH, help="Path to ground_truth_p6.yaml")
    parser.add_argument("--results", default=DEFAULT_RESULTS, help="Path to p6_test_results.json")
    parser.add_argument("--json", action="store_true", help="Output raw JSON only")

    args = parser.parse_args()
    try:
        score_dict = score_phase6(args.ground_truth, args.results)
        if args.json:
            print(json.dumps(score_dict, indent=2))
        else:
            print_score_report(score_dict)
    except Exception as e:
        print(f"Error during scoring: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
