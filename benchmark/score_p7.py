#!/usr/bin/env python3
"""Deterministic Authoritative Scorer for Phase 7: Findings and Evidence Quality.

Frozen prior to Phase 7 test execution (tagged: p7-design-complete).
Reads machine-captured results JSON from docs/audit/evidence/phase7/p7_test_results.json,
validates against benchmark/ground_truth_p7.yaml, computes deterministic metrics across all
8 Phase 7 dimensions (a-h), and emits a forensic report with SHA-256 hashes in the header.
Subjective judgements are advisory only and are never used as a metric.
"""

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys
from typing import Any, Dict, List

import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_GT_PATH = os.path.join(REPO_ROOT, "benchmark/ground_truth_p7.yaml")
DEFAULT_RESULTS_PATH = os.path.join(REPO_ROOT, "docs/audit/evidence/phase7/p7_test_results.json")


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


def score_phase7(gt_path: str, results_path: str) -> Dict[str, Any]:
    with open(gt_path, "r", encoding="utf-8") as f:
        gt = yaml.safe_load(f)
    with open(results_path, "r", encoding="utf-8") as f:
        res_doc = json.load(f)

    gt_cases = gt.get("test_cases", [])
    raw_results = {r["test_id"]: r for r in res_doc.get("test_results", [])}
    meta = res_doc.get("metadata", {})

    scored_cases: List[Dict[str, Any]] = []
    dim_stats: Dict[str, Dict[str, int]] = {}

    passed = 0
    partial = 0
    failed = 0
    not_impl = 0
    not_tested = 0

    for tc in gt_cases:
        tid = tc["test_id"]
        dim = tc["dimension"]
        if dim not in dim_stats:
            dim_stats[dim] = {"total": 0, "passed": 0, "partial": 0, "failed": 0, "not_implemented": 0, "not_tested": 0}
        dim_stats[dim]["total"] += 1

        actual = raw_results.get(tid)
        if not actual:
            verdict = "NOT_TESTED"
            p10_status = "Not Tested"
            details = "Test case not present in results file."
            metrics = {}
            duration = 0.0
            not_tested += 1
            dim_stats[dim]["not_tested"] += 1
        else:
            verdict = str(actual.get("verdict", "FAIL")).upper()
            p10_status = actual.get("phase10_status")
            details = actual.get("details", "")
            metrics = actual.get("metrics", {})
            duration = actual.get("duration_seconds", 0.0)

            if verdict == "PASS":
                passed += 1
                dim_stats[dim]["passed"] += 1
                p10_status = p10_status or ("Verified" if tc["execution_class"] == "WIRE" else "Partially Verified")
            elif verdict == "PARTIAL":
                partial += 1
                dim_stats[dim]["partial"] += 1
                p10_status = p10_status or "Partially Verified"
            elif verdict == "NOT_IMPLEMENTED":
                not_impl += 1
                dim_stats[dim]["not_implemented"] += 1
                p10_status = "Not Implemented"
            elif verdict == "NOT_TESTED":
                not_tested += 1
                dim_stats[dim]["not_tested"] += 1
                p10_status = "Not Tested"
            else:
                verdict = "FAIL"
                failed += 1
                dim_stats[dim]["failed"] += 1
                p10_status = p10_status or "Failed"

        scored_cases.append({
            "test_id": tid,
            "dimension": dim,
            "spec_ids": tc.get("spec_ids", []),
            "title": tc["title"],
            "execution_class": tc["execution_class"],
            "verdict": verdict,
            "phase10_status": p10_status,
            "duration_seconds": duration,
            "details": details,
            "metrics": metrics,
        })

    total = len(gt_cases)
    strict_pass_rate = round((passed / total) * 100.0, 1) if total else 0.0

    # Extract key objective Phase 7 metrics directly from scored cases
    by_id = {c["test_id"]: c["metrics"] for c in scored_cases}
    key_metrics = {
        "field_completeness_strict_mean_pct": by_id.get("P7-TC-COMP-01", {}).get("strict_mean_completeness_pct"),
        "field_completeness_joined_api_mean_pct": by_id.get("P7-TC-COMP-01", {}).get("joined_api_mean_completeness_pct"),
        "findings_evaluated_api": by_id.get("P7-TC-COMP-01", {}).get("total_findings"),
        "evidence_sha256_match_rate_pct": by_id.get("P7-TC-INT-01", {}).get("match_rate_pct"),
        "tamper_copy_detection_rate_pct": by_id.get("P7-TC-INT-02", {}).get("detection_rate_pct"),
        "prod_secret_leak_count": by_id.get("P7-TC-REDACT-01", {}).get("leaks_found"),
        "canary_secret_redaction_rate_pct": by_id.get("P7-TC-REDACT-02", {}).get("redaction_rate_pct"),
        "reproduction_replay_success_rate_pct": by_id.get("P7-TC-REPRO-01", {}).get("replay_success_rate_pct"),
        "reproduction_scope_violations": by_id.get("P7-TC-REPRO-01", {}).get("scope_violations"),
        "accuracy_tp_count": by_id.get("P7-TC-ACC-01", {}).get("tp_count"),
        "accuracy_fp_count": by_id.get("P7-TC-ACC-01", {}).get("fp_count"),
        "accuracy_cvss_band_consistency_pct": by_id.get("P7-TC-ACC-01", {}).get("cvss_band_consistency_pct"),
        "accuracy_wstg_cwe_valid_pct": by_id.get("P7-TC-ACC-01", {}).get("wstg_cwe_valid_pct"),
        "dedup_exact_cluster_accuracy_pct": by_id.get("P7-TC-DEDUP-01", {}).get("exact_cluster_accuracy_pct"),
        "report_factual_fidelity_pct": by_id.get("P7-TC-REP-01", {}).get("factual_fidelity_pct"),
        "report_cross_run_consistency_pct": by_id.get("P7-TC-REP-01", {}).get("cross_run_consistency_pct"),
        "empty_report_claims_secure": by_id.get("P7-TC-REP-02", {}).get("empty_report_claims_secure"),
        "candidate_confirmed_separated": by_id.get("P7-TC-REP-02", {}).get("candidate_confirmed_separated"),
        "llm_groundedness_rate_pct": by_id.get("P7-TC-REP-03", {}).get("groundedness_rate_pct"),
        "llm_fabricated_cves_or_urls": by_id.get("P7-TC-REP-03", {}).get("fabricated_cves_or_urls"),
        "lifecycle_supported_checks_pass_pct": by_id.get("P7-TC-LIFE-01", {}).get("supported_checks_pass_pct"),
    }

    return {
        "benchmark_metadata": {
            "benchmark_phase": gt["metadata"]["benchmark_phase"],
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "git_commit": get_git_info(),
            "ground_truth_p7_sha256": compute_sha256(gt_path),
            "scorer_p7_sha256": compute_sha256(os.path.abspath(__file__)),
            "results_p7_sha256": compute_sha256(results_path),
            "runner_p7_sha256": meta.get("runner_sha256", "UNKNOWN"),
            "target_environment": meta.get("target_environment", gt["metadata"]["target_environment"]),
            "total_tokens": meta.get("total_tokens", 0),
            "total_cost_usd": meta.get("total_cost_usd", 0.0),
            "canary_hits": meta.get("canary_hits", 0),
        },
        "summary_metrics": {
            "total_cases": total,
            "passed_cases": passed,
            "partial_cases": partial,
            "failed_cases": failed,
            "not_implemented_cases": not_impl,
            "not_tested_cases": not_tested,
            "strict_pass_rate_pct": strict_pass_rate,
        },
        "key_objective_metrics": key_metrics,
        "dimension_breakdown": dim_stats,
        "detailed_results": scored_cases,
    }


def print_report(report: Dict[str, Any]) -> None:
    bm = report["benchmark_metadata"]
    sm = report["summary_metrics"]
    km = report["key_objective_metrics"]
    print("=" * 88)
    print("PENTESA BENCHMARK SCORING REPORT — PHASE 7: FINDINGS AND EVIDENCE QUALITY")
    print(f"Timestamp (UTC):           {bm['timestamp_utc']}")
    print(f"Git Commit:                {bm['git_commit']}")
    print(f"Ground Truth P7 SHA-256:   {bm['ground_truth_p7_sha256']}")
    print(f"Scorer P7 SHA-256:         {bm['scorer_p7_sha256']}")
    print(f"Runner P7 SHA-256:         {bm['runner_p7_sha256']}")
    print(f"Results P7 SHA-256:        {bm['results_p7_sha256']}")
    print(f"Target Environment:        {bm['target_environment']}")
    print(f"Live LLM Spend:            {bm['total_tokens']} tokens | ${bm['total_cost_usd']:.4f} USD (Cap: $2.00 / 60,000 tokens)")
    canary_hits = bm["canary_hits"]
    canary_str = "PASSED (0 hits)" if canary_hits == 0 else f"FAILED ({canary_hits} hits)"
    print(f"Canary Honeypot Invariant: {canary_str}")
    print("=" * 88)
    print("\n## 1. Summary Metrics")
    print(f"- Total Test Cases:        {sm['total_cases']}")
    print(f"- Passed:                  {sm['passed_cases']}")
    print(f"- Partially Verified:      {sm['partial_cases']}")
    print(f"- Failed:                  {sm['failed_cases']}")
    print(f"- Not Implemented:         {sm['not_implemented_cases']}")
    print(f"- Not Tested:              {sm['not_tested_cases']}")
    print(f"- Strict Pass Rate:        {sm['strict_pass_rate_pct']}%")

    print("\n## 2. Key Objective Phase 7 Metrics")
    for k, v in km.items():
        print(f"  - {k:<44}: {v}")

    print("\n## 3. Dimension Breakdown")
    print(f"{'Dimension':<24} {'Total':<6} {'Pass':<6} {'Part':<6} {'Fail':<6} {'NotImpl':<8} {'NotTest':<8}")
    print("-" * 70)
    for dim, st in report["dimension_breakdown"].items():
        print(
            f"{dim:<24} {st['total']:<6} {st['passed']:<6} {st['partial']:<6} "
            f"{st['failed']:<6} {st['not_implemented']:<8} {st['not_tested']:<8}"
        )

    print("\n## 4. Case-by-Case Evaluation")
    for c in report["detailed_results"]:
        print(
            f"[{c['verdict']:<7}] {c['test_id']:<16} ({c['execution_class']:<10} | {c['dimension']:<18} | {c['phase10_status']:<18}) : "
            f"{c['details']} ({c['duration_seconds']:.3f}s)"
        )
    print("=" * 88)
    print(json.dumps(report, indent=2))


def main() -> int:
    parser = argparse.ArgumentParser(description="Deterministic Phase 7 Findings & Evidence Quality Scorer")
    parser.add_argument("--ground-truth", default=DEFAULT_GT_PATH)
    parser.add_argument("--results", default=DEFAULT_RESULTS_PATH)
    args = parser.parse_args()

    report = score_phase7(args.ground_truth, args.results)
    print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
