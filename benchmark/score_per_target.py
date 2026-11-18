#!/usr/bin/env python3
"""Supplementary Per-Target Scorer for Pentesa Pentest Benchmark.

DISCLAIMER:
This script provides SUPPLEMENTARY per-target evaluation metrics by filtering the
frozen ground truth by target application ('app' attribute in ground_truth.yaml).
The primary authoritative benchmark metrics remain frozen in benchmark/score.py.

SHA-256 of frozen ground_truth.yaml: f4eb9ecc8420afb1d242738652c283097d494ab3291ee69d2e3438b43634f871
"""

import argparse
import glob
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import yaml

# Ensure workspace root is in PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from benchmark.score import (
    normalize_endpoint,
    normalize_method,
    normalize_parameter,
    normalize_wstg_id,
    extract_cwe_id,
    extract_wstg_category,
    apply_category_equivalence,
    finding_matches_ground_truth,
    is_suppressed_finding,
    evaluate_evidence_completeness,
)


def adapt_finding_schema(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Adapt API serialized finding to include endpoint/method/parameter from evidence.
    
    Addresses defect P1-FIND-02 (API FindingResponse omits root endpoint/method strings).
    """
    f = dict(finding)
    
    # 1. Parameter normalization (handle 'affected_parameter' singular from DB model)
    if not f.get("parameter"):
        if f.get("affected_parameter"):
            f["parameter"] = f["affected_parameter"]
        elif f.get("affected_parameters"):
            f["parameter"] = f["affected_parameters"]

    # 2. Endpoint and method extraction from raw_request or matched_at if root is missing
    if not f.get("endpoint") or not f.get("method"):
        raw_req = ""
        if f.get("evidence") and isinstance(f["evidence"], list) and len(f["evidence"]) > 0:
            raw_req = f["evidence"][0].get("raw_request") or ""
        elif f.get("raw_request"):
            raw_req = f.get("raw_request") or ""

        if raw_req:
            match = re.search(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s?]+)", raw_req.strip())
            if match:
                if not f.get("method"):
                    f["method"] = match.group(1).upper()
                if not f.get("endpoint"):
                    f["endpoint"] = match.group(2)

        if not f.get("endpoint") and f.get("matched_at"):
            parsed = urlparse(f["matched_at"])
            f["endpoint"] = parsed.path or "/"

        if not f.get("endpoint") and f.get("target_url"):
            parsed = urlparse(f["target_url"])
            f["endpoint"] = parsed.path or "/"

    return f


def score_target(
    app: str,
    findings: List[Dict[str, Any]],
    ground_truth_path: str = "benchmark/ground_truth.yaml",
    adapt_schema: bool = False,
    execution_telemetry: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Score findings specifically against the ground truth cases for a single target application."""
    with open(ground_truth_path, "r", encoding="utf-8") as f:
        gt_data = yaml.safe_load(f)

    # Filter ground truth strictly for this target application
    app_gt_cases = [c for c in gt_data.get("cases", []) if c.get("app") == app]
    vulnerable_cases = [c for c in app_gt_cases if c.get("vulnerable") is True]
    secure_cases = [c for c in app_gt_cases if c.get("vulnerable") is False]

    # Optionally adapt finding schema to compensate for P1-FIND-02
    eval_findings = [adapt_finding_schema(f) for f in findings] if adapt_schema else findings

    matched_gt_ids: Set[str] = set()
    matched_finding_ids: Set[str] = set()

    tp_cases: List[Dict[str, Any]] = []
    secure_fp_cases: List[Dict[str, Any]] = []
    unlisted_cases: List[Dict[str, Any]] = []
    fn_cases: List[Dict[str, Any]] = []

    # 1. Match findings against vulnerable cases for this target
    for gt in vulnerable_cases:
        matched = False
        for idx, finding in enumerate(eval_findings):
            f_id = str(finding.get("id") or f"finding_{idx}")
            if f_id in matched_finding_ids:
                continue
            if is_suppressed_finding(finding):
                continue
            if finding_matches_ground_truth(finding, gt):
                matched = True
                matched_gt_ids.add(gt["id"])
                matched_finding_ids.add(f_id)
                tp_cases.append({
                    "gt_id": gt["id"],
                    "app": gt.get("app", ""),
                    "category": gt["category"],
                    "endpoint": gt["endpoint"],
                    "finding_id": f_id,
                    "finding_title": finding.get("title", ""),
                    "severity": finding.get("severity", "")
                })
                break
        if not matched:
            fn_cases.append({
                "gt_id": gt["id"],
                "app": gt.get("app", ""),
                "category": gt["category"],
                "endpoint": gt["endpoint"],
                "expected_severity": gt.get("expected_severity", ""),
                "description": gt.get("known_vulnerability_condition", "")
            })

    # 2. Check for False Positives on Secure Cases for this target
    for gt in secure_cases:
        for idx, finding in enumerate(eval_findings):
            f_id = str(finding.get("id") or f"finding_{idx}")
            if is_suppressed_finding(finding):
                continue
            if finding_matches_ground_truth(finding, gt):
                secure_fp_cases.append({
                    "gt_id": gt["id"],
                    "app": gt.get("app", ""),
                    "category": gt["category"],
                    "endpoint": gt["endpoint"],
                    "finding_id": f_id,
                    "finding_title": finding.get("title", "")
                })
                break

    # 3. Identify UNLISTED findings (findings matching no case in target GT)
    for idx, finding in enumerate(eval_findings):
        f_id = str(finding.get("id") or f"finding_{idx}")
        if is_suppressed_finding(finding):
            continue
        if f_id not in matched_finding_ids:
            unlisted_cases.append({
                "finding_id": f_id,
                "title": finding.get("title", ""),
                "endpoint": finding.get("endpoint", ""),
                "wstg_id": finding.get("wstg_id", ""),
                "cwe_id": finding.get("cwe_id", "")
            })

    # Counts
    tp = len(tp_cases)
    fn = len(fn_cases)
    secure_fp_count = len(secure_fp_cases)
    unlisted_count = len(unlisted_cases)

    total_vuln = len(vulnerable_cases)
    total_secure = len(secure_cases)

    strict_fp_total = secure_fp_count + unlisted_count
    strict_precision = round(tp / (tp + strict_fp_total), 4) if (tp + strict_fp_total) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1_score = round(2 * (strict_precision * recall) / (strict_precision + recall), 4) if (strict_precision + recall) > 0 else 0.0
    fpr_secure = round(secure_fp_count / total_secure, 4) if total_secure > 0 else 0.0

    # WSTG Metrics for this target
    total_catalog_wstg = 106
    distinct_target_wstgs = set(c.get("wstg_id") for c in app_gt_cases if c.get("wstg_id"))
    applicable_wstg = len(distinct_target_wstgs) if distinct_target_wstgs else 1

    telem = execution_telemetry or {}
    executed_wstg = telem.get("executed_wstg_tests", tp + fn)
    wstg_target_coverage_pct = round((executed_wstg / applicable_wstg) * 100.0, 2) if applicable_wstg > 0 else 0.0
    wstg_catalog_coverage_pct = round((executed_wstg / total_catalog_wstg) * 100.0, 2)

    return {
        "target_app": app,
        "scoring_mode": "SCHEMA_ADAPTED (P1-FIND-02 compensated)" if adapt_schema else "STRICT_RAW (as serialized by API)",
        "ground_truth_summary": {
            "target_total_cases": len(app_gt_cases),
            "target_vulnerable_cases": total_vuln,
            "target_secure_cases": total_secure,
            "distinct_wstg_categories": applicable_wstg
        },
        "detection_metrics": {
            "true_positives": tp,
            "false_positives_strict": strict_fp_total,
            "false_negatives": fn,
            "secure_cases_false_positives": secure_fp_count,
            "unlisted_findings_count": unlisted_count,
            "precision": strict_precision,
            "recall": recall,
            "f1_score": f1_score,
            "false_positive_rate_secure": fpr_secure
        },
        "wstg_metrics": {
            "executed_wstg_tests": executed_wstg,
            "applicable_target_wstg_tests": applicable_wstg,
            "total_catalog_tests": total_catalog_wstg,
            "wstg_target_coverage_pct": wstg_target_coverage_pct,
            "wstg_catalog_coverage_pct": wstg_catalog_coverage_pct
        },
        "details": {
            "tp_cases": tp_cases,
            "fn_cases_count": len(fn_cases),
            "secure_fp_cases": secure_fp_cases,
            "unlisted_cases": unlisted_cases
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Pentesa Per-Target Benchmark Scorer (SUPPLEMENTARY)")
    parser.add_argument("--findings", required=True, help="Path to findings JSON file")
    parser.add_argument("--app", required=True, choices=["pentesa-bench", "juiceshop", "dvwa", "crapi", "webgoat"], help="Target app name in ground truth")
    parser.add_argument("--ground-truth", default="benchmark/ground_truth.yaml", help="Path to ground_truth.yaml")
    parser.add_argument("--adapt-schema", action="store_true", help="Adapt finding schema to compensate for P1-FIND-02")
    parser.add_argument("--output", help="Optional path to output JSON file")
    args = parser.parse_args()

    with open(args.findings, "r", encoding="utf-8") as f:
        data = json.load(f)
    findings = data if isinstance(data, list) else data.get("findings", [])

    result = score_target(
        app=args.app,
        findings=findings,
        ground_truth_path=args.ground_truth,
        adapt_schema=args.adapt_schema
    )

    out_str = json.dumps(result, indent=2)
    print(out_str)

    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as f:
            f.write(out_str)


if __name__ == "__main__":
    main()
