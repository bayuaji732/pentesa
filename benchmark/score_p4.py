#!/usr/bin/env python3
"""Pentesa Phase 4 Scoring Engine (benchmark/score_p4.py).

Scores Confirmed Findings and Candidate Findings separately against benchmark/ground_truth_p4.yaml.
Evaluates:
- TP / FP / FN
- Precision, Recall, F1
- False Positive Rate on Secure Controls (FPR_secure)
- Expected-Outcome-Class Match Rate (CONFIRMED_VULN, SECURE_NO_FINDING, FLAGGED_FOR_HUMAN_REVIEW)
- Evidence Completeness across the 15 Phase 7 fields
- Reproduction Success Rate
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from benchmark.score import (
    normalize_endpoint,
    normalize_method,
    normalize_parameter,
    normalize_wstg_id,
    extract_cwe_id,
    apply_category_equivalence,
    is_suppressed_finding,
    evaluate_evidence_completeness,
)


def compute_sha256(path: str) -> str:
    if not os.path.exists(path):
        return "NOT_FOUND"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def adapt_finding_schema(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Compensate for P1-FIND-02 by extracting endpoint/method/parameter from evidence."""
    f = dict(finding)

    if not f.get("parameter"):
        if f.get("affected_parameter"):
            f["parameter"] = f["affected_parameter"]
        elif f.get("affected_parameters"):
            f["parameter"] = f["affected_parameters"]

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


def matches_p4_ground_truth(finding: Dict[str, Any], gt_case: Dict[str, Any]) -> bool:
    """Strict matching rule: endpoint + method + parameter + CWE/WSTG."""
    f_ep = normalize_endpoint(finding.get("endpoint") or finding.get("url_path") or finding.get("path") or finding.get("matched_at") or "")
    gt_ep = normalize_endpoint(gt_case.get("endpoint", ""))

    ep_pattern = re.sub(r"\{[a-zA-Z0-9_]+\}", r"[^/]+", gt_ep)
    if not (f_ep == gt_ep or re.fullmatch(ep_pattern, f_ep)):
        return False

    f_method = normalize_method(finding.get("method") or finding.get("http_method") or "")
    gt_method = normalize_method(gt_case.get("method", ""))
    if f_method and gt_method and f_method != gt_method:
        return False

    gt_param = normalize_parameter(gt_case.get("parameter", ""))
    if gt_param and gt_param not in ("none", "n/a", ""):
        f_params = finding.get("parameter") or finding.get("affected_parameter") or finding.get("affected_parameters") or []
        if isinstance(f_params, str):
            f_params_list = [normalize_parameter(f_params)]
        elif isinstance(f_params, list):
            f_params_list = [normalize_parameter(p) for p in f_params]
        elif isinstance(f_params, dict):
            f_params_list = [normalize_parameter(k) for k in f_params.keys()]
        else:
            f_params_list = []

        if f_params_list and not any(gt_param in p or p in gt_param for p in f_params_list):
            return False

    # CWE / WSTG / Category equivalence matching
    gt_cwe = extract_cwe_id(gt_case.get("cwe"))
    f_cwe = extract_cwe_id(finding.get("cwe_id") or finding.get("cwe"))
    cwe_match = (gt_cwe is not None and f_cwe is not None and gt_cwe == f_cwe)

    gt_wstg = normalize_wstg_id(gt_case.get("wstg_id", ""))
    f_wstg = normalize_wstg_id(finding.get("wstg_id") or finding.get("wstg_code") or "")
    wstg_match = (bool(gt_wstg) and bool(f_wstg) and gt_wstg == f_wstg)

    gt_canon = apply_category_equivalence(gt_case.get("category", ""), gt_cwe, gt_wstg, gt_ep)
    f_canon = apply_category_equivalence(finding.get("category", ""), f_cwe, f_wstg, f_ep)

    if gt_canon and f_canon and gt_canon != f_canon:
        return False

    canon_match = bool(gt_canon and f_canon and gt_canon == f_canon)

    return cwe_match or wstg_match or canon_match


def score_finding_set(
    findings: List[Dict[str, Any]],
    app_gt_cases: List[Dict[str, Any]],
    is_candidate_set: bool = False
) -> Dict[str, Any]:
    vulnerable_cases = [c for c in app_gt_cases if c.get("vulnerable") is True]
    secure_cases = [c for c in app_gt_cases if c.get("vulnerable") is False]

    eval_findings = [adapt_finding_schema(f) for f in findings]

    matched_gt_ids: Set[str] = set()
    matched_finding_ids: Set[str] = set()

    tp_cases: List[Dict[str, Any]] = []
    secure_fp_cases: List[Dict[str, Any]] = []
    unlisted_cases: List[Dict[str, Any]] = []
    fn_cases: List[Dict[str, Any]] = []
    outcome_matches = 0
    evidence_completeness_scores: List[float] = []
    repro_success_count = 0

    # 1. Match against vulnerable cases
    for gt in vulnerable_cases:
        matched = False
        for idx, finding in enumerate(eval_findings):
            f_id = str(finding.get("id") or f"f_{idx}")
            if f_id in matched_finding_ids:
                continue
            if is_suppressed_finding(finding):
                continue
            if matches_p4_ground_truth(finding, gt):
                matched = True
                matched_gt_ids.add(gt["id"])
                matched_finding_ids.add(f_id)

                # Check expected outcome class
                exp_outcome = gt.get("expected_outcome_class", "CONFIRMED_VULN")
                finding_status = str(finding.get("status") or finding.get("validation_status") or "").upper()
                if exp_outcome == "FLAGGED_FOR_HUMAN_REVIEW":
                    # Matches if flagged for review or held as candidate without destructive exploitation
                    if is_candidate_set or "REVIEW" in finding_status or finding.get("requires_human_review"):
                        outcome_matches += 1
                elif exp_outcome == "CONFIRMED_VULN":
                    if finding_status in ("CONFIRMED", "DETECTED") or not is_candidate_set:
                        outcome_matches += 1

                # Evidence completeness
                comp_score, _ = evaluate_evidence_completeness(finding)
                evidence_completeness_scores.append(comp_score)

                # Reproduction success
                if finding.get("reproduction_curl") or finding.get("raw_response"):
                    repro_success_count += 1

                tp_cases.append({
                    "gt_id": gt["id"],
                    "category": gt["category"],
                    "endpoint": gt["endpoint"],
                    "finding_id": f_id,
                    "title": finding.get("title", ""),
                    "expected_outcome": exp_outcome,
                    "completeness_pct": comp_score
                })
                break
        if not matched:
            fn_cases.append({
                "gt_id": gt["id"],
                "category": gt["category"],
                "endpoint": gt["endpoint"],
                "expected_outcome": gt.get("expected_outcome_class", "CONFIRMED_VULN")
            })

    # 2. Match against secure cases (check for FP)
    for gt in secure_cases:
        matched = False
        for idx, finding in enumerate(eval_findings):
            f_id = str(finding.get("id") or f"f_{idx}")
            if is_suppressed_finding(finding):
                continue
            if matches_p4_ground_truth(finding, gt):
                matched = True
                secure_fp_cases.append({
                    "gt_id": gt["id"],
                    "category": gt["category"],
                    "endpoint": gt["endpoint"],
                    "finding_id": f_id,
                    "title": finding.get("title", "")
                })
                break
        if not matched:
            # Secure control passed cleanly with 0 findings -> outcome class match!
            outcome_matches += 1

    # 3. Unlisted findings
    for idx, finding in enumerate(eval_findings):
        f_id = str(finding.get("id") or f"f_{idx}")
        if is_suppressed_finding(finding):
            continue
        if f_id not in matched_finding_ids:
            unlisted_cases.append({
                "finding_id": f_id,
                "title": finding.get("title", ""),
                "endpoint": finding.get("endpoint", "")
            })

    tp = len(tp_cases)
    fn = len(fn_cases)
    sec_fp = len(secure_fp_cases)
    unlisted = len(unlisted_cases)
    strict_fp = sec_fp + unlisted

    total_vuln = len(vulnerable_cases)
    total_sec = len(secure_cases)
    total_cases = total_vuln + total_sec

    precision = round(tp / (tp + strict_fp), 4) if (tp + strict_fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1 = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0
    fpr_sec = round(sec_fp / total_sec, 4) if total_sec > 0 else 0.0
    outcome_match_rate = round(outcome_matches / total_cases, 4) if total_cases > 0 else 0.0
    mean_completeness = round(sum(evidence_completeness_scores) / len(evidence_completeness_scores), 2) if evidence_completeness_scores else 0.0
    repro_rate = round(repro_success_count / tp, 4) if tp > 0 else 0.0

    return {
        "true_positives": tp,
        "false_positives_strict": strict_fp,
        "false_negatives": fn,
        "secure_control_fps": sec_fp,
        "unlisted_findings": unlisted,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "fpr_secure_controls": fpr_sec,
        "expected_outcome_class_match_rate": outcome_match_rate,
        "mean_evidence_completeness_pct": mean_completeness,
        "reproduction_success_rate": repro_rate,
        "tp_cases": tp_cases,
        "fn_cases": fn_cases,
        "secure_fp_cases": secure_fp_cases,
        "unlisted_cases": unlisted_cases
    }


def score_p4(
    app: str,
    confirmed_findings: List[Dict[str, Any]],
    candidate_findings: List[Dict[str, Any]],
    ground_truth_path: str = "benchmark/ground_truth_p4.yaml"
) -> Dict[str, Any]:
    with open(ground_truth_path, "r", encoding="utf-8") as f:
        gt_data = yaml.safe_load(f)

    app_gt = [c for c in gt_data.get("cases", []) if c.get("app") == app]

    confirmed_eval = score_finding_set(confirmed_findings, app_gt, is_candidate_set=False)
    candidate_eval = score_finding_set(candidate_findings, app_gt, is_candidate_set=True)

    gt_sha = compute_sha256(ground_truth_path)

    return {
        "target_app": app,
        "ground_truth_sha256": gt_sha,
        "total_ground_truth_cases": len(app_gt),
        "vulnerable_cases_count": sum(1 for c in app_gt if c.get("vulnerable")),
        "secure_control_cases_count": sum(1 for c in app_gt if not c.get("vulnerable")),
        "confirmed_findings_metrics": confirmed_eval,
        "candidate_findings_metrics": candidate_eval
    }


def main():
    parser = argparse.ArgumentParser(description="Pentesa Phase 4 Scorer")
    parser.add_argument("--app", required=True, choices=["pentesa-bench", "juiceshop", "crapi"], help="Target application name")
    parser.add_argument("--findings", required=True, help="Path to confirmed findings JSON")
    parser.add_argument("--candidates", help="Optional path to candidate findings JSON")
    parser.add_argument("--ground-truth", default="benchmark/ground_truth_p4.yaml", help="Path to ground_truth_p4.yaml")
    parser.add_argument("--output", help="Optional path to output JSON file")
    args = parser.parse_args()

    with open(args.findings, "r", encoding="utf-8") as f:
        d = json.load(f)
    findings = d if isinstance(d, list) else d.get("findings", [])

    candidates = []
    if args.candidates and os.path.exists(args.candidates):
        with open(args.candidates, "r", encoding="utf-8") as f:
            cd = json.load(f)
        candidates = cd if isinstance(cd, list) else cd.get("findings", [])

    result = score_p4(
        app=args.app,
        confirmed_findings=findings,
        candidate_findings=candidates,
        ground_truth_path=args.ground_truth
    )

    out_str = json.dumps(result, indent=2)
    print(out_str)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out_str)


if __name__ == "__main__":
    main()
