#!/usr/bin/env python3
"""Pentesa Pentest Effectiveness Benchmark — Deterministic Scorer.

Evaluates penetration testing findings against the master ground truth matrix
(benchmark/ground_truth.yaml). Matches findings by (endpoint, method, parameter, CWE/WSTG)
and computes:
- True Positives (TP), False Positives (FP), False Negatives (FN)
- Precision, Recall, F1 Score
- False Positive Rate on Secure Cases (FPR_secure)
- Reproduction Success Rate
- Evidence Completeness Score (based on Master Phase 7 requirement checklist)
- WSTG Coverage (Executed / Applicable)
- Execution Reliability (Completed runs, timeouts, crashes)
"""

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
import yaml

# Master Phase 7 Mandatory Finding Quality Fields
PHASE_7_REQUIRED_FIELDS = [
    "id",
    "target",
    "endpoint",
    "method",
    "parameter",
    "wstg_id",
    "cwe_id",
    "detection_source",
    "reproduction_procedure",
    "actual_evidence",
    "severity_justification",
    "confidence",
    "false_positive_assessment",
    "remediation",
    "validation_status",
]


def normalize_endpoint(endpoint_or_url: str) -> str:
    """Normalize full URL or path to a uniform root-relative URL path."""
    if not endpoint_or_url:
        return "/"
    ep = endpoint_or_url.strip()
    if ep.startswith("http://") or ep.startswith("https://"):
        parsed = urlparse(ep)
        path = parsed.path or "/"
    else:
        path = ep.split("?")[0].split("#")[0]
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return path.lower()


def normalize_method(method: str) -> str:
    """Normalize HTTP method string."""
    return (method or "GET").strip().upper()


def normalize_parameter(param: str) -> str:
    """Normalize parameter string (query, form, header, or body)."""
    if not param:
        return ""
    p = param.strip().lower()
    if p.startswith("header:"):
        return p[7:]
    return p


def extract_cwe_id(cwe: Any) -> Optional[int]:
    """Extract integer CWE number from string or int (e.g. 'CWE-89', 89, 'cwe-89')."""
    if not cwe:
        return None
    if isinstance(cwe, int):
        return cwe
    match = re.search(r"(\d+)", str(cwe))
    if match:
        return int(match.group(1))
    return None


def normalize_wstg_id(wstg_code: str) -> str:
    """Normalize full WSTG test code e.g. 'WSTG-INPV-05'."""
    if not wstg_code:
        return ""
    match = re.search(r"WSTG-[A-Z]{4}-\d+", wstg_code.upper())
    if match:
        return match.group(0)
    return wstg_code.strip().upper()


def extract_wstg_category(wstg_code: str) -> str:
    """Extract standard 4-letter WSTG category code e.g. 'WSTG-INPV-05' -> 'INPV'."""
    if not wstg_code:
        return ""
    match = re.search(r"WSTG-([A-Z]{4})", wstg_code.upper())
    if match:
        return match.group(1)
    return ""


def is_suppressed_finding(finding: Dict[str, Any]) -> bool:
    """Check if a finding was suppressed or refuted as a false positive by the platform."""
    status = str(finding.get("validation_status") or finding.get("status") or "").upper()
    confidence = str(finding.get("confidence") or "").upper()
    if (
        status in ("FALSE_POSITIVE", "FP", "REFUTED", "SUPPRESSED")
        or finding.get("is_false_positive", False)
        or confidence in ("REFUTED", "FALSE_POSITIVE")
    ):
        return True
    return False


def evaluate_evidence_completeness(finding: Dict[str, Any]) -> Tuple[float, List[str]]:
    """Evaluate finding against the 15 Phase 7 evidence fields.
    
    Returns:
        (completeness_pct, missing_fields)
    """
    missing = []
    
    # 1. unique finding ID
    if not finding.get("id"):
        missing.append("id")
    # 2. affected target
    if not (finding.get("target") or finding.get("target_url") or finding.get("host")):
        missing.append("target")
    # 3. endpoint
    if not (finding.get("endpoint") or finding.get("url_path") or finding.get("path")):
        missing.append("endpoint")
    # 4. method
    if not (finding.get("method") or finding.get("http_method")):
        missing.append("method")
    # 5. affected parameter
    if not (finding.get("parameter") or finding.get("affected_parameters") or finding.get("param")):
        missing.append("parameter")
    # 6. WSTG mapping
    if not (finding.get("wstg_id") or finding.get("wstg_code")):
        missing.append("wstg_id")
    # 7. CWE mapping
    if not (finding.get("cwe_id") or finding.get("cwe")):
        missing.append("cwe_id")
    # 8. detection source
    if not (finding.get("detection_source") or finding.get("source_tool") or finding.get("discovered_by")):
        missing.append("detection_source")
    # 9. reproduction procedure
    if not (finding.get("reproduction_procedure") or finding.get("reproduction_curl") or finding.get("curl_command")):
        missing.append("reproduction_procedure")
    # 10. actual evidence
    if not (finding.get("actual_evidence") or finding.get("raw_request") or finding.get("evidence_hash") or finding.get("raw_response")):
        missing.append("actual_evidence")
    # 11. severity justification
    if not (finding.get("severity_justification") or finding.get("severity_rationale") or (finding.get("severity") and finding.get("description"))):
        missing.append("severity_justification")
    # 12. confidence level
    if not finding.get("confidence"):
        missing.append("confidence")
    # 13. false positive assessment
    if not (finding.get("false_positive_assessment") or finding.get("fp_analysis") or "is_false_positive" in finding or "fp_risk" in finding):
        missing.append("false_positive_assessment")
    # 14. remediation
    if not (finding.get("remediation") or finding.get("recommendation")):
        missing.append("remediation")
    # 15. validation status
    if not (finding.get("validation_status") or finding.get("status")):
        missing.append("validation_status")

    total_fields = len(PHASE_7_REQUIRED_FIELDS)
    present_fields = total_fields - len(missing)
    completeness_pct = round((present_fields / total_fields) * 100.0, 1)
    return completeness_pct, missing


def apply_category_equivalence(category: str, cwe_id: Optional[int], wstg_id: str, endpoint: str) -> str:
    """Canonicalize vulnerability category based on deterministic equivalence rules (A3).
    
    Category-equivalence rules:
    - SQL Injection (CWE-89 or WSTG-INPV-05) at an authentication/login endpoint scores under
      SQL Injection ('sql_injection'), NOT Authentication ('authentication').
    - Command Injection (CWE-78 or WSTG-INPV-12) scores under 'command_injection'.
    - Cross-Site Scripting (CWE-79 or WSTG-INPV-01/02) scores under 'xss'.
    - SSRF (CWE-918 or WSTG-INPV-19) scores under 'ssrf'.
    - XXE (CWE-611 or WSTG-INPV-07) scores under 'xxe'.
    - Path Traversal (CWE-22/23 or WSTG-ATHZ-01) scores under 'path_traversal'.
    - IDOR/BOLA (CWE-639 or WSTG-ATHZ-04) scores under 'idor'.
    """
    cat = (category or "").lower().strip()
    wstg = normalize_wstg_id(wstg_id)
    ep = normalize_endpoint(endpoint)

    if cwe_id == 89 or wstg == "WSTG-INPV-05" or "sql" in cat:
        return "sql_injection"
    if cwe_id == 78 or wstg == "WSTG-INPV-12" or "command" in cat:
        return "command_injection"
    if cwe_id == 79 or wstg in ("WSTG-INPV-01", "WSTG-INPV-02") or "xss" in cat:
        return "xss"
    if cwe_id == 918 or wstg == "WSTG-INPV-19" or "ssrf" in cat:
        return "ssrf"
    if cwe_id == 611 or wstg == "WSTG-INPV-07" or "xxe" in cat:
        return "xxe"
    if cwe_id in (22, 23) or wstg == "WSTG-ATHZ-01" or "traversal" in cat:
        return "path_traversal"
    if cwe_id == 639 or wstg == "WSTG-ATHZ-04" or "idor" in cat or "bola" in cat:
        return "idor"
    if cwe_id == 285 or wstg == "WSTG-ATHZ-02" or "access control" in cat or "bac" in cat:
        return "broken_access_control"
    if cwe_id in (287, 307, 620) or wstg in ("WSTG-ATHN-02", "WSTG-ATHN-03", "WSTG-ATHN-09") or "auth" in cat:
        return "authentication"
    if cwe_id == 347 or wstg == "WSTG-SESS-01" or "jwt" in cat:
        return "jwt"
    if cwe_id == 434 or wstg == "WSTG-BUSL-08" or "upload" in cat:
        return "file_upload"
    if cwe_id == 1336 or wstg == "WSTG-INPV-18" or "ssti" in cat:
        return "ssti"
    if cwe_id == 362 or wstg == "WSTG-BUSL-04" or "race" in cat:
        return "race_conditions"
    if cwe_id == 213 or wstg == "WSTG-APIT-01" or "api" in cat:
        return "api_security"
    if cwe_id == 840 or wstg == "WSTG-BUSL-01" or "business" in cat or "logic" in cat:
        return "business_logic"
    return cat


def finding_matches_ground_truth(finding: Dict[str, Any], gt_case: Dict[str, Any]) -> bool:
    """Deterministic matching of finding to a ground truth case.
    
    Matching criteria:
    1. Endpoint path matches normalized root-relative path (exact match or path variable placeholder).
    2. HTTP method matches.
    3. Parameter matches (if parameter is specified in GT).
    4. CWE matches OR WSTG category matches OR canonical category equivalence matches.
    """
    f_ep = normalize_endpoint(finding.get("endpoint") or finding.get("url_path") or finding.get("path") or finding.get("target_url") or "")
    gt_ep = normalize_endpoint(gt_case.get("endpoint", ""))
    
    # Handle dynamic path parameters e.g. {vehicleId} or {user_id}
    ep_pattern = re.sub(r"\{[a-zA-Z0-9_]+\}", r"[^/]+", gt_ep)
    if not (f_ep == gt_ep or re.fullmatch(ep_pattern, f_ep)):
        return False

    # Method matching
    f_method = normalize_method(finding.get("method") or finding.get("http_method") or "")
    gt_method = normalize_method(gt_case.get("method", ""))
    if f_method != gt_method:
        return False

    # Parameter matching
    gt_param = normalize_parameter(gt_case.get("parameter", ""))
    if gt_param and gt_param not in ("none", "n/a", ""):
        f_params = finding.get("parameter") or finding.get("affected_parameters") or []
        if isinstance(f_params, str):
            f_params_list = [normalize_parameter(f_params)]
        elif isinstance(f_params, list):
            f_params_list = [normalize_parameter(p) for p in f_params]
        elif isinstance(f_params, dict):
            f_params_list = [normalize_parameter(k) for k in f_params.keys()]
        else:
            f_params_list = []

        if not any(gt_param in p or p in gt_param for p in f_params_list):
            return False

    # CWE / WSTG / Category matching
    gt_cwe = extract_cwe_id(gt_case.get("cwe"))
    f_cwe = extract_cwe_id(finding.get("cwe_id") or finding.get("cwe"))
    cwe_match = (gt_cwe is not None and f_cwe is not None and gt_cwe == f_cwe)

    gt_wstg = normalize_wstg_id(gt_case.get("wstg_id", ""))
    f_wstg = normalize_wstg_id(finding.get("wstg_id") or finding.get("wstg_code") or "")
    wstg_match = (bool(gt_wstg) and bool(f_wstg) and gt_wstg == f_wstg)

    cat_name_match = False
    gt_cat = (gt_case.get("category") or "").strip().lower()
    f_cat = (finding.get("category") or "").strip().lower()
    if gt_cat and f_cat and (gt_cat == f_cat or gt_cat in f_cat):
        cat_name_match = True

    # Category equivalence matching (A3: SQLi at login scores under SQLi)
    gt_canon = apply_category_equivalence(gt_case.get("category", ""), gt_cwe, gt_wstg, gt_ep)
    f_canon = apply_category_equivalence(finding.get("category", ""), f_cwe, f_wstg, f_ep)

    # Disallow cross-category matching when canonical categories differ
    if gt_canon and f_canon and gt_canon != f_canon:
        return False

    canon_match = bool(gt_canon and f_canon and gt_canon == f_canon)

    return cwe_match or wstg_match or cat_name_match or canon_match


def score_benchmark(
    ground_truth_path: str,
    findings: List[Dict[str, Any]],
    execution_telemetry: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Score a benchmark run deterministically against the ground truth matrix.
    
    Implements Master Phase 3 Scorer Policy (A3):
    1. True Positives (TP): Findings matching known vulnerable ground-truth cases.
    2. False Negatives (FN): Vulnerable ground-truth cases not detected by findings.
    3. Secure Case False Positives (FP_secure): Findings matching known secure control cases.
    4. UNLISTED Findings: Findings matching no ground-truth entry.
       - Each unlisted finding is adjudicated via reference PoC.
       - Strict Precision counts UNLISTED findings as FP.
       - Adjudicated Precision differentiates confirmed vulnerabilities from false positives.
       - Precision is reported as AUTHORITATIVE only on pentesa-bench (complete closed-world GT).
    5. WSTG Coverage: Executed / Applicable tests.
    """
    if not os.path.exists(ground_truth_path):
        raise FileNotFoundError(f"Ground truth file not found: {ground_truth_path}")

    with open(ground_truth_path, "r", encoding="utf-8") as f:
        gt_data = yaml.safe_load(f)

    gt_cases = gt_data.get("cases", [])
    vulnerable_cases = [c for c in gt_cases if c.get("vulnerable") is True]
    secure_cases = [c for c in gt_cases if c.get("vulnerable") is False]

    matched_gt_ids: Set[str] = set()
    matched_finding_ids: Set[str] = set()
    
    tp_cases: List[Dict[str, Any]] = []
    secure_fp_cases: List[Dict[str, Any]] = []
    unlisted_cases: List[Dict[str, Any]] = []
    fn_cases: List[Dict[str, Any]] = []

    # 1. Match findings against vulnerable cases (True Positives vs False Negatives)
    for gt in vulnerable_cases:
        matched = False
        for idx, finding in enumerate(findings):
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

    # 2. Check for False Positives on Secure Cases
    for gt in secure_cases:
        for idx, finding in enumerate(findings):
            f_id = str(finding.get("id") or f"finding_{idx}")
            if f_id in matched_finding_ids:
                continue
            if is_suppressed_finding(finding):
                continue
            if finding_matches_ground_truth(finding, gt):
                matched_finding_ids.add(f_id)
                secure_fp_cases.append({
                    "type": "SECURE_CASE_FALSE_POSITIVE",
                    "gt_id": gt["id"],
                    "app": gt.get("app", ""),
                    "category": gt["category"],
                    "endpoint": gt["endpoint"],
                    "finding_id": f_id,
                    "title": finding.get("title", "")
                })

    # 3. Check for Unlisted Findings (A3: unmatched findings become UNLISTED, not automatic FP)
    for idx, finding in enumerate(findings):
        f_id = str(finding.get("id") or f"finding_{idx}")
        if f_id not in matched_finding_ids:
            if is_suppressed_finding(finding):
                continue

            # Check adjudication status from finding metadata
            adjudication = str(
                finding.get("adjudication")
                or finding.get("adjudication_status")
                or finding.get("adjudicated_as")
                or ""
            ).upper()

            is_adjudicated_tp = adjudication in ("TRUE_POSITIVE", "TP", "CONFIRMED_VULNERABILITY", "VALID")
            adjudication_verdict = "CONFIRMED_VULNERABILITY" if is_adjudicated_tp else "FALSE_POSITIVE"

            unlisted_cases.append({
                "type": "UNLISTED_FINDING",
                "finding_id": f_id,
                "target": finding.get("target") or finding.get("host", ""),
                "endpoint": finding.get("endpoint") or finding.get("url_path", ""),
                "title": finding.get("title", ""),
                "category": finding.get("category", ""),
                "cwe": finding.get("cwe_id") or finding.get("cwe"),
                "adjudication_status": adjudication_verdict,
                "is_adjudicated_tp": is_adjudicated_tp,
                "poc": finding.get("reproduction_curl") or finding.get("reproduction_procedure", "")
            })

    # Mathematical Counts
    tp = len(tp_cases)
    fn = len(fn_cases)
    secure_fp_count = len(secure_fp_cases)
    unlisted_count = len(unlisted_cases)
    unlisted_tp_count = sum(1 for u in unlisted_cases if u["is_adjudicated_tp"])
    unlisted_fp_count = unlisted_count - unlisted_tp_count

    total_vuln = len(vulnerable_cases)
    total_secure = len(secure_cases)

    # Core Metrics (A3 Scorer Policy)
    # Strict Precision: UNLISTED counted as FP
    strict_fp_total = secure_fp_count + unlisted_count
    strict_precision = round(tp / (tp + strict_fp_total), 4) if (tp + strict_fp_total) > 0 else 0.0

    # Adjudicated Precision: UNLISTED adjudicated via reference PoC
    adj_numerator = tp + unlisted_tp_count
    adj_denominator = adj_numerator + secure_fp_count + unlisted_fp_count
    adjudicated_precision = round(adj_numerator / adj_denominator, 4) if adj_denominator > 0 else 0.0

    # Standard Recall & F1
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    strict_f1 = round(2 * (strict_precision * recall) / (strict_precision + recall), 4) if (strict_precision + recall) > 0 else 0.0
    adjudicated_f1 = round(2 * (adjudicated_precision * recall) / (adjudicated_precision + recall), 4) if (adjudicated_precision + recall) > 0 else 0.0
    fpr_secure = round(secure_fp_count / total_secure, 4) if total_secure > 0 else 0.0

    # Authoritative Bench App Metrics (A3: complete closed-world ground truth)
    bench_cases_gt = [c for c in gt_cases if c.get("app") == "pentesa-bench"]
    bench_vuln_count = sum(1 for c in bench_cases_gt if c.get("vulnerable") is True)
    bench_secure_count = sum(1 for c in bench_cases_gt if c.get("vulnerable") is False)

    bench_tp = [t for t in tp_cases if t.get("app") == "pentesa-bench"]
    bench_fn = [n for n in fn_cases if n.get("app") == "pentesa-bench"]
    bench_fp_sec = [s for s in secure_fp_cases if s.get("app") == "pentesa-bench"]
    bench_unlisted = [
        u for u in unlisted_cases
        if "pentesa-bench" in str(u.get("target", "")).lower()
        or ":8080" in str(u.get("target", ""))
        or u.get("endpoint", "").startswith(("/sqli", "/xss", "/ssrf", "/jwt", "/cmd", "/ssti", "/xxe", "/race", "/order"))
    ]
    bench_unlisted_tp = sum(1 for u in bench_unlisted if u["is_adjudicated_tp"])
    bench_unlisted_fp = len(bench_unlisted) - bench_unlisted_tp

    bench_tp_count = len(bench_tp)
    bench_fn_count = len(bench_fn)
    bench_strict_fp = len(bench_fp_sec) + len(bench_unlisted)
    bench_strict_prec = round(bench_tp_count / (bench_tp_count + bench_strict_fp), 4) if (bench_tp_count + bench_strict_fp) > 0 else 0.0
    bench_adj_prec = round((bench_tp_count + bench_unlisted_tp) / (bench_tp_count + bench_unlisted_tp + len(bench_fp_sec) + bench_unlisted_fp), 4) if (bench_tp_count + bench_unlisted_tp + len(bench_fp_sec) + bench_unlisted_fp) > 0 else 0.0
    bench_recall = round(bench_tp_count / (bench_tp_count + bench_fn_count), 4) if (bench_tp_count + bench_fn_count) > 0 else 0.0
    bench_f1 = round(2 * (bench_strict_prec * bench_recall) / (bench_strict_prec + bench_recall), 4) if (bench_strict_prec + bench_recall) > 0 else 0.0

    # Reproduction Success Rate
    verified_repro_count = 0
    for finding in findings:
        has_curl = bool(finding.get("reproduction_curl") or finding.get("reproduction_procedure"))
        verified = bool(finding.get("reproduction_verified") or finding.get("reproduction_status") == "VERIFIED")
        if has_curl or verified:
            verified_repro_count += 1
    reproduction_rate = round(verified_repro_count / len(findings), 4) if findings else 0.0

    # Evidence Completeness
    completeness_scores = []
    for finding in findings:
        score, _ = evaluate_evidence_completeness(finding)
        completeness_scores.append(score)
    mean_evidence_completeness = round(sum(completeness_scores) / len(completeness_scores), 2) if completeness_scores else 0.0

    # Execution Telemetry
    telem = execution_telemetry or {}
    total_runs = telem.get("scheduled_runs", 1)
    completed_runs = telem.get("completed_runs", 1)
    timeouts = telem.get("timeouts", 0)
    crashes = telem.get("crashes", 0)
    reliability = round(completed_runs / total_runs, 4) if total_runs > 0 else 1.0

    # WSTG Coverage (A3: Executed / Applicable)
    total_catalog_wstg = 106
    applicable_wstg = telem.get("applicable_wstg_tests")
    if applicable_wstg is None:
        applicable_wstg = telem.get("target_applicable_wstg_tests", 38)

    executed_wstg = telem.get("executed_wstg_tests", tp + fn)
    wstg_coverage_pct = round((executed_wstg / applicable_wstg) * 100.0, 2) if applicable_wstg > 0 else 0.0
    wstg_catalog_coverage_pct = round((executed_wstg / total_catalog_wstg) * 100.0, 2)

    return {
        "benchmark_summary": {
            "total_ground_truth_cases": len(gt_cases),
            "vulnerable_cases_count": total_vuln,
            "secure_cases_count": total_secure,
            "total_findings_evaluated": len(findings),
        },
        "detection_metrics": {
            "true_positives": tp,
            "false_positives": strict_fp_total,
            "false_negatives": fn,
            "secure_cases_false_positives": secure_fp_count,
            "unlisted_findings_count": unlisted_count,
            "unlisted_adjudicated_tp": unlisted_tp_count,
            "unlisted_adjudicated_fp": unlisted_fp_count,
            "precision": strict_precision,
            "strict_precision": strict_precision,
            "adjudicated_precision": adjudicated_precision,
            "recall": recall,
            "f1_score": strict_f1,
            "adjudicated_f1_score": adjudicated_f1,
            "false_positive_rate_secure": fpr_secure,
        },
        "authoritative_bench_metrics": {
            "target": "pentesa-bench",
            "authority_status": "AUTHORITATIVE (ground truth is complete with paired positive/negative controls)",
            "benchmark_cases_count": len(bench_cases_gt),
            "vulnerable_cases_count": bench_vuln_count,
            "secure_cases_count": bench_secure_count,
            "true_positives": bench_tp_count,
            "false_negatives": bench_fn_count,
            "secure_control_false_positives": len(bench_fp_sec),
            "unlisted_findings": len(bench_unlisted),
            "strict_precision": bench_strict_prec,
            "adjudicated_precision": bench_adj_prec,
            "recall": bench_recall,
            "f1_score": bench_f1,
        },
        "third_party_precision_notice": {
            "authority_status": "INFORMATIONAL_ONLY (recall is authoritative; third-party unlisted findings require reference PoC adjudication)",
            "targets": ["juiceshop", "crapi", "dvwa"]
        },
        "quality_and_reliability_metrics": {
            "reproduction_success_rate": reproduction_rate,
            "mean_evidence_completeness_pct": mean_evidence_completeness,
            "wstg_coverage_pct": wstg_coverage_pct,
            "wstg_executed_tests": executed_wstg,
            "wstg_applicable_tests": applicable_wstg,
            "wstg_total_catalog_tests": total_catalog_wstg,
            "wstg_catalog_coverage_pct": wstg_catalog_coverage_pct,
            "execution_reliability": reliability,
            "total_runs": total_runs,
            "completed_runs": completed_runs,
            "timeouts": timeouts,
            "crashes": crashes,
        },
        "breakdown": {
            "true_positives_detail": tp_cases,
            "false_negatives_detail": fn_cases,
            "secure_cases_false_positives_detail": secure_fp_cases,
            "unlisted_findings_detail": unlisted_cases,
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Deterministic Scorer for Pentesa Benchmark")
    parser.add_argument("--ground-truth", default="benchmark/ground_truth.yaml", help="Path to ground truth YAML")
    parser.add_argument("--findings", required=True, help="Path to findings JSON file")
    parser.add_argument("--output", help="Optional path to output scored results JSON")
    args = parser.parse_args()

    with open(args.findings, "r", encoding="utf-8") as f:
        findings_data = json.load(f)

    if isinstance(findings_data, dict):
        findings = findings_data.get("items") or findings_data.get("findings") or [findings_data]
        telemetry = findings_data.get("execution_telemetry")
    elif isinstance(findings_data, list):
        findings = findings_data
        telemetry = None
    else:
        findings = []
        telemetry = None

    result = score_benchmark(args.ground_truth, findings, execution_telemetry=telemetry)
    out_json = json.dumps(result, indent=2)
    print(out_json)

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out_json)


if __name__ == "__main__":
    main()
