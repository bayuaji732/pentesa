#!/usr/bin/env python3
"""Supplementary Scorer for Candidate (Unverified) Findings.

DISCLAIMER:
This script provides SUPPLEMENTARY metrics for candidate findings (leads flagged
by discovery/probers before active exploitation verification). Primary authoritative
benchmark metrics remain CONFIRMED findings only, scored via the frozen benchmark/score.py.
"""

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List
from urllib.parse import urlparse

# Ensure workspace root is in PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from benchmark.score import score_benchmark


def adapt_candidate_finding(item: Dict[str, Any], index: int) -> Dict[str, Any]:
    """Normalize a candidate finding dictionary to match the Phase 7 evaluation schema."""
    target_url = item.get("target_url") or item.get("url") or ""
    parsed = urlparse(target_url)
    endpoint = parsed.path or item.get("endpoint") or "/"

    method = item.get("http_method") or item.get("method") or "GET"
    raw_req = item.get("raw_request") or ""
    if raw_req:
        first_line = raw_req.strip().split("\n")[0].strip()
        match = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+", first_line)
        if match:
            method = match.group(1).upper()

    cwe = item.get("cwe_id")
    if isinstance(cwe, str) and cwe.upper().startswith("CWE-"):
        try:
            cwe = int(cwe.split("-")[1])
        except Exception:
            pass

    return {
        "id": item.get("id") or f"CANDIDATE-{index+1:03d}",
        "target": target_url or f"{parsed.scheme}://{parsed.netloc}",
        "endpoint": endpoint,
        "method": method,
        "parameter": item.get("parameter") or "N/A",
        "wstg_id": item.get("wstg_id") or "WSTG-CLNT-09",
        "cwe_id": cwe or 200,
        "category": item.get("category") or item.get("source") or "candidate_probe",
        "title": item.get("title") or "Unverified Candidate Finding",
        "detection_source": item.get("source") or "prober",
        "reproduction_procedure": item.get("reproduction_curl") or "",
        "reproduction_curl": item.get("reproduction_curl") or "",
        "reproduction_verified": False,
        "actual_evidence": item.get("raw_response") or item.get("description") or "",
        "severity": (item.get("severity") or "LOW").upper(),
        "severity_justification": item.get("description") or "Candidate finding pending validation",
        "confidence": "CANDIDATE",
        "false_positive_assessment": "Unverified candidate lead",
        "remediation": "Apply defense-in-depth controls",
        "validation_status": "CANDIDATE",
    }


def main():
    parser = argparse.ArgumentParser(description="Supplementary Candidate Finding Scorer")
    parser.add_argument("--candidates", required=True, help="Path to JSON file containing candidate findings array")
    parser.add_argument("--ground-truth", default="benchmark/ground_truth.yaml", help="Path to ground truth YAML")
    parser.add_argument("--run-info", default=None, help="Optional run metadata string")
    parser.add_argument("--output", default=None, help="Optional output file path")

    args = parser.parse_args()

    if not os.path.exists(args.candidates):
        print(f"Error: Candidate file '{args.candidates}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(args.candidates, "r", encoding="utf-8") as f:
        data = json.load(f)

    raw_candidates = data if isinstance(data, list) else data.get("candidate_findings", [])
    adapted = [adapt_candidate_finding(c, idx) for idx, c in enumerate(raw_candidates)]

    run_meta = {"candidate_scoring": True}
    if args.run_info:
        try:
            run_meta.update(json.loads(args.run_info))
        except Exception:
            run_meta["raw_info"] = args.run_info

    score_result = score_benchmark(ground_truth_path=args.ground_truth, findings=adapted, execution_telemetry=run_meta)

    # Inject explicit supplementary declaration
    score_result["scoring_declaration"] = {
        "status": "SUPPLEMENTARY",
        "notice": (
            "SUPPLEMENTARY METRICS FOR CANDIDATE (UNVERIFIED) FINDINGS. "
            "PRIMARY AUTHORITATIVE BENCHMARK METRICS REMAIN CONFIRMED FINDINGS ONLY."
        ),
        "total_candidates_evaluated": len(adapted)
    }

    out_str = json.dumps(score_result, indent=2)
    print(out_str)

    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as f:
            f.write(out_str)


if __name__ == "__main__":
    main()
