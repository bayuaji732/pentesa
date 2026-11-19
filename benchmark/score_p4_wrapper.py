#!/usr/bin/env python3
"""Pentesa Phase 4 Scorer Wrapper (benchmark/score_p4_wrapper.py).

Declared wrapper script providing memory-only sanitization for unquoted colons
in ground_truth_p4.yaml (Line 202: unquoted 'check: ') without modifying
the frozen ground_truth_p4.yaml or patching third-party site-packages.
"""

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from benchmark.score_p4 import score_finding_set, compute_sha256


def load_sanitized_ground_truth(path: str) -> Dict[str, Any]:
    """Parse ground truth YAML with memory-only repair of unquoted ': ' scalars."""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    sanitized_lines = []
    for line in text.splitlines():
        # Match lines like '    key: value with another: key'
        m = re.match(r"^(\s*[a-zA-Z0-9_-]+:\s+)(.*)$", line)
        if m:
            prefix, val = m.group(1), m.group(2)
            if not val.startswith(('"', "'", "[", "{")) and ": " in val:
                val = '"' + val.replace('"', '\\"') + '"'
            sanitized_lines.append(prefix + val)
        else:
            sanitized_lines.append(line)

    repaired_yaml = "\n".join(sanitized_lines)
    return yaml.safe_load(repaired_yaml)


def score_p4_safe(
    app: str,
    confirmed_findings: List[Dict[str, Any]],
    candidate_findings: List[Dict[str, Any]],
    ground_truth_path: str = "benchmark/ground_truth_p4.yaml"
) -> Dict[str, Any]:
    gt_data = load_sanitized_ground_truth(ground_truth_path)
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
    parser = argparse.ArgumentParser(description="Pentesa Phase 4 Scorer Wrapper")
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

    result = score_p4_safe(
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
