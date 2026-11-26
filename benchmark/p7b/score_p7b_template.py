"""Automated Fidelity Scorer for Pentesa Pentest Report Template (Phase 9 Wave 1c).

Evaluates rendered PDF (and optional HTML) against benchmark/ground_truth_p7b_template.yaml
and benchmark/p7b/template_spec.yaml.
"""

import argparse
import hashlib
import json
import os
import pathlib
import re
import sys
import yaml

def extract_all_text(content: bytes) -> str:
    """Extract and decompress all FlateDecode streams from PDF."""
    import zlib
    chunks = [content.decode("latin1", errors="replace")]
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", content, re.DOTALL):
        raw_stream = m.group(1)
        try:
            dec = zlib.decompress(raw_stream)
            chunks.append(dec.decode("latin1", errors="replace"))
        except Exception:
            pass
    return "\n".join(chunks)

def score_pdf_report(pdf_path: pathlib.Path, gt_path: pathlib.Path) -> dict:
    if not pdf_path.exists():
        return {"status": "FAILED", "reason": f"PDF file not found: {pdf_path}", "score": 0.0}

    with open(gt_path, "r", encoding="utf-8") as f:
        ground_truth = yaml.safe_load(f)

    content = pdf_path.read_bytes()
    pdf_text = extract_all_text(content)

    results = {
        "pdf_path": str(pdf_path),
        "file_size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "checks_passed": 0,
        "checks_total": 0,
        "details": []
    }

    def record_check(check_id: str, desc: str, passed: bool, info: str = ""):
        results["checks_total"] += 1
        if passed:
            results["checks_passed"] += 1
        results["details"].append({
            "id": check_id,
            "description": desc,
            "passed": passed,
            "info": info
        })

    # 1. Geometry & Page Format Check (P7B-TC-GEOM-01)
    mediaboxes = re.findall(r"/MediaBox\s*\[\s*([\d\.\s]+)\s*\]", pdf_text)
    geom_passed = False
    geom_info = f"Found mediaboxes: {mediaboxes}"
    if mediaboxes:
        first_box = mediaboxes[0].split()
        if len(first_box) >= 4:
            w = float(first_box[2])
            h = float(first_box[3])
            # A4 is 595.28 x 841.89 pt
            if abs(w - 595.28) <= 2.0 and abs(h - 841.89) <= 2.0:
                geom_passed = True
                geom_info = f"Standard A4 verified: {w:.2f} x {h:.2f} pt"
    record_check("P7B-TC-GEOM-01", "ISO A4 Page Format Verification", geom_passed, geom_info)

    # 2. Table Headers & Structure (P7B-TC-TABLE-01)
    # Check for presence of key Indonesian/English table headers in PDF streams
    t1_dates = "Pentest Completion Date" in pdf_text and "Retest Completion Date" in pdf_text
    record_check("P7B-TC-TABLE-01A", "Table 1 Assessment Dates Presence", t1_dates, "Pentest / Retest dates table")

    t2_summary = all(h in pdf_text for h in ["Temuan", "Severity", "Method", "Status"])
    record_check("P7B-TC-TABLE-01B", "Table 2 Findings Summary Presence", t2_summary, "Columns: Temuan, Severity, Method, Status")

    t3_signoff = all(h in pdf_text for h in ["Role", "Nama Perusahaan", "Nama Individu", "TTD"])
    record_check("P7B-TC-TABLE-01C", "Table 3 Sign-Off Approval Presence", t3_signoff, "Columns: Role, Nama Perusahaan, Nama Individu, TTD")

    t4_banner = "Detail Vulnerability" in pdf_text
    record_check("P7B-TC-TABLE-01D", "Table 4 Detail Vulnerability Banner", t4_banner, "Banner: Detail Vulnerability")

    # 3. CVSS v4.0 Vector Conformance (P7B-TC-CVSS4-01)
    cvss4_matches = re.findall(r"CVSS:4\.0\/[A-Z0-9\:\/]+", pdf_text)
    cvss4_valid = False
    cvss4_info = "No CVSS v4.0 vector found"
    if cvss4_matches:
        v = cvss4_matches[0]
        # Must have AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA
        req_metrics = ["AV:", "AC:", "AT:", "PR:", "UI:", "VC:", "VI:", "VA:", "SC:", "SI:", "SA:"]
        if all(m in v for m in req_metrics):
            cvss4_valid = True
            cvss4_info = f"Valid CVSS v4.0 vector: {v[:40]}..."
        else:
            cvss4_info = f"Incomplete CVSS v4.0 vector: {v}"
    record_check("P7B-TC-CVSS4-01", "CVSS v4.0 Full Vector Conformance", cvss4_valid, cvss4_info)

    # 4. PII & Typo Hygiene (P7B-TC-PII-01)
    typo_free = "Interantional" not in pdf_text
    record_check("P7B-TC-PII-01A", "Zero Interantional Typo", typo_free, "No 'Interantional' typo detected")

    # 5. Policies & Neutral Narrative (P7B-TC-POLICY-01)
    no_unsubstantiated = not any(claim in pdf_text for claim in ["STRONG SECURITY POSTURE", "completely secure", "zero risk"])
    record_check("P7B-TC-POLICY-01A", "Zero Unsubstantiated Security Claims", no_unsubstantiated, "No forbidden claims")

    # Final Score Calculation
    score_pct = (results["checks_passed"] / results["checks_total"]) * 100.0 if results["checks_total"] else 0.0
    results["score_pct"] = round(score_pct, 1)
    results["status"] = "PASSED" if score_pct >= 85.0 else "PARTIAL"

    return results

def main():
    parser = argparse.ArgumentParser(description="Score a report against P7B template ground truth.")
    parser.add_argument("--pdf", default=".scratch/prototype_template_reportlab.pdf", help="Path to PDF deliverable")
    parser.add_argument("--gt", default="benchmark/ground_truth_p7b_template.yaml", help="Path to ground truth YAML")
    parser.add_argument("--json", action="store_true", help="Output JSON results")
    args = parser.parse_args()

    res = score_pdf_report(pathlib.Path(args.pdf), pathlib.Path(args.gt))
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"\n========================================================")
        print(f" Pentesa Report Template Fidelity Scorecard (P7B)     ")
        print(f"========================================================")
        print(f"Target PDF:       {res['pdf_path']}")
        print(f"File SHA-256:     {res.get('sha256', '')[:16]}...")
        print(f"Checks Passed:    {res['checks_passed']} / {res['checks_total']} ({res.get('score_pct', 0.0)}%)")
        print(f"Status:           {res['status']}")
        print(f"--------------------------------------------------------")
        for d in res.get("details", []):
            mark = "[PASS]" if d["passed"] else "[FAIL]"
            print(f" {mark} {d['id']:<18} {d['description']:<35} ({d['info']})")
        print(f"========================================================\n")

if __name__ == "__main__":
    main()
