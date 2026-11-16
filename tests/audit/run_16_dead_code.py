"""16 Dead Code and Placeholders Audit Runner.

Scans the Pentesa codebase for TODO, FIXME, XXX, NotImplementedError, placeholder
returns, and mock routes. Classifies findings into Severity categories:
- Critical/Functional Hole (P0/P1)
- Medium/Incomplete Edge-case (P2)
- Low/Harmless Technical Debt/Cleanup (P3)
"""

import os
import sys
import re
from typing import List, Dict, Tuple

sys.path.insert(0, os.path.abspath("."))
from tests.audit.evidence_header import format_evidence_header

SCAN_DIRS = ["apps", "services", "packages"]
OUTPUT_PATH = os.path.join("docs", "audit", "evidence", "phase2", "16_dead_code.txt")

PATTERNS = {
    "TODO": re.compile(r"\bTODO\b[:\s]*(.*)", re.IGNORECASE),
    "FIXME": re.compile(r"\bFIXME\b[:\s]*(.*)", re.IGNORECASE),
    "XXX": re.compile(r"\bXXX\b[:\s]*(.*)", re.IGNORECASE),
    "NOT_IMPLEMENTED": re.compile(r"raise\s+NotImplementedError(\(.*\))?", re.IGNORECASE),
    "PASS_STUB": re.compile(r"^\s*pass\s*(#.*)?$"),
    "MOCK_ENDPOINT": re.compile(r"mock|dummy|fake|placeholder", re.IGNORECASE),
}


def classify_finding(finding_type: str, text: str, fpath: str) -> Tuple[str, str]:
    lower_text = text.lower()
    lower_path = fpath.lower()

    if "test" in lower_path:
        return "P3", "Harmless Cleanup (Test Suite Utility / Fixture)"

    if finding_type == "NOT_IMPLEMENTED":
        if "base" in lower_path or "interface" in lower_path or "abstract" in lower_path:
            return "P3", "Abstract Interface / Base Class Protocol Contract"
        return "P1", "Functional Hole (Unhandled NotImplementedError in Production Path)"

    if finding_type == "FIXME":
        if "security" in lower_text or "auth" in lower_text or "token" in lower_text or "leak" in lower_text:
            return "P1", "Security / Integrity Functional Hole"
        return "P2", "Medium Technical Debt (Requires Remediation)"

    if finding_type == "TODO":
        if any(w in lower_text for w in ["security", "auth", "scope", "sanitize", "redact", "leak", "bypass"]):
            return "P1", "Security / Governance Functional Hole"
        if any(w in lower_text for w in ["retry", "timeout", "error", "validate", "rate"]):
            return "P2", "Operational Robustness Gap"
        return "P3", "Harmless Cleanup / Enhancement Backlog"

    if finding_type == "MOCK_ENDPOINT":
        if "api" in lower_path and ("route" in lower_path or "router" in lower_path):
            return "P1", "Functional Hole (Mock / Stub Endpoint in Production API)"
        return "P3", "Harmless Test / Local Diagnostic"

    return "P3", "Harmless Technical Debt"


class Tuple_Class(tuple):
    def __new__(cls, sev, desc):
        return super().__new__(cls, (sev, desc))


def scan_codebase() -> List[Dict]:
    results = []
    for root_dir in SCAN_DIRS:
        for root, dirs, files in os.walk(root_dir):
            if any(skip in root for skip in [".git", "__pycache__", "node_modules", ".pytest_cache", ".venv"]):
                continue
            for file in files:
                if not file.endswith((".py", ".ts", ".tsx", ".js")):
                    continue
                fpath = os.path.join(root, file)
                rel_path = os.path.relpath(fpath, ".")
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for line_num, line in enumerate(f, 1):
                            line_str = line.strip()
                            for ftype, pat in PATTERNS.items():
                                match = pat.search(line_str)
                                if match:
                                    # Filter false positives in comments/prose
                                    if ftype == "MOCK_ENDPOINT" and not any(kw in line_str.lower() for kw in ["mock", "dummy"]):
                                        continue
                                    if ftype == "PASS_STUB" and not (line_str == "pass" or line_str.startswith("pass #")):
                                        continue
                                    
                                    matched_text = match.group(0) if match.groups() else line_str
                                    sev, cat = classify_finding(ftype, line_str, rel_path)
                                    results.append({
                                        "file": rel_path,
                                        "line": line_num,
                                        "type": ftype,
                                        "snippet": line_str,
                                        "severity": sev,
                                        "category": cat
                                    })
                except Exception:
                    continue
    return results


def main():
    print("=== STARTING 16 DEAD CODE & PLACEHOLDERS AUDIT RUNNER ===")
    lines = []
    lines.append("DEAD CODE, UNIMPLEMENTED STUBS & PLACEHOLDER AUDIT")
    lines.append("=" * 70)

    findings = scan_codebase()
    lines.append(f"Total Codebase Hits Scanned: {len(findings)}")

    sev_counts = {"P1": 0, "P2": 0, "P3": 0}
    type_counts = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        type_counts[f["type"]] = type_counts.get(f["type"], 0) + 1

    lines.append("\nBreakdown by Pattern Type:")
    for t, cnt in sorted(type_counts.items()):
        lines.append(f"  - {t:18s}: {cnt:4d}")

    lines.append("\nBreakdown by Audit Severity Classification:")
    lines.append(f"  - P1 (Critical / Functional Hole)       : {sev_counts['P1']:4d}")
    lines.append(f"  - P2 (Operational Robustness Gap)       : {sev_counts['P2']:4d}")
    lines.append(f"  - P3 (Harmless Cleanup / Technical Debt): {sev_counts['P3']:4d}")

    # Detailed listings for P1 and P2
    lines.append("\n" + "=" * 70)
    lines.append("P1 FINDINGS: FUNCTIONAL HOLES & PRODUCTION STUBS")
    lines.append("=" * 70)
    p1s = [f for f in findings if f["severity"] == "P1"]
    if p1s:
        for f in p1s:
            lines.append(f"[{f['type']}] {f['file']}:{f['line']}")
            lines.append(f"  Snippet : {f['snippet']}")
            lines.append(f"  Category: {f['category']}")
    else:
        lines.append("  (None - zero critical functional holes or unhandled NotImplementedError in production routes)")

    lines.append("\n" + "=" * 70)
    lines.append("P2 FINDINGS: OPERATIONAL ROBUSTNESS GAPS")
    lines.append("=" * 70)
    p2s = [f for f in findings if f["severity"] == "P2"]
    if p2s:
        for f in p2s[:30]:  # Cap output at 30 items for brevity
            lines.append(f"[{f['type']}] {f['file']}:{f['line']} -> {f['snippet'][:80]}")
    else:
        lines.append("  (None)")

    lines.append("\n" + "=" * 70)
    lines.append("P3 FINDINGS: SAMPLE HARMLESS TECHNICAL DEBT / CLEANUP")
    lines.append("=" * 70)
    p3s = [f for f in findings if f["severity"] == "P3"]
    lines.append(f"Total P3 technical debt comments: {len(p3s)}")
    for f in p3s[:15]:
        lines.append(f"  - {f['file']}:{f['line']} -> {f['snippet'][:75]}")

    body = "\n".join(lines)
    print(body)
    header = format_evidence_header(command="python -m tests.audit.run_16_dead_code")
    full_output = header + "\n" + body + "\n"

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(full_output)
    print(f"\n[EVIDENCE WRITTEN] Saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
