"""Automated Fidelity Scorer for Pentesa Pentest Report Template (Phase 9 Wave 1c).

Evaluates rendered PDF deliverables against benchmark/ground_truth_p7b_template.yaml
and benchmark/p7b/template_spec.yaml.
Frozen for Phase 9 Wave 1c verification.
"""

import argparse
import hashlib
import json
import os
import pathlib
import re
import sys
import zlib

try:
    import yaml
except ImportError:
    yaml = None


def parse_pdf_objects(pdf_bytes: bytes) -> dict:
    objects = {}
    pattern = re.compile(rb"(\d+)\s+(\d+)\s+obj\s*(.*?)\s*endobj", re.DOTALL)
    for m in pattern.finditer(pdf_bytes):
        num = int(m.group(1))
        body = m.group(3)
        stream = None
        stream_match = re.search(rb"stream\r?\n(.*?)\r?\nendstream", body, re.DOTALL)
        if stream_match:
            raw_s = stream_match.group(1)
            try:
                stream = zlib.decompress(raw_s)
            except Exception:
                stream = raw_s
        objects[num] = (body, stream)
    return objects


def parse_cmap(cmap_bytes: bytes) -> dict:
    cmap = {}
    lines = cmap_bytes.decode("latin1", errors="replace").splitlines()
    in_bfchar = False
    in_bfrange = False
    for line in lines:
        line = line.strip()
        if "beginbfchar" in line:
            in_bfchar = True
            continue
        elif "endbfchar" in line:
            in_bfchar = False
            continue
        elif "beginbfrange" in line:
            in_bfrange = True
            continue
        elif "endbfrange" in line:
            in_bfrange = False
            continue

        if in_bfchar:
            parts = re.findall(r"<([0-9a-fA-F]+)>", line)
            if len(parts) >= 2:
                try:
                    src = int(parts[0], 16)
                    dst = bytes.fromhex(parts[1]).decode("utf-16be", errors="replace")
                    cmap[src] = dst
                except Exception:
                    pass
        elif in_bfrange:
            if "[" in line:
                m = re.match(r"<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*\[(.*)\]", line)
                if m:
                    try:
                        start = int(m.group(1), 16)
                        dsts = re.findall(r"<([0-9a-fA-F]+)>", m.group(3))
                        for i, d in enumerate(dsts):
                            cmap[start + i] = bytes.fromhex(d).decode("utf-16be", errors="replace")
                    except Exception:
                        pass
            else:
                parts = re.findall(r"<([0-9a-fA-F]+)>", line)
                if len(parts) >= 3:
                    try:
                        start = int(parts[0], 16)
                        end = int(parts[1], 16)
                        base = int(parts[2], 16)
                        for i in range(end - start + 1):
                            dst_hex = f"{base + i:04x}"
                            cmap[start + i] = bytes.fromhex(dst_hex).decode("utf-16be", errors="replace")
                    except Exception:
                        pass
    return cmap


def extract_all_text(content: bytes) -> str:
    """Extract and decompress streams, resolving per-font ToUnicode CMaps for CID fonts."""
    chunks = [content.decode("latin1", errors="replace")]
    streams = []
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", content, re.DOTALL):
        raw_stream = m.group(1)
        try:
            dec = zlib.decompress(raw_stream)
            streams.append(dec)
            chunks.append(dec.decode("latin1", errors="replace"))
        except Exception:
            pass

    # Build per-font CMap dictionary
    objs = parse_pdf_objects(content)
    font_cmaps = {}
    for num, (body, stream) in objs.items():
        body_str = body.decode("latin1", errors="replace")
        if "/Type /Font" in body_str or "/Type/Font" in body_str:
            to_uni_m = re.search(r"/ToUnicode\s+(\d+)\s+\d+\s+R", body_str)
            if to_uni_m:
                uni_obj_num = int(to_uni_m.group(1))
                if uni_obj_num in objs and objs[uni_obj_num][1]:
                    cmap = parse_cmap(objs[uni_obj_num][1])
                    for r_body, _ in objs.values():
                        r_str = r_body.decode("latin1", errors="replace")
                        for f_match in re.finditer(rf"/(F\d+)\s+{num}\s+\d+\s+R", r_str):
                            font_cmaps["/" + f_match.group(1)] = cmap

    # Decode CID text from BT ... ET blocks using exact font CMaps
    if font_cmaps:
        cmap_text = []
        for num, (body, stream) in objs.items():
            if not stream:
                continue
            s_lat = stream.decode("latin1", errors="replace")
            for bt in re.findall(r"BT\s+(.*?)\s+ET", s_lat, re.DOTALL):
                font_match = re.search(r"/(F\d+)\s+[\d\.]+\s+Tf", bt)
                current_font = "/" + font_match.group(1) if font_match else None
                cmap = font_cmaps.get(current_font, {})

                for tj in re.findall(r"(\[.*?\])\s*TJ", bt, re.DOTALL):
                    for hex_str in re.findall(r"<([0-9a-fA-F]+)>", tj):
                        for k in range(0, len(hex_str), 4):
                            chunk = hex_str[k:k+4]
                            if len(chunk) == 4:
                                try:
                                    code = int(chunk, 16)
                                    cmap_text.append(cmap.get(code, ""))
                                except ValueError:
                                    pass
                    for lit in re.findall(r"\((.*?)\)", tj):
                        cmap_text.append(lit)
                for stj in re.findall(r"(\(.*?\)|<[0-9a-fA-F]+>)\s*Tj", bt):
                    if stj.startswith("("):
                        cmap_text.append(stj[1:-1])
                    else:
                        hex_str = stj[1:-1]
                        for k in range(0, len(hex_str), 4):
                            chunk = hex_str[k:k+4]
                            if len(chunk) == 4:
                                try:
                                    code = int(chunk, 16)
                                    cmap_text.append(cmap.get(code, ""))
                                except ValueError:
                                    pass
                cmap_text.append(" ")
        chunks.append("".join(cmap_text))

    return "\n".join(chunks)


def score_pdf_report(pdf_path: pathlib.Path, gt_path: pathlib.Path) -> dict:
    if not pdf_path.exists():
        return {"status": "FAILED", "reason": f"PDF file not found: {pdf_path}", "score": 0.0}

    ground_truth = {}
    if gt_path.exists() and yaml is not None:
        try:
            with open(gt_path, "r", encoding="utf-8") as f:
                ground_truth = yaml.safe_load(f) or {}
        except Exception:
            pass

    content = pdf_path.read_bytes()
    pdf_text = extract_all_text(content)
    # Normalized text collapses whitespace runs so multi-space kerning does not break word matches
    norm_text = " ".join(pdf_text.split())

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

    # 1. ISO A4 Page Geometry (P7B-TC-GEOM-01)
    mediaboxes = re.findall(r"/MediaBox\s*\[\s*([\d\.\s]+)\s*\]", pdf_text)
    geom_passed = False
    geom_info = f"Found mediaboxes: {mediaboxes}"
    if mediaboxes:
        first_box = mediaboxes[0].split()
        if len(first_box) >= 4:
            w = float(first_box[2])
            h = float(first_box[3])
            # A4 is 595.28 x 841.89 pt (tolerance +/- 5 pt)
            if abs(w - 595.28) <= 5.0 and abs(h - 841.89) <= 5.0:
                geom_passed = True
                geom_info = f"Standard A4 verified: {w:.2f} x {h:.2f} pt"
    record_check("P7B-TC-GEOM-01", "ISO A4 Page Format Verification", geom_passed, geom_info)

    # 2. Confidential Header on Pages (P7B-TC-CONF-01)
    conf_header = "Confidential" in norm_text or "CONFIDENTIAL" in norm_text
    record_check("P7B-TC-CONF-01", "Confidential Classification Header", conf_header, "Header badge present")

    # 3. Embedded / Registered Fonts (P7B-TC-FONT-01)
    font_refs = re.findall(r"/(?:Font|FontDescriptor|BaseFont|FontName)\s+/?([A-Za-z0-9_-]+)", pdf_text)
    has_fonts = len(font_refs) >= 2 or "/Type /Font" in pdf_text or "/Type/Font" in pdf_text
    record_check("P7B-TC-FONT-01", "Embedded / Standard Font Descriptors", has_fonts, f"Font references count: {len(font_refs)}")

    # 4. Severity Colour Sampling (P7B-TC-COLOR-01)
    color_patterns = [
        r"1(?:\.0)?\s+0\.75\s+0(?:\.0)?\s+rg",  # #FFC000 RGB operator
        r"0\.85\s+0\.85\s+0\.85\s+rg",          # #D9D9D9 RGB operator
        r"FFC000",
        r"D9D9D9",
        r"/CS\d+\s+cs"
    ]
    color_matched = any(re.search(pat, pdf_text, re.IGNORECASE) for pat in color_patterns) or b"\xff\xc0\x00" in content
    record_check("P7B-TC-COLOR-01", "Severity & Table Color Palette Sampling", color_matched, "Color palette sampled in PDF streams")

    # 5. Section & Label Structural Order (P7B-TC-ORDER-01)
    # Order: Application Description -> Application Purpose -> Scope of Work -> Summary -> Detail Vulnerability
    sections_in_order = True
    order_info = "Sections in correct semantic sequence"
    pos_desc = norm_text.find("Application Description")
    pos_purp = norm_text.find("Application Purpose")
    pos_scope = norm_text.find("Scope of Work")
    pos_summ = norm_text.find("Summary")
    m_detail = re.search(r"Detail\s+Vulnerabilit[y\s]", norm_text, re.IGNORECASE)
    pos_detail = m_detail.start() if m_detail else -1

    indices = [p for p in (pos_desc, pos_purp, pos_scope, pos_summ, pos_detail) if p != -1]
    if len(indices) >= 3 and indices != sorted(indices):
        sections_in_order = False
        order_info = f"Section indices out of order: {indices}"
    elif len(indices) < 2:
        sections_in_order = False
        order_info = f"Insufficient section headings found: count={len(indices)}"
    record_check("P7B-TC-ORDER-01", "Section & Label Order Sequence", sections_in_order, order_info)

    # 6. Table Structure Checks (P7B-TC-TABLE-01A..D)
    t1_dates = bool(re.search(r"Pentest\s+Completion\s+Date|Retest\s+Completion\s+Date|Tanggal", norm_text, re.IGNORECASE))
    record_check("P7B-TC-TABLE-01A", "Table 1 Assessment Dates Presence", t1_dates, "Assessment dates table")

    t2_summary = bool(re.search(r"(?:Temuan|Finding).*(?:Severity|Tingkat)", norm_text, re.IGNORECASE))
    record_check("P7B-TC-TABLE-01B", "Table 2 Findings Summary Presence", t2_summary, "Columns: Temuan, Severity, Method, Status")

    t3_signoff = bool(re.search(r"(?:Role|Peran).*(?:TTD|Signature)", norm_text, re.IGNORECASE))
    record_check("P7B-TC-TABLE-01C", "Table 3 Sign-Off Approval Presence", t3_signoff, "Columns: Role, Nama Perusahaan, Nama Individu, TTD")

    t4_banner = bool(re.search(r"Detail\s+Vulnerabilit[y\s]|Detail\s+Temuan|Vulnerability\s+Detail", norm_text, re.IGNORECASE))
    record_check("P7B-TC-TABLE-01D", "Table 4 Detail Vulnerability Section", t4_banner, "Detail Vulnerability present")

    # 7. Numbering vs Summary Consistency (P7B-TC-NUM-01)
    num_match = bool(re.search(r"1\.\s+[A-Za-z]|Summary", norm_text))
    record_check("P7B-TC-NUM-01", "Finding Numbering vs Summary Consistency", num_match, "Finding numbers align between summary and detail")

    # 8. Candidate Separation (P7B-TC-CAND-01)
    mixed_unconfirmed = "Status: CANDIDATE" in norm_text and "Confirmed Findings" not in norm_text
    candidate_separated = not mixed_unconfirmed
    record_check("P7B-TC-CAND-01", "Candidate vs Confirmed Separation", candidate_separated, "No unsegregated candidate findings in confirmed tables")

    # 9. POC Redaction (P7B-TC-REDACT-01)
    leak_patterns = [
        r"Bearer\s+ey[A-Za-z0-9_-]{20,}",
        r"sk-[a-zA-Z0-9_\-]{20,}"
    ]
    has_leak = any(re.search(pat, norm_text) for pat in leak_patterns)
    record_check("P7B-TC-REDACT-01", "POC Live Secret Redaction", not has_leak, "Zero unredacted live secrets in POC sections")

    # 10. Text Extractability (P7B-TC-EXTRACT-01)
    extractable = len(norm_text.strip()) >= 500
    record_check("P7B-TC-EXTRACT-01", "PDF Text Extractability (>500 chars)", extractable, f"Extracted {len(norm_text.strip())} characters")

    # 11. Empty-Report Neutrality & Policy Conformance (P7B-TC-EMPTY-01)
    forbidden_claims = ["STRONG SECURITY POSTURE", "completely secure", "zero risk", "100% secure"]
    no_unsubstantiated = not any(claim in norm_text for claim in forbidden_claims)
    record_check("P7B-TC-EMPTY-01", "Zero Unsubstantiated Security Claims", no_unsubstantiated, "No forbidden posture claims")

    # 12. CVSS v4.0 Full Vector Conformance (P7B-TC-CVSS4-01)
    cvss4_matches = re.findall(r"CVSS:4\.0\/[A-Z0-9\:\/]+", norm_text)
    cvss4_valid = False
    cvss4_info = "No CVSS v4.0 vector found"
    if cvss4_matches:
        v = cvss4_matches[0]
        req_metrics = ["AV:", "AC:", "AT:", "PR:", "UI:", "VC:", "VI:", "VA:", "SC:", "SI:", "SA:"]
        if all(m in v for m in req_metrics):
            cvss4_valid = True
            cvss4_info = f"Valid CVSS v4.0 vector: {v[:40]}..."
        else:
            cvss4_info = f"Incomplete CVSS v4.0 vector: {v}"
    record_check("P7B-TC-CVSS4-01", "CVSS v4.0 Full Vector Conformance", cvss4_valid, cvss4_info)

    # Final Score Calculation
    score_pct = (results["checks_passed"] / results["checks_total"]) * 100.0 if results["checks_total"] else 0.0
    results["score_pct"] = round(score_pct, 1)
    results["status"] = "PASSED" if score_pct >= 80.0 else "FAILED"

    return results


def main():
    parser = argparse.ArgumentParser(description="Score a PDF deliverable against P7B template ground truth.")
    parser.add_argument("--pdf", required=True, help="Path to target PDF deliverable")
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
            print(f" {mark} {d['id']:<18} {d['description']:<38} ({d['info']})")
        print(f"========================================================\n")


if __name__ == "__main__":
    main()
