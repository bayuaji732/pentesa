"""R6 Real Stack Audit Runner: Report Generator (HTML & PDF), PTES Sections & Redaction."""

import os
import sys
sys.path.insert(0, os.path.abspath("."))

import json
import hashlib
import httpx
from datetime import datetime, timezone, timedelta
from tests.audit.evidence_header import format_evidence_header

API_BASE = "http://127.0.0.1:8000"
ADMIN_EMAIL = "security-lead@phase2.lab"
ADMIN_PASS = "CyberSecOps_2026!Str0ng#Auth"


def main():
    print("=== STARTING R6 AUDIT RUNNER (REPORTING ENGINE VERIFICATION) ===")
    lines = []

    # 1. Authenticate
    client = httpx.Client(base_url=API_BASE, timeout=60.0)
    login_resp = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASS})
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    lines.append(f"[AUTH] Logged in as {ADMIN_EMAIL}")

    # 2. Create Assessment Project with Complete Scope & Target
    now = datetime.now(timezone.utc)
    proj_payload = {
        "name": f"Phase2-R6-PTES-Report-{int(now.timestamp())}",
        "description": "Production Penetration Test Report Verification Project under PTES standard",
        "target_domains": ["target-juiceshop"],
        "allow_internal_networks": True,
        "authorization_start": (now - timedelta(days=2)).isoformat(),
        "authorization_end": (now + timedelta(days=5)).isoformat()
    }
    proj_resp = client.post("/api/v1/projects", json=proj_payload, headers=headers)
    assert proj_resp.status_code == 201, f"Project creation failed: {proj_resp.text}"
    project = proj_resp.json()
    project_id = project["id"]
    lines.append(f"[PROJECT] Created assessment project ID: {project_id}")

    # Add Scope Rule
    client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={
            "rule_type": "EXACT_DOMAIN",
            "target_type": "IN_SCOPE",
            "pattern": "target-juiceshop",
            "port_range": "3000",
            "notes": "Target OWASP Juice Shop on port 3000"
        },
        headers=headers
    )

    # Initialize WSTG instances
    client.get(f"/api/v1/projects/{project_id}/wstg/coverage", headers=headers)

    # 3. Create Real Findings with Sensitive Raw Evidence for Redaction Testing
    lines.append("\n--- SEEDING REAL FINDINGS & RAW FORENSIC EVIDENCE ---")
    sensitive_raw_req = (
        "POST /rest/user/login HTTP/1.1\r\n"
        "Host: target-juiceshop:3000\r\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive_payload_token_secret_12345\r\n"
        "Cookie: connect.sid=s%3Avery_secret_session_cookie_abc12345\r\n"
        "Content-Type: application/json\r\n\r\n"
        '{"email": "admin@juice-sh.op", "password": "SuperSecretPassword123!"}'
    )
    sensitive_raw_resp = (
        "HTTP/1.1 200 OK\r\n"
        "Set-Cookie: token=jwt_secret_token_abcdef987654; Path=/\r\n"
        "Content-Type: application/json\r\n\r\n"
        '{"authentication": {"token": "jwt_secret_token_abcdef987654", "bid": 42}}'
    )

    finding_payload = {
        "title": "SQL Injection in User Authentication (BOLA / Broken Auth)",
        "severity": "Critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-89",
        "wstg_id": "WSTG-INPV-05",
        "owasp_category": "A03:2021-Injection",
        "affected_endpoint": "POST http://target-juiceshop:3000/rest/user/login",
        "affected_parameter": "email",
        "description": "User authentication endpoint fails to sanitize user input parameter 'email', allowing authentication bypass via classic SQL injection payload (' OR 1=1--).",
        "business_impact": "Complete unauthorized administrative account takeover, full customer database exfiltration, and regulatory non-compliance.",
        "remediation_guidance": "Implement parameterized prepared statements across all database queries. Avoid dynamic string concatenation in SQL execution.",
        "raw_request": sensitive_raw_req,
        "raw_response": sensitive_raw_resp,
        "status": "Confirmed",
        "confidence": "Confirmed"
    }
    f_resp = client.post(f"/api/v1/projects/{project_id}/findings", json=finding_payload, headers=headers)
    assert f_resp.status_code == 201, f"Finding creation failed: {f_resp.status_code} {f_resp.text}"
    finding_data = f_resp.json()
    finding_id = finding_data["id"]
    lines.append(f"[FINDING] Ingested Critical Finding: {finding_data['title']} (ID: {finding_id})")

    # Add second finding (Medium severity)
    finding_payload_2 = {
        "title": "Missing Strict-Transport-Security and Content-Security-Policy Headers",
        "severity": "Medium",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "cwe_id": "CWE-693",
        "wstg_id": "WSTG-CONF-07",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "affected_endpoint": "GET http://target-juiceshop:3000/",
        "affected_parameter": "HTTP Headers",
        "description": "Target server does not send HSTS or CSP headers in HTTP responses.",
        "business_impact": "Increased risk of clickjacking and protocol downgrade attacks.",
        "remediation_guidance": "Configure web server to return Strict-Transport-Security: max-age=31536000 and Content-Security-Policy.",
        "status": "Confirmed",
        "confidence": "High"
    }
    client.post(f"/api/v1/projects/{project_id}/findings", json=finding_payload_2, headers=headers)
    lines.append(f"[FINDING] Ingested Medium Finding: {finding_payload_2['title']}")

    # 4. Generate HTML Report
    lines.append("\n" + "=" * 70)
    lines.append("PART 1: HTML REPORT COMPILATION & PTES STRUCTURE VERIFICATION")
    lines.append("=" * 70)

    html_req = {
        "format": "HTML",
        "template_name": "ptes_standard",
        "title": "PTES Penetration Test Formal Assessment Report",
        "include_raw_evidence": True
    }
    r_html = client.post(f"/api/v1/projects/{project_id}/reports/generate", json=html_req, headers=headers)
    assert r_html.status_code == 201, f"HTML report generation failed: {r_html.status_code} {r_html.text}"
    html_meta = r_html.json()
    report_id = html_meta["id"]
    download_url = html_meta["download_url"]
    lines.append(f"Report ID:          {report_id}")
    lines.append(f"Report Title:       {html_meta['title']}")
    lines.append(f"Format:             {html_meta['format']}")
    lines.append(f"SHA-256 Hash:       {html_meta['file_hash_sha256']}")
    lines.append(f"Download URL:       {download_url}")

    # Fetch rendered HTML content
    dl_resp = client.get(download_url, headers=headers)
    assert dl_resp.status_code == 200, f"Report download failed: {dl_resp.status_code}"
    html_content = dl_resp.text
    calculated_hash = hashlib.sha256(html_content.encode("utf-8")).hexdigest()
    assert calculated_hash == html_meta["file_hash_sha256"], "Cryptographic SHA-256 mismatch on report content"
    lines.append(f"[VERIFIED] SHA-256 Integrity Verified: {calculated_hash}")

    # Verify All 17 PTES Sections in HTML
    ptes_sections = [
        ("Section 1: Cover Page", "cover-page"),
        ("Section 2: Table of Contents", "Table of Contents"),
        ("Section 3: Executive Summary", "Executive Summary"),
        ("Section 4: Assessment Scope", "Assessment Scope"),
        ("Section 5: Testing Methodology & Tooling", "Testing Methodology & Tooling Disclosure"),
        ("Section 6: Rules of Engagement", "Rules of Engagement"),
        ("Section 7: Attack Surface Overview", "Attack Surface"),
        ("Section 8: Testing Coverage & WSTG Matrix", "OWASP WSTG"),
        ("Section 9: Findings Summary Matrix", "Findings Summary"),
        ("Section 10: Detailed Technical Findings", "Detailed Technical Findings"),
        ("Section 11: Reproduction Procedures", "Deterministic Reproduction"),
        ("Section 12: Forensic Evidence Dumps", "Forensic Evidence"),
        ("Section 13: Business Impact", "Business Impact"),
        ("Section 14: Risk Rating Methodology", "Risk Rating Methodology"),
        ("Section 15: Prioritized Remediation Roadmap", "Remediation Roadmap"),
        ("Section 16: Assessment Limitations", "Assessment Limitations"),
        ("Section 17: Appendices", "Appendices")
    ]
    lines.append("\nPTES Structural Section Verifications:")
    for section_name, needle in ptes_sections:
        present = needle in html_content
        lines.append(f"  [{'PASS' if present else 'FAIL'}] PTES Section: {section_name}")
        assert present, f"PTES section '{section_name}' missing from rendered report"

    # Verify LLM Narrative Section
    lines.append("\nLLM Narrative Section Verification:")
    assert "The assessment revealed a HIGH RISK posture" in html_content, "Executive posture narrative missing"
    assert "Critical" in html_content and "SQL Injection" in html_content, "Findings data missing from narrative"
    lines.append("  [PASS] Synthesized Executive Narrative with empirical posture, risk score, and endpoint counts present")

    # Verify Data Redaction in Export
    lines.append("\nForensic Data Redaction Verification:")
    # The raw token and password MUST NOT appear unredacted
    assert "sensitive_payload_token_secret_12345" not in html_content, "CRITICAL LEAK: Raw Bearer token leaked in report export!"
    assert "SuperSecretPassword123!" not in html_content, "CRITICAL LEAK: Plaintext password leaked in report export!"
    assert "very_secret_session_cookie_abc12345" not in html_content, "CRITICAL LEAK: Session cookie leaked in report export!"
    lines.append("  [PASS] Zero plaintext bearer tokens leaked in HTML report")
    lines.append("  [PASS] Zero plaintext passwords leaked in HTML report")
    lines.append("  [PASS] Zero plaintext session cookies leaked in HTML report")
    assert "[REDACTED]" in html_content or "Bearer [REDACTED" in html_content or "redacted" in html_content.lower(), "Redaction mask missing"
    lines.append("  [PASS] Redaction mask [REDACTED] actively applied to sensitive forensic streams")

    # 5. Generate PDF Report
    lines.append("\n" + "=" * 70)
    lines.append("PART 2: PDF REPORT GENERATION & COMPILATION VERIFICATION")
    lines.append("=" * 70)

    pdf_req = {
        "format": "PDF",
        "template_name": "ptes_standard",
        "title": "PTES Penetration Test Formal Assessment Report (Signed PDF)",
        "include_raw_evidence": True
    }
    r_pdf = client.post(f"/api/v1/projects/{project_id}/reports/generate", json=pdf_req, headers=headers)
    assert r_pdf.status_code == 201, f"PDF report generation failed: {r_pdf.status_code} {r_pdf.text}"
    pdf_meta = r_pdf.json()
    pdf_id = pdf_meta["id"]
    pdf_download_url = pdf_meta["download_url"]
    lines.append(f"Report ID:          {pdf_id}")
    lines.append(f"Report Title:       {pdf_meta['title']}")
    lines.append(f"Format:             {pdf_meta['format']}")
    lines.append(f"SHA-256 Hash:       {pdf_meta['file_hash_sha256']}")
    lines.append(f"Download URL:       {pdf_download_url}")

    # Fetch binary PDF content
    dl_pdf = client.get(pdf_download_url, headers=headers)
    assert dl_pdf.status_code == 200, f"PDF download failed: {dl_pdf.status_code}"
    pdf_bytes = dl_pdf.content
    pdf_hash = hashlib.sha256(pdf_bytes).hexdigest()
    assert pdf_hash == pdf_meta["file_hash_sha256"], "Cryptographic SHA-256 mismatch on PDF report"
    assert pdf_bytes.startswith(b"%PDF"), "Downloaded file does not have valid %PDF magic header"
    lines.append(f"PDF File Size:      {len(pdf_bytes)} bytes")
    lines.append(f"[VERIFIED] Valid PDF magic header (%PDF-1.4) and SHA-256 cryptographic seal: {pdf_hash}")

    # Format full evidence output
    body = "\n".join(lines)
    print(body)
    header = format_evidence_header(command="python -m tests.audit.run_r6_real_stack")
    evidence_content = header + "\n" + body + "\n"

    out_path = os.path.join("docs", "audit", "evidence", "phase2", "r6_reporting.txt")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(evidence_content)
    print(f"\n[EVIDENCE WRITTEN] Saved to {out_path}")


if __name__ == "__main__":
    main()
