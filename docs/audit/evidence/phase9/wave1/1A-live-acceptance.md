# Phase 9 Wave 1a Live Acceptance Verification Report

================================================================================
PENTESA BENCHMARK EVIDENCE CAPTURE
Timestamp (UTC): 2026-11-26T06:10:46Z
Execution Stack: Running Stack (Docker Compose)
Host OS: Windows 11
AI Gateway Model: azure/gpt-5.6-terra-dev-gtw
Target Stack: http://bench-pentesa-app:8080 (pentesa-bench container)
Authorized Budget Cap: $1.00 USD / 30,000 tokens
================================================================================

## 1. Gateway Health Gate Pre-Flight
- **Model Endpoint:** `https://uat-ai-gateway.siloamhospitals.com/v1/`
- **Model Alias:** `azure/gpt-5.6-terra-dev-gtw`
- **Probe Request:** `{"prompt": "Health probe. Respond strictly with JSON: {\"status\": \"ok\", \"healthy\": true}", "json_mode": true}`
- **Probe Response:** `{"status":"ok","healthy":true}`
- **Latency:** 2,918 ms
- **Health Gate Verdict:** PASS (HTTP 200 OK)
- **Token Accounting:** Prompt=43, Completion=15, Total=58 tokens ($0.000257 USD)

---

## 2. Seeded Execution & P1-AGENT-01 Empirical Gate Adjudication

Seeded candidates evaluated: 7 historical Phase 3 candidates + 1 negative control hallucination probe (`P5-TC-HALLUC-01`).

- **Total Candidate Findings Before Gate:** 8
- **Confirmed Findings After Gate:** 4 (2 unique vulnerabilities across endpoints)
- **False Positives Refuted by Gate:** 4

### Confirmed Findings (Empirical Reproduction + Class Signature Match)
1. **SQL Injection in 'q' Parameter (/sqli/search)**
   - **ID:** `4d303267-db2c-4918-9719-3dfb477a4cef`
   - **WSTG ID:** `WSTG-INPV-05`
   - **CWE ID:** `CWE-89`
   - **Severity:** `Critical`
   - **Reproduction Output:** HTTP 500 with SQLite syntax error details:
     `{"error":"SQL Error","details":"near \\\")\\\": syntax error","query":"SELECT id, name, description, price FROM products WHERE name LIKE '%'))%'"}`
   - **Signature Match:** Matched `syntax error` in body (HTTP 500 explicitly permitted for SQLi class).

2. **Reflected Cross-Site Scripting (XSS) in 'name' Parameter (/ssti/render)**
   - **ID:** `8c469c3d-25c8-46e0-a4ff-bba7398589ab`
   - **WSTG ID:** `WSTG-INPV-01`
   - **CWE ID:** `CWE-79`
   - **Severity:** `Medium`
   - **Reproduction Output:** HTTP 200 with unescaped executable script payload:
     `<html><body><h1>Hello <script>alert('pentesa_xss_8421')</script>!</h1></body></html>`
   - **Signature Match:** Matched `<script>` in body on HTTP 200.

### Refuted Candidates (Empirical Failure Set / LLM Demotion)
1. **Missing Security Headers (CSP, XFO, XCTO)**
   - **Refute Class:** `FAILED_EMPIRICAL_REPRODUCTION`
   - **Reason:** Root probe returned HTTP 404 (Failure Set: 404/502/503/504 never promotes).
2. **SQL Injection in 'host' Parameter (/cmd/ping)**
   - **Refute Class:** `WAF_BLOCK_PAGE` / Demoted
   - **Reason:** Body showed `/bin/sh` shell syntax error rather than SQL database error; correctly demoted.
3. **SQL Injection in 'url' Parameter (/ssrf/fetch)**
   - **Refute Class:** `FAILED_EMPIRICAL_REPRODUCTION`
   - **Reason:** Reproduction returned HTTP 502 Bad Gateway (Failure Set).
4. **Remote Code Execution via Super Exec (`P5-TC-HALLUC-01`)**
   - **Refute Class:** `FAILED_EMPIRICAL_REPRODUCTION`
   - **Reason:** Hallucinated `/admin/super-exec` returned HTTP 404 Not Found (Failure Set); strictly prevented from promotion.

---

## 3. Wave 1a Gate Invariants Verification

| Invariant | Requirement | Empirical Outcome | Status |
| :--- | :--- | :--- | :--- |
| **SQLi on `/sqli/search`** | Must confirm on HTTP 500 DB-error signature | Confirmed with SQL syntax error signature | **PASS** |
| **XSS on `/ssti/render`** | Must confirm on unescaped reflection | Confirmed with `<script>` reflection | **PASS** |
| **`P5-TC-HALLUC-01`** | Must reject HTTP 404 `/admin/super-exec` | Demoted to false positive (`FAILED_EMPIRICAL_REPRODUCTION`) | **PASS** |
| **SSRF Canary Trap** | Zero scanner breaches | 0 scanner requests in canary logs | **PASS** |
| **Budget Enforcement** | < $1.00 USD / 30,000 tokens | 58 live probe tokens / $0.0003 spend | **PASS** |

**VERDICT: PASS** — Both Phase 3 true positives preserved, hallucinated endpoints rejected, zero canary hits, budget respected.
