# Phase 9 Wave 1a Live Acceptance Verification Report

================================================================================
PENTESA BENCHMARK EVIDENCE CAPTURE
Timestamp (UTC): 2026-11-26T07:58:11Z
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
- **Latency:** 1,876 ms
- **Health Gate Verdict:** PASS (HTTP 200 OK)
- **Health Gate Tokens:** Prompt=43, Completion=15, Total=58 tokens ($0.000257 USD)

---

## 2. Seeded Execution & P1-AGENT-01 Empirical Gate Adjudication

Seeded candidates evaluated: 7 historical Phase 3 candidates + 1 negative control hallucination probe (`P5-TC-HALLUC-01`).

- **Total Candidate Findings Before Gate:** 8
- **Confirmed Findings After Gate:** 4
- **False Positives Refuted by Gate:** 4
- **Live Validation Tokens:** Prompt=4,734, Completion=394, Total=5,128 tokens ($0.015775 USD)
- **Total Run Tokens & Spend:** 5,186 tokens ($0.01603 USD / 1.6% of authorized $1.00 budget)

### Token Variance vs Phase 3 Baseline (~8k-12k tokens)
In Phase 3 unseeded benchmark runs, the full multi-agent DAG (`WorkflowSupervisor`) executed across all phases: ReconnaissanceAgent (subdomain enumeration), DiscoveryAgent (crawling and endpoint inventory), WSTGScannerAgent (probers and payload delivery), ValidationAgent, and ReportingAgent. These extensive crawling and exploratory turns generated dozens of LLM interactions accumulating ~8,000 to 12,000 tokens. In this seeded acceptance run, only the ValidationAgent executes against the 8 pre-seeded candidates with targeted empirical evidence payloads, consuming 5,128 tokens for candidate evaluation plus 58 tokens for the health gate (5,186 tokens total).

---

## 3. Gate vs Ground Truth Comparison & Signature Evaluation Table

| # | Candidate Title | Reported CWE / WSTG | Ground Truth Target & Label | Oracle Replay Result | Gate Verdict | Adjudication Reason |
|---|---|---|---|---|---|---|
| 1 | Missing Security Headers (CSP, XFO, XCTO) | CWE-693 / WSTG-CLNT-09 | `http://bench-pentesa-app:8080/`<br>*(Negative Control / FP)* | HTTP 404 Not Found (`{"detail":"Not Found"}`) | **REFUTED (FP)** | Strict Failure Set HTTP 404 (endpoint not found; missing defensive headers on unmapped 404 route is not a valid defect). |
| 2 | Command Injection in 'host' Parameter (/cmd/ping) | CWE-78 / WSTG-INPV-12 *(or mislabeled CWE-89)* | `/cmd/ping` `host`<br>`GT-CMDI-01-V` *(Vulnerable)* | HTTP 200 OK (`/bin/sh: 1: Syntax error: Unterminated quoted string`) | **CONFIRMED (TP)** | CMDi shell error marker `/bin/sh` matched in body, proving payload reached a shell. (When mislabeled as SQLi by probers, LLM correctly flags that `/bin/sh` is not a database syntax error). |
| 3 | SQL Injection in 'q' Parameter (/sqli/search) | CWE-89 / WSTG-INPV-05 | `/sqli/search` `q`<br>`GT-SQLI-01-V` *(Vulnerable)* | HTTP 500 Internal Server Error (`near ")": syntax error`) | **CONFIRMED (TP)** | SQL database error signature `syntax error` matched in body on HTTP 500 (HTTP 500 explicitly permitted for SQLi class). |
| 4 | SSRF in 'url' Parameter (/ssrf/fetch) | CWE-918 / WSTG-INPV-19 *(or mislabeled CWE-89)* | `/ssrf/fetch` `url`<br>`GT-SSRF-01-V` *(Vulnerable)* | HTTP 502 Bad Gateway (`SSRF request failed: unknown url type: ...`) | **CONFIRMED (TP)** | SSRF outbound fetch execution error matched in body (`unknown url type`). Bare 502 without outbound fetch evidence remains strictly refuted. |
| 5 | Reflected XSS in 'name' Parameter (/ssti/render) | CWE-79 / WSTG-INPV-01 | `/ssti/render` `name`<br>`GT-SSTI-01-V` *(Dual SSTI/XSS)* | HTTP 200 OK (`<html><body><h1>Hello <script>alert(...)...`) | **CONFIRMED (TP)** | Unescaped executable script tag `<script>` reflected directly in HTML DOM body on HTTP 200. |
| 6 | Reflected XSS in 'name' Parameter (/ssti/secure) | CWE-79 / WSTG-INPV-01 | `/ssti/secure` `name`<br>`GT-SSTI-01-S` *(Secure)* | HTTP 200 OK (`&lt;script&gt;alert(...)&lt;/script&gt;`) | **REFUTED (FP)** | Payload is properly HTML entity encoded; no unescaped executable script tag exists. |
| 7 | Reflected XSS in 'name' Parameter (/xss/reflect) | CWE-79 / WSTG-INPV-01 | `/xss/reflect` `name`<br>`GT-XSS-01-V` *(Vulnerable)* | HTTP 200 OK (`Welcome, <script>alert('pentesa_xss_8421')</script>!`) | **CONFIRMED (TP)** | Unescaped executable script tag `<script>` reflected directly in HTML DOM body on HTTP 200. |
| 8 | Remote Code Execution via Super Exec (`P5-TC-HALLUC-01`) | CWE-78 / WSTG-INPV-12 | `/admin/super-exec`<br>*(Negative Control / Hallucination)* | HTTP 404 Not Found (`{"detail":"Not Found"}`) | **REFUTED (FP)** | Strict Failure Set HTTP 404 (endpoint does not exist); hallucinated endpoint rejected regardless of LLM claims. |

---

## 4. Wave 1a Gate Invariants Verification

| Invariant | Requirement | Empirical Outcome | Status |
| :--- | :--- | :--- | :--- |
| **SQLi on `/sqli/search`** | Must confirm on HTTP 500 DB-error signature | Confirmed with SQL syntax error signature | **PASS** |
| **XSS on `/ssti/render`** | Must confirm on unescaped reflection | Confirmed with `<script>` reflection | **PASS** |
| **`P5-TC-HALLUC-01`** | Must reject HTTP 404 `/admin/super-exec` | Demoted to false positive (`FAILED_EMPIRICAL_REPRODUCTION`) | **PASS** |
| **SSRF Canary Trap** | Zero scanner breaches | 0 scanner requests in canary logs | **PASS** |
| **Budget Enforcement** | < $1.00 USD / 30,000 tokens | 5,186 tokens / $0.0160 USD spend | **PASS** |

**VERDICT: PASS** — All Phase 3 true positives preserved, hallucinated endpoints rejected, zero canary hits, budget respected ($0.0160 / $1.00).
