# Pentesa — Security & Operational Risk Matrix

> **Document Identifier:** PENTESA-AUDIT-04-RISK-MATRIX-V1.1  
> **Audit Phase:** Phase 2 — Functional & Integration Testing (Part 2B Conclusion)  
> **Auditors:** Independent Principal Software Architect, Senior AppSec Engineer, Senior Penetration Tester, Security QA Engineer  
> **Date:** November 2026  
> **Status:** Active / Evaluated Post-Part 2B  

---

## 1. Risk Scoring Methodology

Risks are quantified using standard Likelihood vs. Impact scoring (1 to 5 scale):
- **Risk Score = Likelihood $\times$ Impact** (Range: 1–25)
  - **Critical (20–25):** Immediate threat to engagement safety, boundary breach, or unauthorized targets.
  - **High (12–19):** Significant security flaw, hardcoded credential/key compromise, or compliance violation.
  - **Medium (6–11):** Functional capability gap, degraded observability, or non-graceful service degradation.
  - **Low (1–5):** Minor operational friction or documentation drift.

---

## 2. Risk Evaluation Matrix

| Risk ID | Title | Threat Source | Likelihood (1-5) | Impact (1-5) | Risk Score | Risk Tier | Mitigation Strategy |
|---|---|---|:---:|:---:|:---:|:---:|---|
| **RSK-01** | Unauthorized Out-of-Scope Target Attack via Subprocess Redirects (NI-03) | Malicious or in-scope redirect to external IP/domain | 5 | 5 | **25** | **CRITICAL** | Quarantine tool binaries to lab-only; enforce Layer-2 Egress Proxy (FIX-06 / FIX-08 / Phase 9). |
| **RSK-02** | Python HTTP Client Scope Breach on 302 Redirect (SEC-RED-01) | HTTP redirects followed automatically by `httpx` | 5 | 5 | **25** | **CRITICAL** | Implement bounded 5-hop redirect loop with per-hop scope & DNS pinning (FIX-01). |
| **RSK-03** | Credential Decryption via Static Master Key (SEC-KEY-01) | Hardcoded repository fallback encryption key | 4 | 5 | **20** | **CRITICAL** | Fail-closed startup requiring $\ge 32$-byte non-default encryption key (FIX-02). |
| **RSK-04** | Default Admin Account Takeover in Production (SEC-PWD-01) | Unconditional seeding of `admin@example.com` / `Admin123!Secure` | 4 | 4 | **16** | **HIGH** | Remove unconditional seeding; require bootstrap credentials or dev flag (FIX-03). |
| **RSK-05** | Silent Mock LLM Execution in Non-Test Environments (AGT-MOCK-01) | Misconfigured `PENTESA_ENV` allowing simulated scans | 3 | 4 | **12** | **HIGH** | Forbid mock provider outside `PENTESA_ENV=test`; fail-closed startup (FIX-04). |
| **RSK-06** | Test Execution Stoppage from Missing Scanner Assets (TOOL-TMPL-01 / TOOL-WORD-01) | Missing templates or wordlists inside Docker container | 4 | 3 | **12** | **HIGH** | Bake pinned templates and SecLists wordlists directly into Docker image (FIX-05). |
| **RSK-07** | Pipeline Hang / Unhandled 500 on LLM Outage (AGT-LLM-01) | AI Gateway disconnect or CloudFront origin failure | 4 | 3 | **12** | **HIGH** | Graceful exception handling returning 502/503 and marking workflow `FAILED` (FIX-07). |
| **RSK-08** | Incomplete Attack Surface Coverage on Modern SPAs (DISCO-SPA-01) | Crawler/fingerprinter inability to analyze client-side DOM/headers | 3 | 2 | **6** | **MEDIUM** | Extend fingerprinting rules to analyze DOM mount elements and script bundles (Phase 9). |
| **RSK-09** | Plaintext Credential Exposure in Forensic Reproduction cURL Artifacts (SEC-RED-02) | Unredacted POST request body in cURL generator and finding ingestion | 4 | 4 | **16** | **HIGH** | Sanitize and redact sensitive request/response body fields with `redact_raw_stream()` (b65eaf3 / FIX-10). |
| **RSK-10** | SPA Catch-All Baseline False-Positive Inflation (TOOL-FP-01) | Express/NodeJS catch-all routing fallback returning 200 OK for all paths | 5 | 3 | **15** | **HIGH** | Multi-probe soft-404 baseline hashing, ffuf `-ac` auto-calibration, and multi-condition Nuclei matchers (FIX-11 / FIX-12). |

---

## 3. Residual Risk Post-Part 2A & 2B Fixes

All designated Part 2A and Part 2B remediations (FIX-01 through FIX-12 / SEC-RED-02) have been implemented, verified on the running PostgreSQL 16 stack, regression-tested, and audited with zero unhashed artifacts.

| Risk ID | Title | Initial Score | Post-Fix Score | Residual Tier | Status | Verification Evidence |
|---|---|:---:|:---:|:---:|---|---|
| **RSK-01** | Tool Subprocess Redirect Egress (NI-03) | **25** (Crit) | **10** (Med) | Lab-Only | Hardened (`5cede9b`) | Flag injection & redirect flags stripped; fail-closed lab guardrail added (`aac2f64`); 0 canary hits observed; tool binaries marked lab-only until Phase 9 Layer-2 egress proxy. |
| **RSK-02** | Python Client Scope Bypass on 302 (SEC-RED-01) | **25** (Crit) | **2** (Low) | Resolved | Closed (`e888ab1`) | Bounded manual redirect loop (max 5 hops) with scope checks, DNS pinning, header stripping; `tests/unit/test_safe_redirect_loop.py` (4/4 pass). |
| **RSK-03** | Master Key Fallback Literal (SEC-KEY-01) | **20** (Crit) | **1** (Low) | Resolved | Closed (`b3c1e1b`) | Fail-closed startup, static fallback removed, $\ge 32$-byte entropy required; `tests/unit/test_encryption_key_security.py` (6/6 pass). |
| **RSK-04** | Default Admin & DB Credentials (SEC-PWD-01) | **16** (High) | **2** (Low) | Resolved | Closed (`a709a7c`) | No unconditional admin seeding; production DB password complexity validated; `tests/audit/run_r1_real_stack.py` (`docs/audit/evidence/phase2/r1_default_admin.txt`). |
| **RSK-05** | Mock LLM in Non-Test Environments (AGT-MOCK-01) | **12** (High) | **2** (Low) | Resolved | Closed (`96a9fe4`) | `MockLLMProvider` refused outside `PENTESA_ENV=test`; simulated findings excluded from reports; `tests/audit/run_14_error_recovery.py` (`docs/audit/evidence/phase2/14_error_recovery.txt`). |
| **RSK-06** | Missing Security Tool Assets (TOOL-TMPL/WORD-01) | **12** (High) | **2** (Low) | Resolved | Closed (`7e80f6d` / `220dd98`) | Pinned Nuclei templates & SecLists `common.txt` baked in Docker images; `docs/audit/evidence/phase2/r4_missing_binary.txt`. |
| **RSK-07** | Hang / 500 on LLM Gateway Failure (AGT-LLM-01) | **12** (High) | **3** (Low) | Resolved | Closed (`561d8e7`) | Upstream outages mapped to HTTP 502/503; workflow marked `FAILED` with `failure_reason`; `tests/audit/run_14_error_recovery.py` (`docs/audit/evidence/phase2/14_error_recovery.txt`). |
| **RSK-08** | Incomplete SPA Coverage (DISCO-SPA-01) | **6** (Med) | **6** (Med) | Open (Deferred) | Phase 9 | Client-side DOM parsing scheduled for Phase 9 architecture roadmap. |
| **RSK-09** | Plaintext Credentials in Reproduction cURL (SEC-RED-02) | **16** (High) | **2** (Low) | Resolved | Closed (`b65eaf3`) | Request body credentials masked with `[REDACTED]`; `tests/audit/run_r6_real_stack.py` (`docs/audit/evidence/phase2/r6_reporting.txt`). |
| **RSK-10** | SPA Catch-All False-Positive Inflation (TOOL-FP-01) | **15** (High) | **2** (Low) | Resolved | Closed (`7987286` / `fbb2e31`) | Multi-probe soft-404 baseline calibration + content signature matchers; 0 false positives on catch-all test servers. |
