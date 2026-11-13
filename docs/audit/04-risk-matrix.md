# Pentesa — Security & Operational Risk Matrix

> **Document Identifier:** PENTESA-AUDIT-04-RISK-MATRIX-V1.0  
> **Audit Phase:** Phase 2 — Functional & Integration Testing (Part 2A Execution)  
> **Auditors:** Independent Principal Software Architect, Senior AppSec Engineer, Senior Penetration Tester, Security QA Engineer  
> **Date:** November 2026  
> **Status:** Active / Evaluated  

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
| **RSK-01** | Unauthorized Out-of-Scope Target Attack via Subprocess Redirects (NI-03) | Malicious or in-scope redirect to external IP/domain | 5 | 5 | **25** | **CRITICAL** | Quarantine tool binaries to lab-only; enforce Layer-2 Egress Proxy (FIX-06 / Phase 3). |
| **RSK-02** | Python HTTP Client Scope Breach on 302 Redirect (SEC-RED-01) | HTTP redirects followed automatically by `httpx` | 5 | 5 | **25** | **CRITICAL** | Implement bounded 5-hop redirect loop with per-hop scope & DNS pinning (FIX-01). |
| **RSK-03** | Credential Decryption via Static Master Key (SEC-KEY-01) | Hardcoded repository fallback encryption key | 4 | 5 | **20** | **CRITICAL** | Fail-closed startup requiring $\ge 32$-byte non-default encryption key (FIX-02). |
| **RSK-04** | Default Admin Account Takeover in Production (SEC-PWD-01) | Unconditional seeding of `admin@example.com` / `Admin123!Secure` | 4 | 4 | **16** | **HIGH** | Remove unconditional seeding; require bootstrap credentials or dev flag (FIX-03). |
| **RSK-05** | Silent Mock LLM Execution in Non-Test Environments (AGT-MOCK-01) | Misconfigured `PENTESA_ENV` allowing simulated scans | 3 | 4 | **12** | **HIGH** | Forbid mock provider outside `PENTESA_ENV=test`; fail-closed startup (FIX-04). |
| **RSK-06** | Test Execution Stoppage from Missing Scanner Assets (TOOL-TMPL-01 / TOOL-WORD-01) | Missing templates or wordlists inside Docker container | 4 | 3 | **12** | **HIGH** | Bake pinned templates and SecLists wordlists directly into Docker image (FIX-05). |
| **RSK-07** | Pipeline Hang / Unhandled 500 on LLM Outage (AGT-LLM-01) | AI Gateway disconnect or CloudFront origin failure | 4 | 3 | **12** | **HIGH** | Graceful exception handling returning 502/503 and marking workflow `FAILED` (FIX-07). |
| **RSK-08** | Incomplete Attack Surface Coverage on Modern SPAs (DISCO-SPA-01) | Crawler/fingerprinter inability to analyze client-side DOM/headers | 3 | 2 | **6** | **MEDIUM** | Extend fingerprinting rules to analyze DOM mount elements and script bundles (Phase 3). |

---

## 3. Residual Risk Post-Part 2A Fixes

Upon successful implementation of Fixes FIX-01 through FIX-07:
1. **RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07** are fully resolved or mitigated to **Low (<5)**.
2. **RSK-01 (NI-03)** remains **High (15)** residual risk in multi-tenant environments without a network egress firewall; mitigated by disallowing redirect-following CLI flags (FIX-06) and designating tool subprocess execution as **Lab-Only** until a full Layer-2 egress proxy container is deployed.
3. **RSK-08** remains **Medium (6)** and is scheduled for Phase 3 exploration.
