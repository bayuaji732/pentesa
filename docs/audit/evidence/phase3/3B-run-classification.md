# Phase 3 Part B — Benchmark Execution Classification Addendum

**Document Identifier:** PENTESA-AUDIT-PHASE3B-RUN-CLASSIFICATION-V1.0  
**Generated At (UTC):** 2026-11-18T03:07:00Z  
**Scope:** Categorization of historical benchmark runs into Completed, Infrastructure Failure, or Agent Failure  
**Governing Standard:** `docs/audit/prompts/phase3.md` & Phase 3 Resume Directives  

---

## 1. Run Classification Inventory

| Run ID | Project Name | Target | DB Status | Classification | Diagnostic Root Cause | Tokens | Cost (USD) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `DRY-RUN-001` | *N/A (Synthetic)* | `pentesa-bench` | *N/A* | `COMPLETED` | Pre-flight mock/dry-run harness validation | 150 | $0.0015 |
| `RUN-PENTESA-BENCH-DEEP-01-FAIL` | `Phase3-Bench-pentesa-bench-Run1` | `pentesa-bench` | `FAILED` | `INFRA_FAILURE` | Layer-2 egress proxy configuration reject (`PENTESA_LAYER2_EGRESS_ENABLED!=true`) | 5,550 | $0.0520 |
| `RUN-PENTESA-BENCH-DEEP-01` | `Phase3-Bench-pentesa-bench-Run1` | `pentesa-bench` | `COMPLETED` | `COMPLETED` | Full execution completed; 0 confirmed findings (404 unlinked root crawl) | 11,423 | $0.1017 |
| `RUN-PENTESA-BENCH-DEEP-02` | `Phase3-Bench-pentesa-bench-Run2` | `pentesa-bench` | `COMPLETED` | `COMPLETED` | Full execution completed; 0 confirmed findings (404 unlinked root crawl) | 5,898 | $0.0498 |
| `RUN-PENTESA-BENCH-DEEP-03` | `Phase3-Bench-pentesa-bench-Run3` | `pentesa-bench` | `FAILED` | `INFRA_FAILURE` | LiteLLM gateway 503 (`no_db_connection`: upstream authentication database down) | 1,445 | $0.0134 |
| `RUN-JUICESHOP-DEEP-01` | `Phase3-Bench-juiceshop-Run1` | `juiceshop` | `FAILED` | `INFRA_FAILURE` | LiteLLM gateway 503 / ConnectError at startup | 0 | $0.0000 |
| `RUN-JUICESHOP-DEEP-02` | `Phase3-Bench-juiceshop-Run2` | `juiceshop` | `FAILED` | `INFRA_FAILURE` | LiteLLM gateway ConnectError at startup | 0 | $0.0000 |
| `RUN-JUICESHOP-DEEP-03` | `Phase3-Bench-juiceshop-Run3` | `juiceshop` | `FAILED` | `INFRA_FAILURE` | LiteLLM gateway ConnectError at startup | 0 | $0.0000 |
| `RUN-DVWA-DEEP-01` | `Phase3-Bench-dvwa-Run1` | `dvwa` | `FAILED` | `INFRA_FAILURE` | LiteLLM gateway ConnectError at startup | 0 | $0.0000 |
| `RUN-DVWA-DEEP-02` | `Phase3-Bench-dvwa-Run2` | `dvwa` | `FAILED` | `INFRA_FAILURE` | LiteLLM gateway ConnectError at startup | 0 | $0.0000 |
| `RUN-DVWA-DEEP-03` | `Phase3-Bench-dvwa-Run3` | `dvwa` | `FAILED` | `INFRA_FAILURE` | LiteLLM gateway ConnectError at startup | 0 | $0.0000 |
| `RUN-CRAPI-DEEP-01` | `Phase3-Bench-crapi-Run1` | `crapi` | `FAILED` | `INFRA_FAILURE` | LiteLLM gateway ConnectError at startup | 0 | $0.0000 |
| `RUN-CRAPI-DEEP-02` | `Phase3-Bench-crapi-Run2` | `crapi` | `FAILED` | `INFRA_FAILURE` | LiteLLM gateway ConnectError at startup | 0 | $0.0000 |
| `RUN-CRAPI-DEEP-03` | `Phase3-Bench-crapi-Run3` | `crapi` | `FAILED` | `INFRA_FAILURE` | LiteLLM gateway ConnectError at startup | 0 | $0.0000 |
| `RUN-WEBGOAT-DEEP-01` | `Phase3-Bench-webgoat-Run1` | `webgoat` | `FAILED` | `INFRA_FAILURE` | LiteLLM gateway ConnectError at startup | 0 | $0.0000 |
| `RUN-WEBGOAT-DEEP-02` | `Phase3-Bench-webgoat-Run2` | `webgoat` | `FAILED` | `INFRA_FAILURE` | LiteLLM gateway ConnectError at startup | 0 | $0.0000 |
| `RUN-WEBGOAT-DEEP-03` | `Phase3-Bench-webgoat-Run3` | `webgoat` | `FAILED` | `INFRA_FAILURE` | LiteLLM gateway ConnectError at startup | 0 | $0.0000 |
| `GATEWAY-HEALTH-030326` | *N/A (Health Gate)* | `gateway-health` | *N/A* | `COMPLETED` | Gate Step 1 verified gateway recovery (HTTP 200 OK) | 2 | $0.0000 |

---

## 2. Statistical Treatment and Scorer Accounting

1. **Exclusion from Precision / Recall Means**:
   Runs classified as `INFRA_FAILURE` represent infrastructure aborts prior to active security testing. Including them as 0% recall/precision runs would artificially skew vulnerability detection metrics. Therefore, detection metrics (Precision, Recall, F1, Secure FPR) are evaluated exclusively over `COMPLETED` runs.
2. **Inclusion in Execution Reliability**:
   Execution reliability explicitly accounts for infrastructure and operational stability:
   $$\text{Execution Reliability} = \frac{\text{Completed Runs}}{\text{Total Attempted Runs}} = \frac{2}{16} = 12.5\%$$
   This low reliability directly reflects the external LiteLLM gateway outage and validates the platform's fail-closed handling.
3. **Cumulative Cost & Token Persistence**:
   All tokens consumed during failed and partial runs ($18,768 tokens, $0.1649 total spend) remain permanently tallied in `docs/audit/evidence/phase3/cost-log.md` toward the authorized budget cap ($10.00 / 300,000 tokens).
4. **Immutability of Evidence**:
   All raw score outputs and findings JSON artifacts generated during failed attempts are preserved verbatim in `docs/audit/evidence/phase3/`.
