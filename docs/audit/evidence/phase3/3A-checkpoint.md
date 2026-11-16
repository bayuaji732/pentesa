# PENTESA AUDIT — PHASE 3 PART A CHECKPOINT

**Phase:** Phase 3 (Pentest Effectiveness Benchmark) — Part A  
**Status:** COMPLETE (PART A ONLY) — WAITING FOR USER APPROVAL  
**Generated At (UTC):** 2026-11-16T09:42:00Z  
**Branch:** main  
**Scope Boundary:** Phase 3 Part A only (Step 0 Gates G1–G3, Benchmark Environment, Ground Truth, Scorer & Mathematical Self-Tests). No benchmark scans have been executed, and Part B / Phase 4 have not been started.

---

## 1. Step 0 Gate Results (G1 – G3)

### Gate G1: Phase 2 Summary & Requirement Traceability Correction
* **Phase 3 Purpose & Scope Clarification:**
  - Corrected `docs/audit/evidence/phase2/phase2-summary.md` and `docs/audit/02-requirement-traceability.md`.
  - Removed misleading phrasing "certified ready" and "live target penetration testing and exploitation validation".
  - Accurately defined Phase 3 as an **isolated Pentest Effectiveness Benchmark** against five designated targets on an internal network.
* **Pytest Test Collection Count:**
  - Replaced the stale count (208) with the authentic pytest collection count:
    - Pre-audit baseline: 208 tests (Part 2A)
    - Post-remediation V-round: 215 tests
    - Post-F-round: 221 tests
    - Post-FIX-10 (`b65eaf3`): **222 tests**
    - Post-G3 Restart Recovery test: **223 tests**
    - Post-Phase 3A Scorer test suite: **239 tests collected** (`pytest --collect-only -q`).
* **Cumulative Token Accounting:**
  - Corrected the cumulative token total from 15,664 to **15,675 tokens** (12 probe + 5,296 + 4,907 + 5,460 tokens across runs L1–L4).
* **Gateway Description & Network Topology:**
  - Removed "Swedish" terminology from all AI gateway descriptions.
  - Truthfully documented Docker network topology:
    - Docker bridge network `internal: false` is required for API/worker containers to reach the enterprise AI gateway (Azure OpenAI / LiteLLM Proxy).
    - Scanner boundary enforcement is maintained at the application layer via target scope validation, manual 5-hop redirect loop with DNS pinning, and lab-only tool guardrails (FIX-08).
* **Evidence Manifest & README Integrity:**
  - Created `docs/audit/evidence/phase2/README.md` defining the machine-captured evidence policy and SHA-256 manifest rules.
  - Created `docs/audit/evidence/phase2/MANIFEST.sha256` covering all 39 Phase 2 evidence files.
  - Verified 100% integrity match: `Verified 39/39 files match MANIFEST.sha256 exactly`.
* **Requirement Traceability Honest Restatement:**
  - Updated `docs/audit/02-requirement-traceability.md`:
    - `FR-DS-06` (Technology Fingerprinting) marked as **Partially Verified** (technology fingerprinter misses SPAs lacking server headers; defect `DISCO-SPA-01` open, deferred to Phase 9 DOM parsing roadmap).
    - `FR-ST-05` (Global and Per-Target Rate Limiting) marked as **Partially Verified** (rate limiting verified for tool runners against targets, but `/http-test` endpoint is unthrottled in API spec and awaits global rate limiting in Phase 9).
    - `NI-05` (Dynamic Skill Execution Runtime Engine) & `NI-09` (Scan Scheduling & Recurring Jobs) marked as **Not Implemented**.
    - Architectural Worker Clarification: The execution worker is **NOT Celery**; it is an in-process asyncio event loop in `services.execution_engine.worker` (Celery is completely absent from the architecture).
    - Final Traceability Breakdown (51 capabilities):
      - **Verified:** 39 (76.47%)
      - **Partially Verified:** 10 (19.61%)
      - **Not Implemented:** 2 (3.92%)
      - **Not Tested:** 0 (0.00%)

---

### Gate G2: Verification of R3 WSTG Plan Counts & SecLists Reconciliation
* **Investigation of `r3_wstg_plan_counts.txt`:**
  - Inspected the raw machine-captured file `docs/audit/evidence/phase2/r3_wstg_plan_counts.txt` (timestamp `2026-11-16T04:15:18Z`).
  - Raw JSON output confirmed:
    - `total_tests`: 106
    - `planned`: 38
    - `not_applicable`: 68
    - `passed`: 0
    - `failed`: 0
    - `needs_review`: 0
    - `overall_coverage`: 64.2%
    - `executed_coverage`: 0.0%
    - `health_score`: 64.2%
  - **Root Cause & Defect Logging:**
    - The summary report `phase2-summary.md` and traceability matrix had copy-pasted draft numbers from pre-remediation commit `efbcd1b` (44 planned, 60 N/A, 2 failed).
    - In reality, R3 tested planning and applicability calculation only; zero tests were executed against targets, explaining why 0 failed.
    - Logged defect **EVID-02** (P1: Evidence Documentation Discrepancy in R3 Coverage Metrics) in `docs/audit/03-defect-register.md`.
* **SecLists `common.txt` Hash Reconciliation:**
  - Upstream raw file at commit `0c618cfc28d1e68811b95c61cc9ab05bc10b0a02`:
    `https://raw.githubusercontent.com/danielmiessler/SecLists/0c618cfc28d1e68811b95c61cc9ab05bc10b0a02/Discovery/Web-Content/common.txt`
  - SHA-256: `47fb86ca6fb3f97e5491161581900d6d99851fb16764eacddf16aa85617c956a`
  - `Dockerfile.api` verifies this exact hash at build time with `sha256sum -c -`.
  - Machine-captured evidence saved to `docs/audit/evidence/phase3/seclists_verification.txt`.
  - The obsolete documentation string `6e8286a...` was identified as a transcription error and corrected.

---

### Gate G3: Restart Recovery (NI-06 Remediation)
* **Problem:**
  - If the API container or worker restarted while a workflow was in `RUNNING` status, executions remained indefinitely orphaned in the database.
* **Remediation Implemented:**
  - Added `recover_interrupted_workflows(session)` in `apps/api/main.py` inside the FastAPI lifespan startup handler:
    - Finds all `WorkflowExecution` records with `status == "RUNNING"`.
    - Updates their `status` to `FAILED`, sets `completed_at` to UTC now, and sets `state_data["failure_reason"] = "interrupted by restart"`.
    - Finds all associated `AgentExecution` records with `status in ("RUNNING", "QUEUED")`.
    - Updates their `status` to `FAILED`, sets `completed_at`, and sets `error_message = "interrupted by restart"`.
* **Unit Regression Test:**
  - Created `tests/unit/test_workflow_restart_recovery.py` verifying fail-closed recovery for running workflows and agent tasks on container boot.
  - Test collected and passed.

---

## 2. Benchmark Environment & Architecture

### Environment Topology
The benchmark environment is defined in `benchmark/docker-compose.bench.yml` and operates on an isolated Docker bridge network:
- **Network:** `pentesa-bench-net`
- **Docker-Level Isolation:** `internal: true` (target containers have zero outbound internet connectivity).
- **Scanner Egress Disclosure (NI-03):**
  - While target containers are strictly isolated by Docker engine networking, the scanner's API/worker containers require an internet route to reach the AI gateway.
  - The application-layer lab-only guardrail (FIX-08) and strict target allowlist are the primary barriers preventing tool subprocesses (nuclei, ffuf) from contacting unapproved destinations until the Layer-2 egress proxy (NI-03) is implemented in Phase 9.
  - **Invariant:** Only targets declared in `benchmark/docker-compose.bench.yml` may ever be scanned.

```
       [ Enterprise AI Gateway ] (Azure OpenAI / LiteLLM Proxy)
                  ▲
                  │ HTTPS (LLM API Calls)
                  │
   ┌──────────────┴────────────────────────────────┐
   │ Pentesa Core Scanner (pentesa-api, worker)    │
   │  - Lab-only tool guardrail (FIX-08)           │
   │  - SSRF-safe redirect resolver                │
   └──────────────┬────────────────────────────────┘
                  │ (HTTP / Assessment Traffic)
                  ▼
═════════════════════════════════════════════════════════════════════
 Docker Network: pentesa-bench-net (internal: true — ZERO OUTBOUND)
═════════════════════════════════════════════════════════════════════
   ├── target-juiceshop   (OWASP Juice Shop v17.1.1)
   ├── target-dvwa        (DVWA latest — PHP / MySQL)
   ├── target-webgoat     (OWASP WebGoat v2023.8 — Java / Spring)
   ├── crapi-*            (crAPI microservices v0.3.0)
   ├── target-pentesa-bench (Pentesa Bench purpose-built service)
   └── bench-canary       (Internal HTTP Canary Sensor on :9099)
```

### How to Bring the Benchmark Up

1. **Build Purpose-Built Benchmark & Canary Images:**
   ```bash
   docker compose -f benchmark/docker-compose.bench.yml build
   ```

2. **Start All Target Containers:**
   ```bash
   docker compose -f benchmark/docker-compose.bench.yml up -d
   ```

3. **Verify Target Health (via container attached to `pentesa-bench-net`):**
   > [!NOTE]
   > Because `pentesa-bench-net` is configured with `internal: true` and zero host ports are mapped to preserve total network isolation, targets are **NOT** reachable via `localhost:<port>` from the host. All verification requests must run inside containers attached to `pentesa-bench-net` using Docker service DNS names.

   ```bash
   # Juice Shop
   docker run --rm --network pentesa-bench-net curlimages/curl:latest -fs http://bench-juiceshop:3000/rest/admin/application-version

   # DVWA
   docker run --rm --network pentesa-bench-net curlimages/curl:latest -fs -I http://bench-dvwa/login.php

   # WebGoat
   docker run --rm --network pentesa-bench-net curlimages/curl:latest -fs -I http://bench-webgoat:8080/WebGoat/login

   # crAPI Web UI
   docker run --rm --network pentesa-bench-net curlimages/curl:latest -fs -I http://bench-crapi-web

   # Pentesa Bench App
   docker run --rm --network pentesa-bench-net curlimages/curl:latest -fs http://bench-pentesa-app:8080/healthz

   # Canary Trap Sensor
   docker run --rm --network pentesa-bench-net curlimages/curl:latest -fs http://bench-canary-sensor:9099/health
   ```

4. **Deterministic State Reset (Between Benchmark Runs):**
   ```bash
   docker run --rm --network pentesa-bench-net curlimages/curl:latest -fs -X POST http://bench-pentesa-app:8080/api/reset
   ```

5. **Teardown & Volume Purge:**
   ```bash
   docker compose -f benchmark/docker-compose.bench.yml down -v
   ```

---

## 3. Pinned Target Image Tags and Digests

| Target Application | Role / Archetype | Image Tag | Image Digest / Build Source |
| :--- | :--- | :--- | :--- |
| **OWASP Juice Shop** | Modern SPA (NodeJS / Express / Angular) | `bkimminich/juice-shop:latest` | `sha256:877fc77b12d72b42e486eb09b6b1711cc56514306d92006b284e7e7cf076a809` |
| **DVWA** | Multi-tier PHP / Apache / MySQL (Vulnerable & Impossible) | `vulnerables/web-dvwa:latest` | `sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7` |
| **OWASP WebGoat** | Enterprise Java / Spring Boot | `webgoat/webgoat:v2023.8` | `sha256:92336340cbe5c0d68f237fb3a12ff357c32bf7a2ea51d957ba4b819f7fb07502` |
| **crAPI Web** | React Frontend for Microservices | `crapi/crapi-web:v0.3.0` | `sha256:d8ff72d3f2ea4169738096fc0b9435bce59fcfa36d653ae89ee5e4ecfdf49a50` |
| **crAPI Identity** | Go Identity & Auth Microservice | `crapi/crapi-identity:v0.3.0` | `sha256:220d9124be330d6768393e87fc42aeb0498a96860d84f938f3fa55b62e49c716` |
| **crAPI Community** | Go / MongoDB Community Microservice | `crapi/crapi-community:v0.3.0` | `sha256:1a1532f80879eb00bb03ec542861eefabde87ca969c3a3dc724b11fba826ee52` |
| **crAPI Workshop** | Java / PostgreSQL Workshop Microservice | `crapi/crapi-workshop:v0.3.0` | `sha256:9058b73fcfcbff995cbfd6990391d1f6634560b73c4fe305ca70678d167eb2e3` |
| **crAPI Database** | PostgreSQL 14 Database for crAPI | `postgres:14-alpine` | `sha256:496e6263cb32b2e1b191c4d924d5462cf3f7b8a7db30be8184ec66c7f6681604` |
| **crAPI MongoDB** | Document Store for crAPI Community | `mongo:4.4.18` | `sha256:1a84f4791da324c4784a86bdf3b5be5e4318721c56ef9cc3340ec9e11ad73e04` |
| **crAPI MailHog** | Local SMTP Test Sensor | `mailhog/mailhog:v1.0.1` | `sha256:8d76a3d4d61c69161f003078390b3459c5d01119b4566412f1e403fa8a381273` |
| **Pentesa Bench** | Purpose-Built Paired Vulnerable/Secure App | `pentesa-bench:latest` | `sha256:0a68b5081041b9ee5884e1e9164993bc24718e391260258701b2555acc170465` |
| **Bench Canary** | Internal SSRF Callback Sensor | `pentesa-canary:latest` | `sha256:d1de4f5330043f65d6387f222875cda5b6fc2bd9d3a11570a0af78e65efb0bb5` |

---

## 4. Ground-Truth Case Counts per Category

The master ground truth matrix (`benchmark/ground_truth.yaml`) defines exactly **30 cases** across **15 categories**:
- **15 Vulnerable Cases** (1 per category)
- **15 Secure Cases** (1 per category)
- **Human Review Requirement:** For business logic cases, the designated expected outcome is `flagged for human review` rather than automated exploitation.

| # | Master Category | Vulnerable Case ID | Target Endpoint | Method / Param | Secure Case ID | Secure Endpoint | Method / Param | WSTG ID | CWE |
| :-: | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | SQL Injection | `GT-SQLI-01-V` | `/rest/products/search` | `GET` `q` | `GT-SQLI-02-S` | `/vulnerabilities/sqli/` | `GET` `id` | `WSTG-INPV-05` | CWE-89 |
| **2** | Cross-Site Scripting (XSS) | `GT-XSS-01-V` | `/rest/products/search` | `GET` `q` | `GT-XSS-02-S` | `/vulnerabilities/xss_r/` | `GET` `name` | `WSTG-INPV-01` | CWE-79 |
| **3** | Server-Side Request Forgery | `GT-SSRF-01-V` | `/ssrf/fetch` | `GET` `url` | `GT-SSRF-02-S` | `/ssrf/secure` | `GET` `url` | `WSTG-INPV-19` | CWE-918 |
| **4** | IDOR / BOLA | `GT-IDOR-01-V` | `/identity/api/v2/vehicle/{vehicleId}/location` | `GET` `vehicleId` | `GT-IDOR-02-S` | `/identity/api/v2/user/myprofile` | `GET` `Authorization` | `WSTG-ATHZ-04` | CWE-639 |
| **5** | Broken Access Control | `GT-BAC-01-V` | `/rest/admin/application-configuration` | `GET` `Authorization` | `GT-BAC-02-S` | `/rest/user/change-password` | `GET` `Authorization` | `WSTG-ATHZ-02` | CWE-285 |
| **6** | Authentication weaknesses | `GT-AUTH-01-V` | `/rest/user/login` | `POST` `email` | `GT-AUTH-02-S` | `/login.php` | `POST` `password` | `WSTG-ATHN-02` | CWE-287 |
| **7** | JWT weaknesses | `GT-JWT-01-V` | `/jwt/profile` | `GET` `Authorization` | `GT-JWT-02-S` | `/jwt/secure` | `GET` `Authorization` | `WSTG-SESS-10` | CWE-347 |
| **8** | File upload vulnerabilities | `GT-UPLD-01-V` | `/upload/file` | `POST` `file` | `GT-UPLD-02-S` | `/upload/secure` | `POST` `file` | `WSTG-BUSL-08` | CWE-434 |
| **9** | Path traversal | `GT-TRAV-01-V` | `/files/read` | `GET` `filename` | `GT-TRAV-02-S` | `/files/secure` | `GET` `filename` | `WSTG-FILE-01` | CWE-22 |
| **10** | Command injection | `GT-CMDI-01-V` | `/cmd/ping` | `GET` `host` | `GT-CMDI-02-S` | `/cmd/secure` | `GET` `host` | `WSTG-INPV-12` | CWE-78 |
| **11** | SSTI | `GT-SSTI-01-V` | `/ssti/render` | `GET` `name` | `GT-SSTI-02-S` | `/ssti/secure` | `GET` `name` | `WSTG-INPV-18` | CWE-1336 |
| **12** | XXE | `GT-XXE-01-V` | `/xxe/parse` | `POST` `body` | `GT-XXE-02-S` | `/xxe/secure` | `POST` `body` | `WSTG-INPV-07` | CWE-611 |
| **13** | API security weaknesses | `GT-APIS-01-V` | `/workshop/api/shop/orders/all` | `GET` `Authorization` | `GT-APIS-02-S` | `/identity/api/auth/v2/check-otp` | `POST` `otp` | `WSTG-APIT-01` | CWE-213 |
| **14** | Race conditions | `GT-RACE-01-V` | `/race/coupon` | `POST` `coupon_code` | `GT-RACE-02-S` | `/race/secure` | `POST` `coupon_code` | `WSTG-BUSL-04` | CWE-362 |
| **15** | Business logic vulnerabilities | `GT-BUSL-01-V` | `/order/checkout` | `POST` `client_price` | `GT-BUSL-02-S` | `/order/secure` | `POST` `client_price` | `WSTG-BUSL-01` | CWE-840 |

**Totals:** 15 vulnerable cases, 15 secure cases = **30 total test cases**.

---

## 5. SHA-256 of `ground_truth.yaml`

```text
b7ce1b48034cc75d15ac0276ad110a62231c4ec4bc3e081655f3fab05dc3683c
```

*Verification Command:*
```bash
python -c "import hashlib; print(hashlib.sha256(open('benchmark/ground_truth.yaml', 'rb').read()).hexdigest())"
```

---

## 6. Scorer Self-Test Results & Mathematical Proofs

Unit tests and CLI runner tests were executed using synthetic findings (`tests/fixtures/synthetic_benchmark_findings.json`) before any real benchmark scans were conducted.

### 6.1 Unit Test Suite Execution (`tests/unit/test_benchmark_scorer.py`)
```text
============================= test session starts =============================
platform win32 -- Python 3.12.13, pytest-9.2.0, pluggy-1.7.0
plugins: anyio-4.16.0, asyncio-1.4.1.post1, cov-7.1.0
collected 16 items

tests/unit/test_benchmark_scorer.py::test_normalize_endpoint PASSED      [  6%]
tests/unit/test_benchmark_scorer.py::test_normalize_method PASSED        [ 12%]
tests/unit/test_benchmark_scorer.py::test_normalize_parameter PASSED     [ 18%]
tests/unit/test_benchmark_scorer.py::test_extract_cwe_id PASSED          [ 25%]
tests/unit/test_benchmark_scorer.py::test_extract_wstg_category PASSED   [ 31%]
tests/unit/test_benchmark_scorer.py::test_evaluate_evidence_completeness_perfect PASSED [ 37%]
tests/unit/test_benchmark_scorer.py::test_evaluate_evidence_completeness_missing_fields PASSED [ 43%]
tests/unit/test_benchmark_scorer.py::test_finding_matches_ground_truth_exact PASSED [ 50%]
tests/unit/test_benchmark_scorer.py::test_finding_matches_ground_truth_dynamic_path PASSED [ 56%]
tests/unit/test_benchmark_scorer.py::test_finding_matches_ground_truth_mismatches PASSED [ 62%]
tests/unit/test_benchmark_scorer.py::test_scorer_perfect_detection PASSED [ 68%]
tests/unit/test_benchmark_scorer.py::test_scorer_partial_detection_with_false_positives PASSED [ 75%]
tests/unit/test_benchmark_scorer.py::test_scorer_zero_findings PASSED    [ 81%]
tests/unit/test_benchmark_scorer.py::test_scorer_suppressed_and_refuted_findings PASSED [ 87%]
tests/unit/test_benchmark_scorer.py::test_scorer_quality_and_reliability_metrics PASSED [ 93%]
tests/unit/test_benchmark_scorer.py::test_scorer_cli_execution PASSED    [100%]

============================= 16 passed in 0.98s ==============================
```

### 6.2 Scorer CLI Execution Output (`benchmark/score.py`)
```bash
python benchmark/score.py --ground-truth benchmark/ground_truth.yaml --findings tests/fixtures/synthetic_benchmark_findings.json
```

**Verbatim Machine Output:**
```json
{
  "benchmark_summary": {
    "total_ground_truth_cases": 30,
    "vulnerable_cases_count": 15,
    "secure_cases_count": 15,
    "total_findings_evaluated": 19
  },
  "detection_metrics": {
    "true_positives": 15,
    "false_positives": 3,
    "false_negatives": 0,
    "secure_cases_false_positives": 2,
    "precision": 0.8333,
    "recall": 1.0,
    "f1_score": 0.9091,
    "false_positive_rate_secure": 0.1333
  },
  "quality_and_reliability_metrics": {
    "reproduction_success_rate": 1.0,
    "mean_evidence_completeness_pct": 100.0,
    "wstg_coverage_pct": 35.85,
    "execution_reliability": 1.0,
    "total_runs": 5,
    "completed_runs": 5,
    "timeouts": 0,
    "crashes": 0
  },
  "breakdown": {
    "true_positives_detail": [
      {
        "gt_id": "GT-SQLI-01-V",
        "category": "SQL Injection",
        "endpoint": "/rest/products/search",
        "finding_id": "SYNTH-TP-01-SQLI",
        "finding_title": "SQL Injection in Product Search parameter 'q'",
        "severity": "HIGH"
      },
      {
        "gt_id": "GT-XSS-01-V",
        "category": "XSS",
        "endpoint": "/rest/products/search",
        "finding_id": "SYNTH-TP-02-XSS",
        "finding_title": "Reflected Cross-Site Scripting in Search Query",
        "severity": "HIGH"
      },
      {
        "gt_id": "GT-SSRF-01-V",
        "category": "SSRF",
        "endpoint": "/ssrf/fetch",
        "finding_id": "SYNTH-TP-03-SSRF",
        "finding_title": "Server-Side Request Forgery via /ssrf/fetch",
        "severity": "CRITICAL"
      },
      {
        "gt_id": "GT-IDOR-01-V",
        "category": "IDOR / BOLA",
        "endpoint": "/identity/api/v2/vehicle/{vehicleId}/location",
        "finding_id": "SYNTH-TP-04-IDOR",
        "finding_title": "Broken Object Level Authorization in Vehicle Tracking",
        "severity": "HIGH"
      },
      {
        "gt_id": "GT-BAC-01-V",
        "category": "Broken Access Control",
        "endpoint": "/rest/admin/application-configuration",
        "finding_id": "SYNTH-TP-05-BAC",
        "finding_title": "Unauthenticated Administrative Configuration Access",
        "severity": "HIGH"
      },
      {
        "gt_id": "GT-AUTH-01-V",
        "category": "Authentication weaknesses",
        "endpoint": "/rest/user/login",
        "finding_id": "SYNTH-TP-06-AUTH",
        "finding_title": "Authentication Bypass via SQL Injection in Login Email",
        "severity": "CRITICAL"
      },
      {
        "gt_id": "GT-JWT-01-V",
        "category": "JWT weaknesses",
        "endpoint": "/jwt/profile",
        "finding_id": "SYNTH-TP-07-JWT",
        "finding_title": "JWT Algorithm None Signature Bypass",
        "severity": "CRITICAL"
      },
      {
        "gt_id": "GT-UPLD-01-V",
        "category": "File upload vulnerabilities",
        "endpoint": "/upload/file",
        "finding_id": "SYNTH-TP-08-UPLD",
        "finding_title": "Arbitrary File Upload with Executable Extension",
        "severity": "CRITICAL"
      },
      {
        "gt_id": "GT-TRAV-01-V",
        "category": "Path traversal",
        "endpoint": "/files/read",
        "finding_id": "SYNTH-TP-09-TRAV",
        "finding_title": "Directory Traversal in File Reader via Parameter 'filename'",
        "severity": "HIGH"
      },
      {
        "gt_id": "GT-CMDI-01-V",
        "category": "Command injection",
        "endpoint": "/cmd/ping",
        "finding_id": "SYNTH-TP-10-CMDI",
        "finding_title": "Operating System Command Injection in Ping Service",
        "severity": "CRITICAL"
      },
      {
        "gt_id": "GT-SSTI-01-V",
        "category": "SSTI",
        "endpoint": "/ssti/render",
        "finding_id": "SYNTH-TP-11-SSTI",
        "finding_title": "Server-Side Template Injection via Jinja2",
        "severity": "HIGH"
      },
      {
        "gt_id": "GT-XXE-01-V",
        "category": "XXE",
        "endpoint": "/xxe/parse",
        "finding_id": "SYNTH-TP-12-XXE",
        "finding_title": "XML External Entity Injection in Document Parser",
        "severity": "HIGH"
      },
      {
        "gt_id": "GT-APIS-01-V",
        "category": "API security weaknesses",
        "endpoint": "/workshop/api/shop/orders/all",
        "finding_id": "SYNTH-TP-13-APIS",
        "finding_title": "Excessive Data Exposure in Orders Endpoint",
        "severity": "MEDIUM"
      },
      {
        "gt_id": "GT-RACE-01-V",
        "category": "Race conditions",
        "endpoint": "/race/coupon",
        "finding_id": "SYNTH-TP-14-RACE",
        "finding_title": "Concurrency Race Condition in Coupon Redemption",
        "severity": "HIGH"
      },
      {
        "gt_id": "GT-BUSL-01-V",
        "category": "Business logic vulnerabilities",
        "endpoint": "/order/checkout",
        "finding_id": "SYNTH-TP-15-BUSL",
        "finding_title": "Client-Side Price Parameter Tampering in Checkout",
        "severity": "HIGH"
      }
    ],
    "false_negatives_detail": [],
    "false_positives_detail": [
      {
        "type": "SECURE_CASE_FALSE_POSITIVE",
        "gt_id": "GT-SQLI-02-S",
        "category": "SQL Injection",
        "endpoint": "/vulnerabilities/sqli/",
        "finding_id": "SYNTH-FP-01-SECURE-SQLI",
        "title": "Spurious SQLi Finding on DVWA Impossible Security Level"
      },
      {
        "type": "SECURE_CASE_FALSE_POSITIVE",
        "gt_id": "GT-JWT-02-S",
        "category": "JWT weaknesses",
        "endpoint": "/jwt/secure",
        "finding_id": "SYNTH-FP-02-SECURE-JWT",
        "title": "Spurious JWT Finding on Secure Endpoint"
      },
      {
        "type": "UNMATCHED_FALSE_POSITIVE",
        "finding_id": "SYNTH-FP-03-UNMATCHED",
        "endpoint": "/api/v1/fake-phantom-endpoint",
        "title": "Spurious Hallucinated Finding on Non-Existent Endpoint",
        "category": "SQL Injection",
        "cwe": 89
      }
    ]
  }
}
```

### 6.3 Mathematical Proof Verification
1. **True Positives ($TP = 15$):** All 15 vulnerable ground-truth categories are matched 1-to-1.
2. **False Positives ($FP = 3$):** 2 false positives on secure cases + 1 unmatched finding on a fake endpoint.
3. **Suppressed Finding Handling:** Refuted candidate finding `SYNTH-REFUTED-01` (`is_false_positive: true`) was correctly ignored and not counted as a false positive.
4. **Precision:** $\frac{TP}{TP + FP} = \frac{15}{15 + 3} = \frac{15}{18} \approx 0.8333$
5. **Recall:** $\frac{TP}{TP + FN} = \frac{15}{15 + 0} = 1.0$
6. **F1-Score:** $2 \times \frac{0.8333 \times 1.0}{0.8333 + 1.0} \approx 0.9091$
7. **False Positive Rate on Secure Cases ($FPR_{secure}$):** $\frac{2}{15} \approx 0.1333$
8. **Reproduction Success Rate:** $1.0$ (15 / 15 TP findings contained verified reproduction procedures).
9. **Mean Evidence Completeness:** $100.0\%$ (all 15 Phase 7 required fields present in TP findings).
10. **WSTG Coverage & Execution Reliability:** 38 / 106 ($35.85\%$) coverage, 5/5 ($1.0$) completed runs, 0 timeouts, 0 crashes.

---

## 7. Open Issues and Carry-Over Items

| Item ID | Category | Description | Severity | Current Status |
| :--- | :--- | :--- | :--- | :--- |
| **EVID-02** | Evidence Accuracy | Phase 2 R3 summary document recorded artificial draft numbers (44 planned, 2 failed) instead of raw machine numbers (38 planned, 0 failed). | P1 | **Logged in Defect Register & Summary Corrected** |
| **CARRY-01** | Evidence Completeness | UI workflow Playwright screenshots 03 (Project Overview / Execution Dashboard) and 09 (Settings / Configurations) were missing from initial capture. | P2 | Tracked for Phase 10 final evidence pack |
| **CARRY-02** | Verification | Mid-crawl and mid-validation asynchronous workflow cancellation behavior remains untested under heavy concurrency. | P2 | Deferred to Phase 4 / Phase 8 |
| **CARRY-03** | Evidence Completeness | API contract drift verification recorded summary numbers without detailed diff listings. | P3 | Tracked for Phase 10 |
| **CARRY-04** | Security Architecture | DNS rebinding protection for tool subprocesses (nuclei/ffuf) untested when domain resolves to multi-homed IP. | P2 | Scheduled for Phase 6 Security Assessment |
| **CARRY-05** | Security Architecture | Scanner API/worker containers maintain route to enterprise AI gateway (NI-03 egress disclosure). | P1 | Lab-only guardrail enforced; Layer-2 proxy deferred to Phase 9 |
| **CARRY-06** | Catalog Integrity | Discrepancy between static catalog entries (106) and raw WSTG instance models. | P2 | Tracked in Defect Register |
| **CARRY-07** | Detection Calibration | Soft-404 and catch-all detector needs calibration against SPA client routing. | P2 | Tracked for Phase 9 DOM parsing engine |
| **CARRY-08** | Operational Resilience | System handling of missing tool binaries (e.g. absent ffuf binary). | P2 | **Verified** (Validated in R4 & unit test `test_missing_binary_raises_tool_not_available_error`) |
| **CARRY-09** | Rate Limiting | Nuclei and ffuf command-line rate limits must be capped across concurrent runs. | P2 | **Verified** (Validated in R5 & unit test `test_ffuf_build_argv_rate_limit_capping`) |
| **CARRY-10** | Cryptographic Integrity| Audit log SHA-256 hash chain tampering verification (SHA-256 hash chain, not HMAC). | P2 | **Verified** (Validated in `test_audit_chain.py` & live stack) |
| **CARRY-11** | Budget Enforcement | Real-time token budget cutoff at $10.00 / 300k tokens via platform-side hard stop. | P1 | **Verified** (Enforced via `LLMBudgetExceededError` in `agents/base.py` & verified in `test_llm_budget_enforcement.py`) |

---

## 8. Checkpoint Verdict & Next Steps

* **Phase 3 Part A Execution Status:** COMPLETE.
* **Scan Invariant:** Zero benchmark scans have been started. Part B and Phase 4 have not been started.
* **Stop Condition Reached:** In accordance with instructions, execution is stopped here.

**Awaiting user approval before proceeding to Phase 3 Part B (Execution of Benchmark Runs).**
