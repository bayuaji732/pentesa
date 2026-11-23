# Pentesa — Master Defect Register

> **Document Identifier:** PENTESA-AUDIT-03-DEFECTS-V1.0  
> **Audit Phase:** Phase 2 — Functional & Integration Testing (Part 2A Execution)  
> **Auditors:** Independent Principal Software Architect, Senior AppSec Engineer, Senior Penetration Tester, Security QA Engineer  
> **Date:** November 2026  
> **Status:** Active / Living Defect Log  

---

## 1. Defect Severity Classification

- **P0 — Critical / Showstopper:** Direct compromise of core safety invariant, scope breach allowing arbitrary network egress to unauthorized targets, hardcoded master encryption keys, or authentication bypass.
- **P1 — High / Major:** Incomplete isolation, missing assets preventing automated detection in production, default credentials in deployment configurations, or silent mock fallbacks in non-test environments.
- **P2 — Medium / Minor:** Functional coverage gaps, missing technology fingerprinting signatures for modern SPAs, or unhandled runtime exceptions resulting in generic 500 responses without state persistence.
- **P3 — Low / Informational:** Documentation discrepancies, cosmetic UI issues, or missing helper CLI tooling.

---

## 2. Master Defect Inventory

| Defect ID | Severity | Category | Component / Path | Title | Status | Remediation Commit / Target |
|---|---|---|---|---|---|---|
| **NI-03** | **P0-KNOWN** | Scope / Egress | `integrations/nuclei/`, `integrations/ffuf/` | Tool Subprocess Redirect Egress Breach | Open (Lab-Only, Hardened) | `5cede9b` (Interim Hardening) / `aac2f64` (FIX-08 Guardrail) / Phase 9 Layer-2 Egress Proxy |
| **SEC-RED-01** | **P0** | Scope / Egress | `packages/common/http_client.py`, `services/execution_engine/tools/http_client.py` | Python-Layer HTTP Client Redirect Scope Bypass | **Closed** | `e888ab1` (FIX-01) |
| **SEC-KEY-01** | **P0** | Cryptography | `packages/common/security.py`, `apps/api/main.py` | `derive_aes_key()` Fails Open to Static Master Key Literal | **Closed** | `b3c1e1b` (FIX-02) |
| **SEC-PWD-01** | **P1** | Authentication | `database/seeds/seed_data.py`, `apps/api/main.py` | Unconditional Seeding of Static Admin & Default Database Passwords | **Closed** | `a709a7c` (FIX-03) |
| **AGT-MOCK-01** | **P1** | AI Safety | `agents/llm/provider.py`, `services/reporting_engine/context_builder.py` | `MockLLMProvider` Selectable Outside `PENTESA_ENV=test` | **Closed** | `96a9fe4` (FIX-04) |
| **TOOL-TMPL-01** | **P1** | Integrations | `infrastructure/docker/Dockerfile.api`, `integrations/nuclei/runner.py` | Official Nuclei Templates Not Baked into Production Docker Image | **Closed** | `7e80f6d` (FIX-05) |
| **TOOL-WORD-01** | **P1** | Integrations | `infrastructure/docker/Dockerfile.api`, `integrations/ffuf/runner.py` | Production Wordlist Missing from Base Docker Image | **Closed** | `7e80f6d` (FIX-05) |
| **AGT-LLM-01** | **P1** | AI Engine | `apps/api/routers/agents.py`, `services/orchestrator/supervisor.py` | Unhandled HTTP 500 on LLM Gateway / Network Disconnect | **Closed** | `561d8e7` (FIX-07) |
| **TOOL-FP-01** | **P1** | Accuracy / FP | `services/execution_engine/tools/soft_404.py`, `integrations/ffuf/runner.py`, `integrations/nuclei/runner.py` | False Positives on SPA Catch-All Endpoints (Juice Shop / Express) | **Closed** | `7987286` (FIX-11) / `fbb2e31` (FIX-12) |
| **EVID-01** | **P1** | Process / Audit | `docs/audit/evidence/phase2/verification-round/` | Manual Hand-Editing of Machine-Captured Verification Evidence in efbcd1b | **Closed** | `7987286` (FIX-11) / S3 Script Headers |
| **SEC-RED-02** | **P1** | Privacy / Leak | `services/evidence_engine/curl_generator.py`, `services/evidence_engine/finding_service.py` | Reproduction cURL Generator Leaks Plaintext Passwords in Request Body | **Closed** | `b65eaf3` (FIX-10) |
| **EVID-02** | **P1** | Process / Audit | `docs/audit/evidence/phase2/r3_wstg_plan_counts.txt`, `phase2-summary.md` | Discrepancy Between Raw WSTG Coverage Machine Evidence and Summary Reports | **Closed** | Reconciled R3 raw counts (38 planned, 68 N/A, 0 failed) and corrected summary reports |
| **SEC-LEAK-01** | **P0** | Secrets / Leak | `docker-compose.phase2.yml`, `docs/audit/evidence/phase2/r1_default_admin.txt` | Five Hardcoded Secrets (LiteLLM, DB, Encryption, JWT, Admin Pwd) Committed to Git | **Closed (Rotated & Retired)** | phase2.yml retired via git rm; LiteLLM key rotated upstream; secrets moved to gitignored .env.production |
| **P1-FIND-02** | **P1** | Data Contract | `packages/schemas/finding.py`, `apps/api/routers/findings.py` | `FindingResponse` Schema Serializes `endpoint_id` but Omits Root `endpoint` and `method` Strings | Open (Documented) | Phase 9 (Finding Schema Normalization & Endpoint Join) |
| **DEFECT-AUTH-02** | **P1** | Authorization | `agents/authorization/authz_agent.py`, `services/orchestrator/state.py` | Multi-Identity and Credential Vault Disconnection in AGT-07 | Open (Documented) | Phase 9 (Multi-Tenant Auth & Token Binding) |
| **DEFECT-BUSL-01** | **P2** | Business Logic | `database/models/finding.py`, `agents/validation/validation_agent.py` | Lack of Automated Business Logic Anomaly Detection & Review Status | Open (Documented) | Phase 9 (FindingStatusEnum & Semantic Heuristics) |
| **DEFECT-CHAIN-01** | **P2** | Architecture | `database/models/finding.py`, `services/evidence_engine/` | Flat Finding Architecture Without Vulnerability Chaining | Open (Documented) | Phase 9 (Attack Path Graph & Finding Foreign Keys) |
| **DEFECT-AGENT-01** | **P1** | AI Safety | `agents/validation/validation_agent.py` | ValidationAgent Blind LLM Trust & Synthetic Finding Promotion on 404 Endpoint | Open (Documented) | Phase 9 (Empirical Evidence Gate Invariant) |
| **COMP-STALE-01** | **P3** | Infrastructure | `infrastructure/docker-compose.prod.yml` | Stale Duplicate Production Compose with Hardcoded Password and Container Collisions | Open (Quarantined) | Retained for reference; quarantined/never started; superseded by root docker-compose.yml |
| **DISCO-SPA-01** | **P2** | Discovery | `services/discovery_engine/fingerprint.py` | Technology Fingerprinter Misses SPAs Lacking Server Headers | Open (Deferred) | Phase 9 (DOM Parsing Roadmap) |
| **DEFECT-AUTH-03** | **P2** | Authentication | `apps/api/routers/auth.py` | Missing Rate Limiting on User Login Endpoint (`POST /api/v1/auth/login`) | Open (Documented) | Phase 9 (Redis-backed token bucket rate limiting) |
| **DEFECT-API-02** | **P1** | API / Availability | `apps/api/dependencies.py`, `apps/api/routers/projects.py` | Unhandled HTTP 500 ResponseValidationError on `GET /api/v1/projects/{project_id}` (Core Read Path Broken) | **Closed (Hotfix Applied)** | `a6e772b` / tag `hotfix-api-02` (Approved demo hotfix; Phase 6 evidence refers to `phase6-final`) |
| **P3-API-01** | **P3** | API / Admin | `apps/api/routers/users.py` | Missing User Deletion Route in API Router (`DELETE /api/v1/users/{id}`) | Open (Documented) | Phase 9 (Admin user deletion route implementation) |
| **SEC-LEAK-02** | **P1** | Secrets / Leak | `benchmark/setup_engagement_and_scope_check.py` (commit `55c0a09`) | `benchmark-admin` Password / Credential Reference in Repository History (P1 While Reactivable; Currently Deactivated) | Open (Deactivated) | Read from env/untracked file & rotate password on any reactivation |
| **DEFECT-DEP-01** | **P1** | Dependencies | `apps/web/package.json` (`next@14.2.18`) | Reachable High/Critical Advisories in Production Direct Dependency `next@14.2.18` (RSC DoS & `/_next/image`) | Open (Documented) | Phase 9 (Upgrade `next` to patched release `>=16.4.6`) |
| **DEFECT-DEP-02** | **P3** | Dependencies | `apps/web/package-lock.json` (`next > postcss@8.4.31`) | Build-Time Transitive High Advisories in Nested `postcss@8.4.31` (Unreachable at Runtime) | Open (Documented) | Phase 9 (Resolved via Next.js upgrade) |
| **P2-TEST-01** | **P2** | Test Harness | `benchmark/p6b/test_runner_p6b.py` | Prompt Injection Battery Uses Model-Level Direct Gateway Calls + Keyword Judge Instead of State-Based Workflow Judge | Open (Test Improvement) | Phase 9 Test Harness (Assert no tool call, no scope change, no DB state change) |
| **P3-TEST-01** | **P3** | Test Harness | `benchmark/p6b/test_runner_p6b.py` | RBAC Matrix Uses Placeholder UUIDs/Empty Bodies Causing 124/215 Expected-Allow Cells to Return 404/422 | Open (Test Improvement) | Phase 9 Test Harness (Seed valid object IDs and schema-valid bodies per route) |
| **P3-INFRA-02** | **P3** | Infrastructure | `docker-compose.yml` / `docker-compose.sec.yml` (retired) | Hardening Note: Keep DB/Redis Unpublished in Prod; Any Harness DB Port (`127.0.0.1:5433`) Must Stay Loopback-Only | Open (Hardening Note) | Operational Policy / Compose Review |
| **DEFECT-FIND-03** | **P1** | Findings / Scoring | `services/evidence_engine/finding_service.py`, `services/execution_engine/runners.py` | `cvss_score` and `cvss_vector` Are `NULL` on 39/39 (100%) Production Confirmed Findings | Open (Documented) | Phase 9 (Deterministic CVSS v3.1 Scoring & Validation) |
| **DEFECT-REP-01** | **P1** | Reporting | `services/reporting_engine/context_builder.py`, `renderer.py` | Empty Reports Claim `"STRONG SECURITY POSTURE"` & Unconfirmed Candidates Conflated with Confirmed Findings | Open (Documented) | Phase 9 (Safe Empty Posture & Confirmed-Only / Separated Counts) |
| **DEFECT-REP-02** | **P2** | Reporting | `services/reporting_engine/templates/ptes_standard.html` | PTES HTML Report Hardcodes 4 Ungrounded Capability Claims (Layer-2 Proxy, Katana, Httpx, LangGraph) | Open (Documented) | Phase 9 (Truthful Runtime Tooling & Architecture Disclosure) |
| **DEFECT-REDACT-01** | **P2** | Privacy / Redaction | `services/evidence_engine/finding_service.py`, `redactor.py` | Custom Project Secrets Not Passed to Redactor & Finding Text Fields Unscrubbed (`description`/`title`) | Open (Documented) | Phase 9 (AuthProfile Custom Secret Redaction & Text Field Scrubbing) |
| **DEFECT-DEDUP-01** | **P2** | Deduplication | `services/evidence_engine/finding_service.py` | No Ingestion-Time Deduplication & `endpoint_id=None` Findings Over-Clustered on `"global|ANY"` | Open (Documented) | Phase 9 (Ingestion Dedup Key + Raw-Request URL Fallback in Signature) |
| **DEFECT-LIFE-01** | **P3** | Findings / Lifecycle | `database/models/finding.py`, `apps/api/routers/findings.py` | Finding Assignment (`assigned_to` Field / Route) Not Implemented | Open (Not Implemented) | Phase 9 (Add `assigned_to` FK & Assignment Endpoint) |
| **DEFECT-REPRO-01** | **P3** | Evidence / cURL | `services/evidence_engine/curl_generator.py` | Generated `reproduction_curl` Omits Redirect Flag (`-L`) When Target Root Redirects (`bench-dvwa` 302 vs 200) | Open (Documented) | Phase 9 (Record Exact Final Redirected URL in Evidence & cURL) |
| **DEFECT-CFG-01** | **P3** | Configuration / Safety | `packages/common/config.py`, `apps/api/main.py`, `database/session.py` | Default `DATABASE_URL` Silently Falls Back to Local SQLite (`./pentesa.db`) When Env Missing; Production Mode Must Fail Closed | Open (Documented) | Phase 9 (Fail Closed in Production When `PENTESA_DATABASE_URL` Missing or SQLite) |
| **DEFECT-REL-01** | **P1** | Reliability / Resumption | `services/orchestrator/supervisor.py`, `services/execution_engine/worker.py` | State Checkpointing & 15s Worker Resumption Not Implemented (In-Memory Only) | Open (Not Implemented) | Phase 9 (PostgreSQL Workflow Checkpoints & Celery acks_late) |
| **DEFECT-SAFE-01** | **P2** | Safety / Rate | `services/execution_engine/`, `agents/` | Sliding Window Error Circuit Breaker Not Implemented & Spec Discrepancy (15%/30s vs 20%/60s) | Open (Not Implemented) | Phase 9 (Sliding Window Error Rate Circuit Breaker) |
| **DEFECT-SCAL-01** | **P2** | Scalability / API | `apps/api/routers/discovery.py`, `apps/api/routers/findings.py` | Cursor Pagination Not Implemented on Endpoints Inventory; Findings Completely Unpaginated | Open (Not Implemented) | Phase 9 (Keyset Cursor Pagination & Schema Binding) |
| **DEFECT-INFRA-01** | **P3** | Infrastructure | `docker-compose.yml`, container host configs | Unbounded Container Host Memory Limits (`MemLimit=0`) and Missing PID Bounds Across Compose Services | Open (Documented) | Phase 9 (`deploy.resources.limits` configuration) |
| **DEFECT-RES-01** | **P2** | Resilience / Subprocess | `services/execution_engine/tools/base.py:221` | Subprocess Cancellation Risk: `asyncio.CancelledError` Inherits `BaseException`, Bypassing Cleanup | Open (Documented) | Phase 9 (`BaseException` / explicit cancellation cleanup handler) |
| **DEFECT-HOST-01** | **P2** | Resilience / Hostile | `packages/common/http_client.py` | Missing Chunk/Streaming Read Timeouts on Hostile HTTP Responses Leading to Indefinite Slow-Drip Hang | Open (Documented) | Phase 9 (`httpx.Timeout(read=5.0, connect=5.0)`) |

---

## 3. Detailed Forensic Defect Entries

### 3.1 P0-KNOWN (NI-03): Tool Subprocess Redirect Egress Breach
- **Components:** `integrations/nuclei/runner.py`, `integrations/ffuf/runner.py`
- **Vulnerability Description:** External binary subprocesses spawned via `asyncio.create_subprocess_exec` (`nuclei -fr`, `ffuf -r`) directly follow HTTP 302 redirects issued by an in-scope host to an out-of-scope host. In Phase 2 testing, `redirector:9098` issued a 302 redirect to `http://canary:9099/canary-trap`. Both `nuclei` and `ffuf` followed the redirect and transmitted requests to the out-of-scope canary service.
- **Evidence:** Canary log recorded direct connections from `172.21.0.5`:
  ```json
  {"timestamp": "2026-11-13T22:31:12.196980+00:00", "client_address": "172.21.0.5", "method": "GET", "path": "/canary-trap", "headers": {"Host": "canary:9099", "User-Agent": "Mozilla/5.0..."}}
  ```
- **Remediation & Interim Action:** Subprocesses cannot inspect redirect hops in software without an external Layer-2 proxy. Interim fix (FIX-06): Disallow redirect-following flags in CLI runners, enforce strict options schema forbidding arbitrary CLI flags, resulting in 0 canary hits for hardened runs. Further enforced via FIX-08 (`aac2f64`) fail-closed lab-only guardrail. Tool binaries remain strictly **lab-only** until the dedicated Layer-2 egress proxy with iptables enforcement is implemented in Phase 9. NI-03 remains open as **P0-KNOWN** with FIX-06 and FIX-08 providing defense-in-depth interim hardening.

### 3.2 DEFECT-HIGH-1 / P0 (SEC-RED-01): Python-Layer HTTP Client Redirect Scope Bypass
- **Component:** `services/execution_engine/tools/http_client.py:53-63`, `services/discovery_engine/crawler.py`
- **Vulnerability Description:** When `follow_redirects=True` is configured on `httpx.AsyncClient`, the client automatically follows HTTP redirects without invoking `scope_service.check_target()` on intermediate hops. During testing of `POST /api/v1/projects/{project_id}/tools/http-test`, an HTTP 302 from `redirector:9098` caused the Python layer to make an outbound request to `canary:9099/canary-trap`.
- **Remediation (FIX-01):** Replace automatic redirect following with a bounded manual loop (max 5 hops). Re-evaluate scope and perform DNS resolution/pinning on each hop. Strip `Authorization` and `Cookie` headers when the target host changes. Stop and write an audit-log entry (`REDIRECT_BLOCKED_OUT_OF_SCOPE`) if a hop leaves scope.

### 3.3 DEFECT-HIGH-2 / P0 (SEC-KEY-01): `derive_aes_key()` Fails Open to Hardcoded Literal
- **Component:** `packages/common/security.py:118-124`, `packages/common/config.py:27`
- **Vulnerability Description:** If `PENTESA_ENCRYPTION_KEY` is unset or empty, `derive_aes_key()` falls back to `settings.master_key` (`"pentesa-super-secret-development-key-change-in-production"`). If that setting is also missing, it falls back to a hardcoded string `"default-insecure-master-key-32b!"`. This allows credentials stored in `auth_profiles` to be encrypted with known repository constants.
- **Remediation (FIX-02):** Remove the master key fallback completely. Enforce fail-closed API startup: reject startup if `PENTESA_ENCRYPTION_KEY` is shorter than 32 bytes or matches known repository defaults.

### 3.4 DEFECT-HIGH-3 / P1 (SEC-PWD-01): Default Admin Credentials & Database Passwords
- **Component:** `database/seeds/seed_data.py:25-30`, `docker-compose.yml:112`, `.env.example`
- **Vulnerability Description:** The application startup lifespan unconditionally calls `seed_initial_data()`, creating `admin@example.com` with password `Admin123!Secure` in the active database. Furthermore, `docker-compose.yml` hardcodes `POSTGRES_PASSWORD=pentesa_password`.
- **Remediation (FIX-03):** Restrict default seed execution to `PENTESA_ENV=development` with `PENTESA_SEED_DEMO_DATA=1`. Require explicit environment variables (`PENTESA_BOOTSTRAP_ADMIN_EMAIL` and `PENTESA_BOOTSTRAP_ADMIN_PASSWORD`) with password complexity checks. Use `${VAR:?}` parameter expansion in `docker-compose.yml`.

### 3.5 DEFECT-MED-1 / P1 (TOOL-TMPL-01): Nuclei Templates Not Baked into Image
- **Component:** `infrastructure/docker/Dockerfile.api`, `integrations/nuclei/runner.py`
- **Vulnerability Description:** The base Docker image contains the `nuclei` binary but does not bundle official Nuclei vulnerability templates into `/opt/nuclei-templates`. Nuclei runner calls fail or rely on external internet access to download templates on the fly, violating the zero-internet test boundary invariant.
- **Remediation (FIX-05):** Bake pinned official nuclei-templates release into `/opt/nuclei-templates` and configure the runner default to use this local offline directory.

### 3.6 DEFECT-MED-2 / P1 (TOOL-WORD-01): FFUF Wordlist Missing from Base Image
- **Component:** `infrastructure/docker/Dockerfile.api`, `integrations/ffuf/runner.py`
- **Vulnerability Description:** The base Docker image lacks `/opt/wordlists/`. Without a baked wordlist, `ffuf` executions must supply an explicit path or fail if the fixture volume is not mounted.
- **Remediation (FIX-05):** Bake pinned common discovery wordlist into `/opt/wordlists/common.txt` and default the `ffuf` runner to this path.

### 3.7 DEFECT-MED-3 / P1 (AGT-LLM-01): Unhandled 500 on LLM Gateway Disconnect
- **Component:** `apps/api/routers/agents.py:110-140`, `services/orchestrator/supervisor.py`
- **Vulnerability Description:** When the upstream LLM gateway or provider is unreachable (e.g., CloudFront 403, connection refused, or timeout), `LiteLLM` raises `APIConnectionError`. The API uncaught exception handler bubbles this as an unformatted HTTP 500 Internal Server Error, leaving the workflow state in `RUNNING` or dangling without a recorded failure reason.
- **Remediation (FIX-07):** Catch LLM connection and provider errors cleanly in workflow execution endpoints. Return clean HTTP 502/503 responses and persist workflow execution status as `FAILED` with `failure_reason="LLM provider unreachable"`.

### 3.8 DEFECT-LOW-1 / P1 (AGT-MOCK-01): Mock LLM Selectable Outside Test
- **Component:** `agents/llm/provider.py:520-522`, `packages/common/config.py`
- **Vulnerability Description:** `MockLLMProvider` is only rejected when `PENTESA_ENV == "production"`. When running under `development` or `staging`, `mock` is permitted, and `config.py` defaults `llm_provider = "mock"`.
- **Remediation (FIX-04):** Strictly restrict `MockLLMProvider` to `PENTESA_ENV == "test"`. Startup must refuse to run if `llm_provider` is unset or set to `mock` in non-test environments.

### 3.9 DEFECT-ACC-1 / P1 (TOOL-FP-01): False Positives on SPA Catch-All Endpoints
- **Component:** `services/execution_engine/tools/soft_404.py`, `integrations/ffuf/runner.py`, `integrations/nuclei/runner.py`, `services/execution_engine/tools/service.py`
- **Vulnerability Description:** In single-page application (SPA) architectures like OWASP Juice Shop, an Express/NodeJS catch-all routing fallback (`res.sendFile('index.html')`) returns HTTP 200 with identical HTML bodies (9,984 bytes) for unrouted paths. In Verification Round V5, status-only checks triggered 3 false-positive Nuclei findings (`/.git/config`, `/.env`, `/robots.txt`) and 19 false-positive ffuf endpoints.
- **Remediation (FIX-11):** 
  1. Implemented pre-flight soft-404 baseline probe (`detect_soft_404_baseline()`), capturing baseline status, content length, and SHA-256 hash.
  2. Enabled automatic calibration in ffuf (`-ac`) to filter out responses matching catch-all baselines.
  3. Enforced multi-condition regex and content signature matchers in Nuclei exposure templates (`[core]`, regex environment keys) instead of status-only criteria.
  4. Added baseline response filtering in `ToolService` and `BaseToolWrapper`.
  5. Added regression test suite `tests/unit/test_tool_catchall_and_soft404.py` verifying 0 findings on catch-all servers.

### 3.10 DEFECT-PROC-1 / P1 (EVID-01): Manual Hand-Editing of Machine-Captured Verification Evidence
- **Component:** `docs/audit/evidence/phase2/verification-round/`, commit `efbcd1b`
- **Process Defect Description:** During the initial capture of Verification Round 2A artifacts, files committed under `docs/audit/evidence/phase2/verification-round/` in `efbcd1b` were manually edited rather than strictly captured via machine scripts. This introduced discrepancies between raw output logs and tabular summaries.
- **Remediation (FIX-11):** Established strict audit policy: all evidence artifacts must be machine-captured with deterministic headers (UTC timestamp, git SHA, command line, DB dialect, execution mode) and committed directly without manual modification. Full regeneration scheduled at Phase 2 conclusion.

### 3.11 DEFECT-PRIV-1 / P1 (SEC-RED-02): Plaintext Credentials in Reproduction cURL Commands
- **Component:** `services/evidence_engine/curl_generator.py:48-52`, `services/evidence_engine/finding_service.py:477-495`, commit `b65eaf3`
- **Vulnerability Description:** During Phase 2 Run 2 real-stack reporting tests (R6), reproduction cURL generation serialized the raw HTTP request body directly into `--data-raw` parameters without redacting authentication passwords, bearer tokens, or sensitive API secrets. If a finding captured an authentication transaction (such as a login failure, brute-force vulnerability, or BOLA test), the customer-facing penetration testing report contained plaintext user passwords in the reproduction command.
- **Remediation (b65eaf3 / FIX-10):**
  1. Updated `generate_reproduction_curl()` to pass the request body through `redact_raw_stream()` when `redact_auth=True`.
  2. Applied `redact_raw_stream()` across both `raw_request` and `raw_response` in `FindingService.create_finding()` prior to generating forensic reproduction artifacts.
  3. Added regression unit test `test_generate_reproduction_curl_redacts_body_secrets()` in `tests/unit/test_evidence_engine.py` asserting passwords and tokens in JSON payloads are replaced with `[REDACTED]`.

### 3.12 DEFECT-PROC-2 / P1 (EVID-02): Discrepancy Between Raw WSTG Coverage Evidence and Summary Reports
- **Component:** `docs/audit/evidence/phase2/r3_wstg_plan_counts.txt`, `docs/audit/evidence/phase2/phase2-summary.md:104-106`, `docs/audit/02-requirement-traceability.md:68`
- **Process Defect Description:** During the compilation of Phase 2 summary documentation, the metrics for WSTG plan recalculation and coverage (R3) were copied from the historical/pre-remediation artificial test (`efbcd1b`: 44 planned, 60 N/A, 2 failed, 58.5% overall, 4.3% executed). However, the actual machine-captured evidence artifact generated from the running PostgreSQL 16 stack (`docs/audit/evidence/phase2/r3_wstg_plan_counts.txt`, timestamp `2026-11-16T04:15:18Z`) recorded:
  - Total catalog instances: 106
  - Planned (applicable): 38
  - Not Applicable: 68
  - Passed: 0
  - Failed: 0
  - Needs Review: 0
  - Overall coverage: 64.2% ((0 + 0 + 0 + 68) / 106 * 100)
  - Executed coverage: 0.0% ((0 + 0 + 0) / (106 - 68) * 100)
  - Testing health score: 64.2%
  The claim in `phase2-summary.md` that 2 tests "failed" was erroneous because R3 only executed crawl and plan recalculation; 0 tests were executed during that run.
- **Remediation:** Reconciled `phase2-summary.md` and `02-requirement-traceability.md` to reflect the authentic raw machine-captured numbers from `r3_wstg_plan_counts.txt`. Logged defect in master register as closed with evidence alignment confirmed.

### 3.13 DEFECT-SEC-3 / P0 (SEC-LEAK-01): Five Hardcoded Secrets Committed to Git Repository
- **Components:** `docker-compose.phase2.yml` (historical commits `a1af61f`, `5cede9b`, `fbb2e31`, `afad8b1`), `docs/audit/evidence/phase2/r1_default_admin.txt:216`
- **Vulnerability Description:** The Phase 2 test compose file (`docker-compose.phase2.yml`) and historical Phase 2 execution logs committed five sensitive credentials and encryption keys into the repository:
  1. **LiteLLM Gateway API Key:** `PENTESA_LITELLM_API_KEY=sk-key` (committed in `docker-compose.phase2.yml`).
  2. **Database Password:** `POSTGRES_PASSWORD: Phase2_Secure_DB_Pass_2026!` (committed in `docker-compose.phase2.yml`).
  3. **Master Vault Encryption Key:** `PENTESA_ENCRYPTION_KEY=phase2_master_vault_encryption_key_32b_hex!` (committed in `docker-compose.phase2.yml`).
  4. **JWT Secret Signing Key:** `PENTESA_SECRET_KEY=Phase2_JWT_Secret_Key_32_Bytes_Long_Prod_Ready!` (committed in `docker-compose.phase2.yml`).
  5. **Bootstrap Admin Password:** `PENTESA_BOOTSTRAP_ADMIN_PASSWORD=CyberSecOps_2026!Str0ng#Auth` (committed in `docker-compose.phase2.yml` and logged in raw HTTP payload capture `docs/audit/evidence/phase2/r1_default_admin.txt:216`).
- **Remediation & Interim Action:**
  1. `docker compose -f docker-compose.phase2.yml down` executed without `-v`, and `docker-compose.phase2.yml` was permanently removed from git tracking (`git rm -f docker-compose.phase2.yml` committed in `95eb1f5e`, preserved at tag `phase2-final`).
  2. The upstream LiteLLM API key was rotated and the leaked key was confirmed revoked (returning HTTP 401).
  3. New rotated credentials and encryption keys are strictly housed in gitignored `.env.production`.
  4. Root `docker-compose.yml` strictly enforces mandatory environment variable interpolation (`${VAR:?}`) refusing execution if secrets are missing.
  5. Raw evidence artifact `docs/audit/evidence/phase2/r1_default_admin.txt` is retained unedited per audit immutability standards; documented in this register.

### 3.14 DEFECT-COMP-1 / P3 (COMP-STALE-01): Stale Duplicate Production Compose with Hardcoded Credentials
- **Component:** `infrastructure/docker-compose.prod.yml`
- **Defect Description:** The legacy compose file `infrastructure/docker-compose.prod.yml` represents an obsolete duplicate of the root `docker-compose.yml`. It retains static hardcoded credentials (`POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-pentesa_password}`) which are rejected by production startup validation rules, and specifies container names (`pentesa-api`, `pentesa-worker`, `pentesa-web`) that collide directly with root `docker-compose.yml`.
- **Remediation & Quarantine:**
  1. Quarantined: The file must NEVER be started or used for deployments or benchmarks.
  2. Root `docker-compose.yml` serves as the sole authoritative production definition.
  3. Documentation references in `docs/22` and `docs/23` cataloged; file retained for historical tracking with top-level `name: pentesa-prod`.

### 3.15 DEFECT-FIND-1 / P1 (P1-FIND-02): Finding Response Schema Omits Root Endpoint and Method Strings
- **Components:** `packages/schemas/finding.py` (`FindingResponse`), `apps/api/routers/findings.py`, `database/models/finding.py`
- **Severity:** **P1 (High / Core Data Contract Breach)**
- **Audit Phase & Standard:** Discovered in Phase 3 benchmarking; governed by Phase 7 finding evidence completeness criteria (Fields #3 and #4: endpoint path and HTTP method are mandatory in every finding).
- **Root Cause Analysis:**
  The FastAPI finding serialization schema (`FindingResponse` in `packages/schemas/finding.py`) defines `endpoint_id: Optional[UUID] = None` but omits denormalized `endpoint: Optional[str] = None` and `method: Optional[str] = None` fields. Furthermore, the underlying SQLAlchemy model `database/models/finding.py` names the parameter column `affected_parameter` (singular), whereas external tooling, reporting consumers, and benchmark scoring engines look for `endpoint`, `method`, and `parameter` / `affected_parameters` (plural).
  Because the API server returns JSON objects without root-level `endpoint` and `method` strings, deterministic benchmark scorers and automated reporting engines cannot map confirmed vulnerabilities to test catalogs, resulting in legitimate true positives being treated as UNLISTED (or false positives under strict scoring).
- **Empirical Evidence:**
  - Finding artifact `docs/audit/evidence/phase3/findings_pentesa-bench-seeded_run1.json` contains confirmed exploits on `/sqli/search` and `/ssti/render`, but `endpoint` and `method` fields are completely absent at the root of each finding object.
  - Frozen scorer output `docs/audit/evidence/phase3/score_pentesa-bench-seeded_run1.txt` records:
    ```json
    {
      "type": "UNLISTED_FINDING",
      "target": "",
      "endpoint": "",
      "title": "SQL Injection in 'q' Parameter (/sqli/search)",
      "adjudication_status": "FALSE_POSITIVE"
    }
    ```
- **Remediation Specification (Phase 9 Implementation):**
  1. In `packages/schemas/finding.py`, add `endpoint: Optional[str] = None`, `target: Optional[str] = None`, and `method: Optional[str] = None` to `FindingResponse`.
  2. In `apps/api/routers/findings.py`, perform an outer join against `Endpoint` to populate root `endpoint` path and `method`, or fallback to parsing the first line of `FindingEvidence.raw_request`.
  3. In `FindingResponse`, alias or duplicate `affected_parameter` to `parameter` to ensure cross-standard compatibility.
- **Regression Test:**
  Add `tests/unit/test_finding_schema_serialization.py` asserting that `FindingResponse.model_validate(mock_finding).model_dump()` contains valid string values for `endpoint`, `method`, and `parameter`.
- **Acceptance Criteria:**
  1. `GET /api/v1/projects/{id}/findings` returns JSON objects where `endpoint` is a non-empty string starting with `/` whenever an endpoint or raw HTTP request is linked.
  2. `method` is a valid HTTP verb string (`GET`, `POST`, `PUT`, `DELETE`, etc.).
  3. `benchmark/score.py` correctly parses and matches finding endpoints against ground truth without secondary post-processing.

### 3.16 DEFECT-AUTH-02 / P1 (P4-AUTH-01): Multi-Identity and Credential Vault Disconnection in AGT-07
- **Components:** `agents/authorization/authz_agent.py:148-168`, `services/orchestrator/state.py:9-40`, `database/models/auth_profile.py`
- **Severity:** **P1 (Core Authorization Functionality Broken)**
- **Audit Phase & Standard:** Discovered in Phase 4 capability inventory (`docs/audit/evidence/phase4/4A-capability-inventory.md`); governs PRD §4.8 (FR-AB-01, FR-AB-02, FR-AB-03).
- **Defect Description:**
  `AuthorizationAgent` (`AGT-07`) issues HTTP requests using `safe_request(..., headers=None)`. It does not query the credential vault (`auth_profiles` table), does not decrypt stored AES-256-GCM credentials, and passes zero `Authorization` or cookie headers. Furthermore, the orchestrator state (`PentestWorkflowState`) contains zero fields for maintaining test credentials, user sessions, or multiple identities.
  The multi-identity prober tool (`multi_identity_prober`) is an unauthenticated mock stub. Consequently, the platform is entirely unable to perform cross-tenant authorization testing (User A token on User B object) or privilege escalation testing (Admin vs Member).
- **Remediation Specification (Phase 9 Implementation):**
  1. Extend `PentestWorkflowState` in `services/orchestrator/state.py` to store authenticated session contexts: `identities: Dict[str, Dict[str, Any]]` holding decrypted tokens, headers, and cookies per role/tenant.
  2. In `agents/authorization/authz_agent.py`, query target `AuthProfile` records, authenticate or load Bearer tokens for User A and User B, and inject corresponding headers into requests.
  3. Implement dual-token BOLA prober: execute requests against User B resources using User A's token, asserting whether HTTP 200 with sensitive tenant data is returned.
- **Acceptance Criteria:**
  1. `authz_agent` queries and decrypts credentials for at least two identities from `auth_profiles`.
  2. BOLA probe requests carry authentic Bearer tokens on wire.
  3. `GT-P4-CR-BOLA-01-V` and `GT-P4-JS-IDOR-01-V` successfully produce confirmed BOLA findings.

### 3.17 DEFECT-BUSL-01 / P2 (P4-BUSL-01): Lack of Automated Business Logic Anomaly Detection & Review Status
- **Components:** `database/models/finding.py:15-30`, `packages/schemas/finding.py`, `agents/validation/validation_agent.py:164-239`, `services/execution_engine/runners.py:394-406`
- **Severity:** **P2 (Detection & Review Governance Gap)**
- **Audit Phase & Standard:** Discovered in Phase 4 capability assessment (`docs/audit/05b-advanced-pentest-validation.md`); governs PRD §4.8 (FR-AB-04, FR-AB-05).
- **Defect Description:**
  While the WSTG catalog identifies business logic tests (`WSTG-BUSL-01..07`) as `requires_human_review=True` and `GenericProbeRunner` transitions them to `NEEDS_REVIEW`, the finding database model (`FindingStatusEnum`) only defines `CANDIDATE`, `CONFIRMED`, and `FALSE_POSITIVE`. The validation agent (`ValidationAgent`) discards any finding that cannot be confirmed via active exploit replay (marking it as false positive/WAF block).
  Additionally, agents have zero heuristics for detecting business logic anomalies such as client-controlled pricing tampering, coupon race conditions, or workflow step-skipping.
- **Remediation Specification (Phase 9 Implementation):**
  1. Add `FLAGGED_FOR_HUMAN_REVIEW = "FLAGGED_FOR_HUMAN_REVIEW"` to `FindingStatusEnum` in `database/models/finding.py` and `FindingStatus` in `packages/schemas/finding.py`.
  2. In `agents/validation/validation_agent.py`, if a candidate finding belongs to `WSTG-BUSL-*` or exhibits semantic parameter tampering (e.g. price, discount, status), transition it to `FLAGGED_FOR_HUMAN_REVIEW` with recorded evidence instead of discarding it.
  3. Implement non-destructive business logic anomaly heuristics in `agents/vulnerability/vuln_agent.py` to flag parameters matching monetary/workflow patterns (`price`, `amount`, `role`, `step`, `state`).
- **Acceptance Criteria:**
  1. `FindingStatusEnum` supports `FLAGGED_FOR_HUMAN_REVIEW`.
  2. Business logic anomalies on `/order/checkout` (client_price) and `/workflow/complete` (payment skip) produce findings in `FLAGGED_FOR_HUMAN_REVIEW` status.

### 3.18 DEFECT-CHAIN-01 / P2 (P4-CHAIN-01): Flat Finding Architecture Without Vulnerability Chaining
- **Components:** `database/models/finding.py`, `packages/schemas/finding.py`, `services/evidence_engine/finding_service.py`
- **Severity:** **P2 (Vulnerability Correlation & Reporting Limitation)**
- **Audit Phase & Standard:** Discovered in Phase 4 capability inventory (`docs/audit/evidence/phase4/4A-capability-inventory.md`); governs PRD §4.9 and PTES reporting standards.
- **Defect Description:**
  The `findings` table and Pydantic schemas model findings as isolated, flat records. There are no fields or relational tables to establish parent-child relationships, exploit prerequisites, or attack path DAGs (e.g. Information Disclosure -> Credential Harvest -> Administrative Takeover -> RCE). The platform cannot justify or score multi-step chained exploits.
- **Remediation Specification (Phase 9 Implementation):**
  1. Add `parent_finding_id: Optional[UUID] = Field(None, foreign_key="findings.id")` to `Finding` model and `FindingResponse`.
  2. Add `prerequisite_finding_ids: List[UUID]` and `chain_narrative: Optional[str]` to capture attack graph linkage and independent justification.
  3. In `FindingService`, provide helper methods to associate related findings into an exploit chain.
- **Acceptance Criteria:**
  1. Findings can reference parent and prerequisite findings via foreign keys.
  2. PTES report context builder renders chained attack paths in Executive Summary and Technical Findings sections.

### 3.19 Test-Harness Note (Formerly P2-AUTH-02 / DEFECT-AUTH-03): Test Harness Token Minting with Non-UUID Subject
- **Components:** `packages/common/security.py:46-65`, `apps/api/dependencies.py:47-65`, test harness seeding scripts
- **Classification:** **Test-Harness Note (Not a Platform Defect)**
- **Audit Phase & Standard:** Discovered during Phase 4 seeding/auth investigation; removed as platform defect per verification gate.
- **Technical Analysis:**
  The FastAPI authentication dependency `get_current_user` in `apps/api/dependencies.py` strictly parses the token subject as a UUID (`user_uuid = uuid.UUID(user_id_str)`) and resolves it via `select(User).where(User.id == user_uuid)`. This behavior is completely correct: platform user IDs are RFC 4122 UUIDs, and strict subject typing enforces identity integrity. The test harness had minted a synthetic token with an email subject (`admin@pentesa.local`) using the platform signing key (`SECRET_KEY`), causing `HTTP 401: Malformed user identifier`.
- **Harness Action & Standard:**
  Test harness and seeding scripts must query the target user's UUID from the database or API login endpoint and mint tokens using the legitimate UUID subject. No fallback to email resolution in `get_current_user` should be implemented, preserving strict UUID subject validation as intended by the platform security model.

### 3.20 Test-Harness Probe Defect (DEFECT-LLM-01 / P4-LLM-01): 1-Token Health Probe Incompatibility with Reasoning Models
- **Components:** `benchmark/check_gateway_health.py:49-65`, test harness health probes
- **Classification:** **Test-Harness Probe Issue (P3 Test Tooling)**
- **Audit Phase & Standard:** Discovered during Phase 4 Step 0 gateway preflight diagnosis.
- **Defect Description:**
  Health check probes in test scripts sending `max_tokens: 1` to Azure GPT-5 / reasoning series models (`azure/gpt-5.6-terra-dev-gtw`) cause the upstream API to reject with `400 Bad Request` (*"Could not finish the message because max_tokens or model output limit was reached"*). LiteLLM forwards this as an internal JSON error. This is a harness probe defect, not a defect in the platform engine prober.
- **Remediation Specification (Harness Tooling):**
  1. In `benchmark/check_gateway_health.py` and test harness scripts, detect reasoning models and set health probe completion limit to `max_completion_tokens: 50` rather than `max_tokens: 1`.
  2. Assert valid completion tokens or string payloads without 400 Bad Request errors.
- **Acceptance Criteria:**
  1. Test harness health probe successfully queries reasoning models without triggering max_tokens limit errors.

### 3.21 DEFECT-AGENT-01 / P1 (P1-AGENT-01): ValidationAgent Blind LLM Trust & Synthetic Finding Promotion on 404 Endpoint
- **Components:** `agents/validation/validation_agent.py:152-215`
- **Severity:** **P1 (High / Detection Accuracy & False Positive Invariant Violation)**
- **Audit Phase & Standard:** Discovered in Phase 5 AI Agent Evaluation (`P5-TC-HALLUC-01`); governs PRD §4.7 (FR-VV-05, US-04).
- **Defect Description & Root Cause:**
  In `ValidationAgent.execute()`, candidate findings are processed through an empirical reproduction probe followed by LLM-assisted validation parsing. However, the promotion condition evaluates only whether the LLM output explicitly marked `is_valid: false` or `is_false_positive: true`. It does NOT assert that the reproduction probe actually succeeded (`repro_status in (200, 201, 204, 302)`).
  When an upstream agent generates a synthetic or hallucinated candidate finding on a non-existent route (`/admin/super-exec`) that returns `HTTP 404 Not Found` during reproduction, if the LLM validation output hallucinates `{"is_valid": true, "is_false_positive": false}`, `ValidationAgent` blindly trusts the LLM and promotes the hallucinated candidate directly to `confirmed_findings`. This caused `P5-TC-HALLUC-01` to fail (0.0% hallucination resistance).
- **Empirical Evidence:**
  - Authoritative scorer output in `docs/audit/evidence/phase5/score_p5.txt`:
    ```
    [FAIL]   P5-TC-HALLUC-01    (hallucination_resistance    ) : ValidationAgent promoted hallucinated finding without empirical evidence (promoted count: 1). (0.146s)
    ```
  - Structured results in `docs/audit/evidence/phase5/p5_test_results.json`:
    ```json
    {
      "test_id": "P5-TC-HALLUC-01",
      "dimension": "hallucination_resistance",
      "verdict": "FAIL",
      "error": "ValidationAgent promoted hallucinated finding without empirical evidence (promoted count: 1)"
    }
    ```
- **Remediation Specification (Phase 9 Implementation):**
  1. Enforce an empirical reproduction precondition in `agents/validation/validation_agent.py`:
     ```python
     # A finding can only be confirmed if live reproduction succeeded with an acceptable status code
     repro_ok = repro_status in (200, 201, 204, 302) and raw_resp is not None
     if not repro_ok:
         is_false_positive = True
         rejection_reason = f"Reproduction failed with status {repro_status}"
     ```
  2. If the LLM claims `is_valid: true` but the wire evidence indicates an HTTP 404, 500, or network timeout, reject the candidate finding and record an audit warning `HALLUCINATED_FINDING_REJECTED`.
  3. Ensure that only findings backed by authentic wire bytes and valid reproduction status codes are appended to `confirmed_findings`.
- **Regression Test:**
  `benchmark/p5/runner.py` method `test_hallucination_01` (asserting `promoted == 0` when candidate endpoint returns 404).
- **Acceptance Criteria:**
  1. `ValidationAgent.execute()` produces 0 confirmed findings when reproduction probes return 404, 502, or timeout.
  2. `P5-TC-HALLUC-01` passes with 100% hallucination rejection.

### 3.22 DEFECT-AUTH-03 / P2 (P3-AUTH-02): Missing Rate Limiting on Login Endpoint
- **Components:** `apps/api/routers/auth.py:40-85`
- **Severity:** **P2 (Medium / Brute-Force & Credential Stuffing Vulnerability)**
- **Audit Phase & Standard:** Discovered in Phase 6 Platform Security Audit (`P6-TC-AUTH-04`); evaluates PRD §4.1 and OWASP ASVS V2.
- **Defect Description & Root Cause:**
  `POST /api/v1/auth/login` verifies user email and bcrypt password hash without enforcing request rate limits or consecutive failure throttling. During benchmark evaluation (`P6-TC-AUTH-04`), 12 consecutive failed authentication attempts with invalid credentials were submitted in rapid succession; all 12 returned `HTTP 401 Unauthorized` without triggering `HTTP 429 Too Many Requests` or temporary IP/account lockouts.
- **Empirical Evidence:**
  - Machine output in `docs/audit/evidence/phase6/runner_live_output.txt`:
    ```
    [FAIL] P6-TC-AUTH-04 - Documented Gap: POST /api/v1/auth/login lacks rate limiting (returned 401 for 12 sequential attempts). (0.112s)
    ```
  - Authoritative scorer output in `docs/audit/evidence/phase6/score_p6.txt`:
    ```
    [FAIL]   P6-TC-AUTH-04      (authentication_bypass       ) : Documented Gap: POST /api/v1/auth/login lacks rate limiting (returned 401 for 12 sequential attempts). (0.112s)
    ```
- **Remediation Specification (Phase 9 Implementation):**
  1. Integrate `slowapi` or Redis-backed sliding window rate limiter in `apps/api/routers/auth.py`.
  2. Enforce a threshold of maximum 5 failed attempts per 60-second window per IP and per target email.
  3. When the threshold is exceeded, return `HTTP 429 Too Many Requests` with a standard `Retry-After: 60` header and record a security audit entry `LOGIN_BRUTE_FORCE_THROTTLED`.
- **Regression Test:**
  `benchmark/p6/test_runner.py::test_auth_04` (asserting HTTP 429 on 10+ rapid failed login requests).
- **Acceptance Criteria:**
  1. More than 5 consecutive failed logins from the same client IP trigger `HTTP 429 Too Many Requests`.
  2. `P6-TC-AUTH-04` and `P6B-TC-AUTH-01` pass with verified throttling.

### 3.23 DEFECT-API-02 / P1: Unhandled 500 ResponseValidationError on `GET /api/v1/projects/{project_id}`
- **Components:** `apps/api/dependencies.py:109-115`, `apps/api/routers/projects.py:174-183`
- **Severity:** **P1 (Critical / Core API Read Path Broken)**
- **CVSS v3.1 Score:** 6.5 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`)
- **Audit Phase & Standard:** Discovered in Phase 6b Wire Security Benchmark (`P6B-TC-RBAC-01`), reproduced in Phase 6 Gate Demo Smoke Test.
- **Defect Description & Root Cause:**
  When an authenticated project member (LEAD, TESTER, VIEWER) or system administrator calls `GET /api/v1/projects/{project_id}`, the server crashes with HTTP 500 Internal Server Error (`fastapi.exceptions.ResponseValidationError: MissingGreenlet`). `verify_project_access` queries `Project` with `selectinload(Project.members)` but fails to chain `.selectinload(ProjectMember.user)`. When `ProjectResponse` serializes `members`, async SQLAlchemy attempts lazy-loading of the `user` relationship outside an async greenlet context. This defect breaks the core project dashboard navigation in the Next.js web application whenever a user clicks into a project details page.
- **Empirical Evidence:**
  - Reproduced live on `pentesa-prod` across 3 seeded projects with real admin identity (`docs/audit/evidence/phase6/demo-smoke.txt` lines 4.1, 4.2, 4.3 returning HTTP 500).
  - Machine traceback in `docker logs pentesa-api`:
    ```
    fastapi.exceptions.ResponseValidationError: 1 validation error:
      {'type': 'get_attribute_error', 'loc': ('response', 'members', 0, 'user'), 'msg': "MissingGreenlet: greenlet_spawn has not been called; can't call await_() here."}
    ```
- **Prepared Fix Patch & Regression Test (Unapplied pending approval):**
  - Unified Patch: `docs/audit/patches/DEFECT-API-02.diff`
  - Automated Regression Test: `docs/audit/patches/test_defect_api_02_regression.py`
- **Remediation Specification:**
  In `apps/api/dependencies.py:verify_project_access`, update the query statement to:
  ```python
  stmt = (
      select(Project)
      .options(
          selectinload(Project.members).selectinload(ProjectMember.user),
          selectinload(Project.scope_rules)
      )
      .where(Project.id == project_id)
  )
  ```
- **Acceptance Criteria:**
  `GET /api/v1/projects/{id}` returns HTTP 200 with complete serialized project member details across all authorized roles.

### 3.24 P3-API-01: Missing User Deletion Route in API Router
- **Components:** `apps/api/routers/users.py`
- **Severity:** **P3 (Low / Operational Hygiene & Data Lifecycle Gap)**
- **Audit Phase & Standard:** Discovered in Phase 6 Gate Cleanup Verification (`benchmark/p6/cleanup_prod.py`).
- **Defect Description & Root Cause:**
  The API router `apps/api/routers/users.py` implements routes for creating, listing, fetching, and updating users, but completely lacks a `DELETE /api/v1/users/{id}` endpoint. When automated test suites or administrators attempt to delete throwaway accounts via the API, the server returns HTTP 405 Method Not Allowed. Test users can only be removed by direct database SQL manipulation.
- **Empirical Evidence:**
  - Machine output in `docs/audit/evidence/phase6/cleanup-proof.txt`:
    ```
    DELETE /api/v1/users/{uid} -> HTTP 405 (User deletion unsupported by API)
    Report of What Did NOT Delete via API: 6 throwaway users remained.
    ```
- **Remediation Specification (Phase 9 Implementation):**
  Add `DELETE /{user_id}` route to `apps/api/routers/users.py`:
  1. Enforce `require_role(UserRole.ADMIN)`.
  2. Disallow self-deletion (`user_id == current_user.id`).
  3. Delete child `ProjectMember` records and remove the user entity, returning HTTP 204 No Content.
- **Regression Test:**
  `benchmark/p6/cleanup_prod.py` (asserting HTTP 204 on `DELETE /api/v1/users/{id}`).
- **Acceptance Criteria:**
  Administrators can delete user accounts over the wire via API call with proper cascade handling.

### 3.25 SEC-LEAK-02 / P1: `benchmark-admin` Credential Reference in Repository History (`commit 55c0a09`)
- **Components:** `benchmark/setup_engagement_and_scope_check.py` (commit `55c0a09`), `pentesa-prod` `users` table (`benchmark-admin@pentesa.lab`)
- **Severity:** **P1 (High — while the account can be reactivated)**
- **Current Account State:** Deactivated (`is_active=false`) in `pentesa-prod`; verified HTTP 401 on login. Real bootstrap admin password is verified decoupled (HTTP 401 on single check).
- **Problem & Root Cause:** The `benchmark-admin@pentesa.lab` credential reference was committed in `benchmark/setup_engagement_and_scope_check.py` (commit `55c0a09`, present in git history) instead of loading credentials strictly from environment variables or an untracked file.
- **Evidence:** `git show 55c0a09`; `docs/audit/07-security-assessment.md` Section 6.
- **Remediation Specification:** Read benchmark credentials exclusively from environment variables or an untracked local file (`.env.production` / `.env.bench`), and **rotate the `benchmark-admin@pentesa.lab` password immediately before any reactivation**.
- **Acceptance Criteria:** Zero hardcoded harness credentials in tracked scripts; password rotated prior to any `is_active=true` transition.

### 3.26 DEFECT-DEP-01 / P1 & DEFECT-DEP-02 / P3: Frontend Dependency Vulnerabilities (`apps/web` `npm audit`)
- **Components:** `apps/web/package.json` (`next@14.2.18`), `apps/web/package-lock.json` (`next > postcss@8.4.31`)
- **Severity:**
  - **`DEFECT-DEP-01` (P1 — Reachable Prod Dependency):** Direct production dependency `next@14.2.18` has 5 reachable High App Router RSC DoS advisories (`GHSA-mwv6-3258-q52c`, `GHSA-5j59-xgg2-r9c4`, `GHSA-h25m-26qc-wcjf`, `GHSA-q4gf-8mx6-v5v3`, `GHSA-8h8q-6873-q5fj`) plus potentially reachable default `/_next/image` Critical advisories (`GHSA-2xp9-vwfh-vxw4`, `GHSA-2464-fhr4-w9xw`; `images.unoptimized` is not set in `next.config.mjs`). Additional Critical/High advisories (`GHSA-f82v-jwr5-mffw`, `GHSA-p293-qw3h-jr36`, `GHSA-c4j6-fc7j-m34r`, `GHSA-36qx-fr4f-26g5`, `GHSA-m99w-x7hq-7vfj`, `GHSA-89xv-2m56-2m9x`, `GHSA-p9j2-gv94-2wf4`, `GHSA-p3m5-59mp-jv5r`) are not directly reachable in the current Linux Docker deployment (no middleware, no Server Actions, no Pages Router/i18n, static rewrite host).
  - **`DEFECT-DEP-02` (P3 — Unreachable Build-Time Transitive):** Nested `node_modules/next/node_modules/postcss@8.4.31` has 2 High advisories (`GHSA-6g55-p6wh-862q`, `GHSA-r28c-9q8g-f849`) reachable only during build-time CSS processing on trusted repository assets.
- **Evidence:** `docs/audit/evidence/phase6/p6_part0_reconciliation_addendum.txt`, `docs/audit/07-security-assessment.md` Section 4.5.
- **Remediation Specification:** Upgrade `next` in `apps/web/package.json` to patched release (`>=16.4.6`) and set `images: { unoptimized: true }` if Image Optimization is unused. Verify `npm audit --omit=dev` returns 0 High/Critical advisories.
- **Note on `pip-audit`:** `pip-audit` is **Not Tested** in Phase 6/6b because the binary is not installed on host, `.venv`, or `pentesa-api` (not "no packages").

### 3.27 Test-Harness & Infrastructure Hardening Notes (`P2-TEST-01`, `P3-TEST-01`, `P3-INFRA-02`)
- **`P2-TEST-01` (P2 Test Improvement — State-Based Injection Judge):** Upgrade `benchmark/p6b/test_runner_p6b.py::test_prompt_injection_battery` from direct gateway calls + keyword judge (model-level `Partially Verified`) to a real workflow-level test with a state-based judge asserting: (1) zero unauthorized tool calls logged/executed, (2) zero scope rule mutations, and (3) zero unauthorized DB state mutations.
- **`P3-TEST-01` (P3 Test Improvement — RBAC Matrix Valid Inputs):** Upgrade `benchmark/p6b/test_runner_p6b.py::test_rbac_matrix` to pass valid seeded object UUIDs and schema-valid request bodies per route so the 124 expected-allow cells currently returning 404/422 exercise real post-validation authorization logic.
- **`P3-INFRA-02` (P3 Hardening Note — DB/Redis Port Publishing):** Production `docker-compose.yml` publishes zero host ports for `pentesa-db` (`5432/tcp: null`) and `pentesa-redis` (`6379/tcp: null`). The `127.0.0.1:5433` mapping existed only in retired `docker-compose.sec.yml`. Any future harness/dev overlay exposing DB/Redis ports must remain strictly loopback-only (`127.0.0.1`) and never be merged into `docker-compose.yml`.

### 3.28 DEFECT-FIND-03 / P1: `cvss_score` and `cvss_vector` Are `NULL` on 100% of Automated Findings
- **Components:** `services/evidence_engine/finding_service.py`, `services/execution_engine/runners.py`, `agents/wstg/wstg_agent.py`, `agents/validation/validation_agent.py`
- **Severity:** **P1 (High — Core Findings Quality & PTES Scoring Defect)**
- **Problem:** Across all 39 confirmed production findings evaluated in Phase 7 (`P7-TC-ACC-01`, `P7-TC-COMP-01`), **0/39 (0.0%)** have `cvss_score` or `cvss_vector` populated (`NULL`), resulting in `0.0%` CVSS-to-severity band consistency and `"Score: None"` / `"N/A"` rendered in exported PTES reports.
- **Root Cause:** Automated runners and `FindingService.create_finding()` accept `cvss_score=None` and `cvss_vector=None` without invoking a deterministic CVSS v3.1 calculator or validating that `cvss_score` matches the declared severity band.
- **Evidence:** `docs/audit/evidence/phase7/score_p7.txt`, `docs/audit/evidence/phase7/p7_accuracy_audit.json`, `docs/audit/evidence/phase7/p7_completeness_audit.json`.
- **Recommended Fix:** Add deterministic default CVSS v3.1 base vector & score computation by CWE/WSTG class in `FindingService.create_finding()` when unset, and validate `cvss_score` lies within the severity band (`Critical: 9.0–10.0`, `High: 7.0–8.9`, `Medium: 4.0–6.9`, `Low: 0.1–3.9`, `Informational: 0.0`).
- **Regression Test:** `tests/unit/test_finding_cvss_validation.py` asserting non-null `cvss_score`/`cvss_vector` and band consistency on created findings.
- **Acceptance Criteria:** 100% of confirmed findings return valid CVSS v3.1 score & vector consistent with severity in `FindingResponse` and reports.

### 3.29 DEFECT-REP-01 / P1: Empty Report Claims `"STRONG SECURITY POSTURE"` & Unconfirmed Candidates Conflated with Confirmed Findings
- **Components:** `services/reporting_engine/context_builder.py:102-192`, `services/reporting_engine/renderer.py:210-241`
- **Severity:** **P1 (High — Misleading Security Deliverable & Integrity Breach)**
- **Problem:** (1) On a zero-finding project (even with 0 endpoints discovered or 0 tests executed), `context_builder.py:191` emits `"The assessment revealed a STRONG SECURITY POSTURE with zero confirmed high-severity vulnerabilities across the tested target scope"`, falsely claiming the target is secure. (2) `context_builder.py:109` filters only `Finding.status != "False Positive"`, counting unconfirmed `Detected`/`Triaged` candidates directly inside `total_findings` and `risk_summary`, while `renderer.py` (PDF) omits the `Status` column completely.
- **Root Cause:** Hardcoded optimistic `else:` narrative in `context_builder.py:190-191`, and lack of status-based separation (`Confirmed` vs `Candidate`/`Needs Manual Review`) in `ReportContext` and PDF table columns.
- **Evidence:** `docs/audit/evidence/phase7/score_p7.txt` (`P7-TC-REP-02`), `docs/audit/evidence/phase7/p7_report_quality_audit.json` (`empty_report_claims_secure=True`, `mixed_total_reported=2`, `pdf_shows_detected_status=False`).
- **Recommended Fix:** Replace zero-finding text with neutral scope-and-coverage-qualified wording (stating zero confirmed findings were recorded within the executed coverage percentage and noting untested scope); restrict executive risk counts to `Confirmed` findings and render any `Detected`/`Needs Manual Review` items in a clearly separated `"Unconfirmed / Pending Review"` table across both HTML and PDF.
- **Regression Test:** `tests/unit/test_reporting_safety_and_status.py` asserting zero-finding reports never match security-claim phrases and mixed-status projects separate confirmed vs candidate counts in both HTML and PDF.
- **Acceptance Criteria:** `P7-TC-REP-02` passes with `empty_report_claims_secure=False` and `candidate_confirmed_separated=True`.

### 3.30 DEFECT-REP-02 / P2: Ungrounded Capability Boilerplate Claims in PTES HTML Report Template
- **Components:** `services/reporting_engine/templates/ptes_standard.html:334,354,355`
- **Severity:** **P2 (Medium — Factual Accuracy of Client Deliverables)**
- **Problem:** Every generated HTML report hardcodes 4 false platform claims: `"Layer 2 kernel/proxy egress enforcement prevented out-of-scope transmissions"` (`NI-03` absent), `"Katana (headless crawler)"`, `"Httpx (probing)"` (`NI-04` absent), and `"governed by LangGraph"` (`NI-01` absent).
- **Root Cause:** Static aspirational prose from early design docs left in `ptes_standard.html` instead of binding actual executed tools and runtime architecture from `ReportContext`.
- **Evidence:** `docs/audit/evidence/phase7/p7_report_quality_audit.json` (`ungrounded_boilerplate_count=4`).
- **Recommended Fix:** Populate Methodology & Scope sections dynamically from `ReportContext` reflecting actual tools executed (`nuclei`, `ffuf`, Python `httpx` crawler/prober, Layer-1 scope engine, sequential `WorkflowSupervisor`).
- **Regression Test:** Assert generated HTML/PDF contains zero mentions of unimplemented components unless actually executed.
- **Acceptance Criteria:** `ungrounded_boilerplate_count == 0` in `P7-TC-REP-02`.

### 3.31 DEFECT-REDACT-01 / P2: Custom Project Secrets Not Passed to Redactor & Finding Text Fields Unscrubbed
- **Components:** `services/evidence_engine/finding_service.py:478-518`, `services/evidence_engine/redactor.py`
- **Severity:** **P2 (Medium — Incomplete Credential / Canary Redaction)**
- **Problem:** While standard regex patterns redacted 5/5 planted secrets (Bearer JWT, Cookie session, JSON password, form password, Luhn PAN), a planted custom canary secret (`PENTESA_P7_CANARY_SECRET_9f8e7d6c`) leaked unredacted in `raw_response`, `finding_description`, and exported `html_report` (`83.33%` overall).
- **Root Cause:** `FindingService.create_finding()` calls `redact_raw_stream(payload.raw_request)` without passing decrypted project `AuthProfile` secret values as `custom_secrets`, and never runs `redact_raw_stream()` on `finding.title`, `finding.description`, or `finding.remediation_guidance`.
- **Evidence:** `docs/audit/evidence/phase7/score_p7.txt` (`P7-TC-REDACT-02`), `docs/audit/evidence/phase7/p7_test_results.json`.
- **Recommended Fix:** Query project `AuthProfile` secret values (decrypted in memory only) and pass as `custom_secrets` into `redact_raw_stream()` for `raw_request`, `raw_response`, `reproduction_curl`, AND finding narrative fields (`title`, `description`, `remediation_guidance`), plus apply a final redaction pass in `context_builder.py` before report rendering.
- **Regression Test:** `tests/unit/test_canary_redaction_all_surfaces.py` verifying 0 leaks across evidence, finding fields, HTML, and PDF for both standard patterns and project `AuthProfile` custom secrets.
- **Acceptance Criteria:** `canary_secret_redaction_rate_pct == 100.0%` in `P7-TC-REDACT-02`.

### 3.32 DEFECT-DEDUP-01 / P2: No Ingestion-Time Deduplication & Null-Endpoint Over-Clustering on `"global|ANY"`
- **Components:** `services/evidence_engine/finding_service.py:424-553, 899-936`
- **Severity:** **P2 (Medium — Duplicate Bloat & Incorrect Clustering)**
- **Problem:** (1) `POST /api/v1/projects/{id}/findings` inserts duplicate records unconditionally (`ingestion_auto_dedup=False`). (2) `GET /findings/deduplicate` falls back to `path="global", method="ANY"` whenever `finding.endpoint_id is None`, falsely clustering completely distinct findings (`/.env` and `/debug/vars`) with the same CWE as duplicates (`exact_cluster_accuracy=66.7%`).
- **Root Cause:** `create_finding()` does not compute or check a deduplication signature before insertion, and `deduplicate_findings()` does not parse target path/method from `FindingEvidence.raw_request` or `title` when `endpoint_id` is `None`.
- **Evidence:** `docs/audit/evidence/phase7/score_p7.txt` (`P7-TC-DEDUP-01`).
- **Recommended Fix:** Extract normalized `(path, method)` from `Endpoint` or fallback `FindingEvidence.raw_request` (falling back to normalized title hash if neither exists instead of `"global|ANY"`), store `dedup_signature` on `Finding`, and optionally merge/increment `occurrence_count` on `create_finding()`.
- **Regression Test:** `tests/unit/test_finding_dedup_null_endpoint.py` asserting distinct `endpoint_id=None` findings are never merged while exact duplicates cluster cleanly.
- **Acceptance Criteria:** `exact_cluster_accuracy_pct == 100.0%` and `null_endpoint_overclustered == False`.

### 3.33 DEFECT-LIFE-01 / P3 & DEFECT-REPRO-01 / P3: Missing Finding Assignment & cURL Redirect Omission
- **`DEFECT-LIFE-01` (P3 — Finding Assignment Not Implemented):**
  - **Components:** `database/models/finding.py`, `packages/schemas/finding.py`, `apps/api/routers/findings.py`
  - **Problem & Root Cause:** No `assigned_to` FK or assignment API endpoint exists (`P7-TC-LIFE-01`).
  - **Fix & Acceptance Criteria:** Add `assigned_to: Optional[UUID]` FK to `users.id` on `Finding`, expose on `FindingResponse`, and add `PATCH /api/v1/projects/{pid}/findings/{fid}/assign` with audit logging (`FINDING_ASSIGNED`). Regression test verifying assignment + audit entry.
- **`DEFECT-REPRO-01` (P3 — cURL Redirect Omission on `bench-dvwa`):**
  - **Components:** `services/evidence_engine/curl_generator.py`, `agents/wstg/wstg_agent.py`
  - **Problem & Root Cause:** When `wstg_agent` checks a redirecting root URL (`http://bench-dvwa` -> 302 -> `/login.php` 200), stored `raw_response` captures HTTP 200 while generated `curl -i -s 'http://bench-dvwa'` omits `-L` (or the final URL), yielding HTTP 302 on replay (`21/24` = 87.5% status match in `P7-TC-REPRO-01`).
  - **Fix & Acceptance Criteria:** Record the exact final in-scope URL in `raw_request` and `reproduction_curl` so replay HTTP status matches stored `raw_response` 100% (24/24) without requiring unsafe blind `-L` redirect following.

### 3.34 DEFECT-CFG-01 / P3: Default `DATABASE_URL` Silently Falls Back to Local SQLite in Production Mode
- **Components:** `packages/common/config.py:51-55`, `apps/api/main.py:71-79`, `database/session.py:15-19`
- **Severity:** **P3 (Low — Fail-Open Configuration & State-Split Hazard)**
- **Problem:** When `PENTESA_DATABASE_URL` / `DATABASE_URL` is unset in the process environment, `Settings.database_url` (`packages/common/config.py:52`) silently defaults to `sqlite+aiosqlite:///./pentesa.db`. Meanwhile, `validate_encryption_key_startup()` (`apps/api/main.py:71-79`) only checks for hardcoded weak passwords inside `db_url` and does **not** reject `sqlite` URLs when `PENTESA_ENV` is `production` or `staging`. Consequently, misconfigured scripts or services silently read/write a stale local `./pentesa.db` file instead of failing closed (this directly caused the 585-row SQLite vs 1,249-row PostgreSQL audit-chain split in Phase 6 `demo-smoke.txt`).
- **Root Cause:** Permissive SQLite development default in `Settings.database_url` combined with missing dialect/presence assertion in `validate_encryption_key_startup()`.
- **Evidence:** `packages/common/config.py:51-55` (`default="sqlite+aiosqlite:///./pentesa.db"`), `apps/api/main.py:71-79`, `docs/audit/07-security-assessment.md` §4.4a.
- **Recommended Fix:** In `apps/api/main.py:validate_encryption_key_startup()`, when `env not in ("development", "test")`, require `PENTESA_DATABASE_URL` (or `DATABASE_URL`) to be explicitly set and reject any URL starting with `sqlite` (raise `RuntimeError` fail-closed on startup).
- **Regression Test:** `tests/unit/test_startup_fail_closed_db.py` asserting startup raises `RuntimeError` when `PENTESA_ENV=production` and `PENTESA_DATABASE_URL` is unset or `sqlite+aiosqlite:///...`.
- **Acceptance Criteria:** Production/staging startup refuses to boot without an explicit non-SQLite PostgreSQL `PENTESA_DATABASE_URL`.

### 3.35 DEFECT-REL-01 / P1: Workflow State Checkpointing & 15s Resumption Not Implemented
- **Components:** `services/orchestrator/supervisor.py`, `services/execution_engine/worker.py`, `apps/api/routers/agents.py:35-65`
- **Severity:** **P1 (High — Reliability & Workflow Durability Gap)**
- **Problem:** When `pentesa-api` or `pentesa-worker` crashes or restarts during an active assessment, all active workflows are permanently terminated and cannot resume within the 15-second spec threshold (`NFR-REL-01`).
- **Root Cause:** Architectural divergence from PRD/SRS specifications: Celery is absent, `services/execution_engine/worker.py` is an idle stub (`await asyncio.sleep(2)`), and active workflows execute in-memory inside the API process via `_ACTIVE_WORKFLOW_TASKS: Dict[uuid.UUID, asyncio.Task]`. No cyclic PostgreSQL checkpointing exists.
- **Evidence:** `docs/audit/evidence/phase8/8A-spec.md` §2.5, `benchmark/p8/test_runner_p8.py` (`P8-TC-REL-01`), `score_p8.txt`.
- **Recommended Fix:** Introduce durable state persistence via PostgreSQL checkpoints on every agent transition, combined with Celery / Redis task queue with `acks_late=True` and dead-letter handling.
- **Regression Test:** `tests/integration/test_workflow_resumption_on_worker_crash.py`.
- **Acceptance Criteria:** A killed worker restarts, detects the incomplete workflow, and resumes within 15.0s without duplicate tool execution.

### 3.36 DEFECT-SAFE-01 / P2: Error Threshold Backoff Circuit Breaker Not Implemented & Spec Discrepancy
- **Components:** `services/execution_engine/`, `agents/`, `packages/common/http_client.py`
- **Severity:** **P2 (Medium — Scan Safety & Spec Inconsistency)**
- **Problem:** Zero circuit breaker logic is implemented in the platform. When target services return sustained 5xx HTTP error responses, the scanner does not automatically back off or pause (`NFR-SAFE-01`). Additionally, a documentation conflict exists: PRD §4.2 specifies a 15% error rate over a 30s sliding window, whereas System Architecture §6 specifies a 20% error rate over a 60s sliding window.
- **Root Cause:** Missing sliding-window error rate tracker in the HTTP client / execution engine layer, and unaligned specifications between PRD and System Architecture.
- **Evidence:** Codebase search confirming 0 occurrences of circuit breaker / backoff tracking in `services/`, `agents/`, and `integrations/`; `score_p8.txt` (`P8-TC-SAFE-01`).
- **Recommended Fix:** (1) Align documentation to a single authoritative standard (recommend PRD 15% / 30s). (2) Implement a Redis-backed sliding-window error counter that emits an auditable `SCAN_PAUSED_CIRCUIT_BREAKER` event when 5xx errors breach the threshold.
- **Regression Test:** `tests/unit/test_circuit_breaker_sliding_window.py`.
- **Acceptance Criteria:** Target error rate > 15% over 30s transitions scan to PAUSED status within 2 seconds.

### 3.37 DEFECT-SCAL-01 / P2: Cursor Pagination Not Implemented for 10k Items & Findings Unpaginated
- **Components:** `apps/api/routers/discovery.py:103-136`, `apps/api/routers/findings.py:30-52`
- **Severity:** **P2 (Medium — Large Project Scalability Gap)**
- **Problem:** PRD `NFR-SCAL-01` specifies cursor pagination capable of serving 10,000 items per project. In reality, `GET /api/v1/projects/{id}/endpoints` uses SQL `LIMIT ... OFFSET ...`, and `GET /api/v1/projects/{id}/findings` returns all findings unpaginated.
- **Root Cause:** Standard SQL offset pagination used instead of keyset cursor pagination (`WHERE id > :cursor ORDER BY id ASC LIMIT :limit`), and findings router omits pagination parameters entirely.
- **Evidence:** `apps/api/routers/discovery.py:111-112`, `apps/api/routers/findings.py:30-52`, `score_p8.txt` (`P8-TC-SCAL-01`).
- **Recommended Fix:** Implement keyset-based cursor pagination (`cursor: Optional[str]`, `has_more: bool`, `next_cursor: Optional[str]`) on both `/endpoints` and `/findings` endpoints.
- **Regression Test:** `tests/unit/test_cursor_pagination_10k.py`.
- **Acceptance Criteria:** Deep pagination on 10,000 items with cursor exhibits flat latency ($O(1)$) across all pages.

### 3.38 DEFECT-INFRA-01 / P3: Unbounded Container Host Memory Limits Across Compose Services
- **Components:** `docker-compose.yml`, `infrastructure/docker/`
- **Severity:** **P3 (Low — Host Resource Exhaustion Risk)**
- **Problem:** Docker inspect on running production stack reveals that `pentesa-api`, `pentesa-worker`, `pentesa-db`, `pentesa-redis`, and `pentesa-web` have `HostConfig.Memory = 0` (unbounded host RAM) and no PID limits (`PidsLimit = None`). A runaway fuzzer or memory leak can consume all host memory, risking host OOM panic.
- **Root Cause:** `docker-compose.yml` lacks `deploy.resources.limits` configuration blocks for memory and pids.
- **Evidence:** `docs/audit/evidence/phase8/p8_test_results.json` (`P8-TC-LIM-01`), `score_p8.txt`.
- **Recommended Fix:** Add explicit resource constraints in `docker-compose.yml`: memory limits (API: 2GB, Worker: 2GB, DB: 1GB, Redis: 512MB, Web: 1GB) and PID limits (API/Worker: 200).
- **Acceptance Criteria:** `docker inspect` shows non-zero memory and pid limits across all 5 production containers.

### 3.39 DEFECT-RES-01 / P2: Subprocess Cancellation Risk (`asyncio.CancelledError` Inherits `BaseException`)
- **Components:** `services/execution_engine/tools/base.py:216-240`
- **Severity:** **P2 (Medium — Subprocess Lifecycle / Orphan Risk)**
- **Problem:** In Python 3.8+, `asyncio.CancelledError` inherits from `BaseException`, not `Exception`. `BaseToolWrapper.execute()` catches `asyncio.TimeoutError` and generic `Exception`, but does **not** catch `asyncio.CancelledError`. When an API workflow task is cancelled, the awaiting coroutine is cancelled immediately, bypassing subprocess termination and risking orphan `ffuf` or `nuclei` background processes.
- **Root Cause:** Missing `except asyncio.CancelledError:` block or `finally:` block with `proc.kill()` in `BaseToolWrapper.execute()`.
- **Evidence:** `services/execution_engine/tools/base.py:216-240`, `score_p8.txt` (`P8-TC-RES-01`).
- **Recommended Fix:** In `BaseToolWrapper.execute()`, ensure subprocess handle is terminated in a `finally:` block if `proc.returncode is None`.
- **Regression Test:** `tests/unit/test_subprocess_cleanup_on_task_cancel.py`.
- **Acceptance Criteria:** Task cancellation sends `SIGKILL` to subprocess and waits for exit, leaving 0 orphan processes.

### 3.40 DEFECT-HOST-01 / P2: Missing Chunk/Streaming Read Timeouts on Hostile Target Responses
- **Components:** `packages/common/http_client.py:45-75`, `services/discovery_engine/crawler.py`
- **Severity:** **P2 (Medium — Scanner Hang Resilience)**
- **Problem:** When probing a target that emits an HTTP slow-drip response (1 byte every 1.0 second), standard `httpx.Timeout(5.0)` does not fire because each chunk arrives before the idle read timeout. This causes the scanner worker thread to hang indefinitely until the hard task timeout.
- **Root Cause:** HTTP clients configure connect/read timeouts, but do not enforce a cumulative total streaming duration cap on individual HTTP response bodies.
- **Evidence:** `docs/audit/evidence/phase8/p8_test_results.json` (`P8-TC-HOST-01`), `score_p8.txt` (slow_drip: HANG).
- **Recommended Fix:** Implement cumulative stream duration enforcement in `packages/common/http_client.py` via `asyncio.timeout()` wrapping the entire request + body iteration stream.
- **Regression Test:** `tests/unit/test_slow_drip_stream_timeout.py`.
- **Acceptance Criteria:** Target returning 1 byte/sec is terminated and reported within 5.0 seconds maximum.






