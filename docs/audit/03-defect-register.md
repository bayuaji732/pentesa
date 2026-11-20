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
| **P3-AUTH-02** | **P2** | Authentication | `apps/api/routers/auth.py` | Missing Rate Limiting on User Login Endpoint (`POST /api/v1/auth/login`) | Open (Documented) | Phase 9 (Redis-backed token bucket rate limiting) |

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
  2. `P6-TC-AUTH-04` passes with verified throttling.





