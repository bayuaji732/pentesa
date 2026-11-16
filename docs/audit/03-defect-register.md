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
| **DISCO-SPA-01** | **P2** | Discovery | `services/discovery_engine/fingerprint.py` | Technology Fingerprinter Misses SPAs Lacking Server Headers | Open (Deferred) | Phase 9 (DOM Parsing Roadmap) |

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


