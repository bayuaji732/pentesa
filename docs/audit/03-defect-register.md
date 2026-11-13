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

| Defect ID | Severity | Category | Component / Path | Title | Status | Target Fix |
|---|---|---|---|---|---|---|
| **NI-03** | **P0-KNOWN** | Scope / Egress | `integrations/nuclei/`, `integrations/ffuf/` | Tool Subprocess Redirect Egress Breach | Open (Lab-Only) | FIX-06 (Interim) / Phase 3 |
| **SEC-RED-01** | **P0** | Scope / Egress | `services/execution_engine/tools/http_client.py`, `services/discovery_engine/crawler.py` | Python-Layer HTTP Client Redirect Scope Bypass | In Progress | FIX-01 |
| **SEC-KEY-01** | **P0** | Cryptography | `packages/common/security.py`, `packages/common/config.py` | `derive_aes_key()` Fails Open to Static Master Key Literal | In Progress | FIX-02 |
| **SEC-PWD-01** | **P1** | Authentication | `database/seeds/seed_data.py`, `docker-compose.yml`, `.env.example` | Unconditional Seeding of Static Admin & Default Database Passwords | In Progress | FIX-03 |
| **AGT-MOCK-01** | **P1** | AI Safety | `agents/llm/provider.py`, `packages/common/config.py` | `MockLLMProvider` Selectable Outside `PENTESA_ENV=test` | In Progress | FIX-04 |
| **TOOL-TMPL-01** | **P1** | Integrations | `infrastructure/docker/Dockerfile.api`, `integrations/nuclei/runner.py` | Official Nuclei Templates Not Baked into Production Docker Image | In Progress | FIX-05 |
| **TOOL-WORD-01** | **P1** | Integrations | `infrastructure/docker/Dockerfile.api`, `integrations/ffuf/runner.py` | Production Wordlist Missing from Base Docker Image | In Progress | FIX-05 |
| **AGT-LLM-01** | **P1** | AI Engine | `apps/api/routers/agents.py`, `services/orchestrator/supervisor.py` | Unhandled HTTP 500 on LLM Gateway / Network Disconnect | In Progress | FIX-07 |
| **DISCO-SPA-01** | **P2** | Discovery | `services/discovery_engine/fingerprint.py` | Technology Fingerprinter Misses SPAs Lacking Server Headers | Open (Deferred) | Phase 3 |

---

## 3. Detailed Forensic Defect Entries

### 3.1 P0-KNOWN (NI-03): Tool Subprocess Redirect Egress Breach
- **Components:** `integrations/nuclei/runner.py`, `integrations/ffuf/runner.py`
- **Vulnerability Description:** External binary subprocesses spawned via `asyncio.create_subprocess_exec` (`nuclei -fr`, `ffuf -r`) directly follow HTTP 302 redirects issued by an in-scope host to an out-of-scope host. In Phase 2 testing, `redirector:9098` issued a 302 redirect to `http://canary:9099/canary-trap`. Both `nuclei` and `ffuf` followed the redirect and transmitted requests to the out-of-scope canary service.
- **Evidence:** Canary log recorded direct connections from `172.21.0.5`:
  ```json
  {"timestamp": "2026-11-13T22:31:12.196980+00:00", "client_address": "172.21.0.5", "method": "GET", "path": "/canary-trap", "headers": {"Host": "canary:9099", "User-Agent": "Mozilla/5.0..."}}
  ```
- **Remediation & Interim Action:** Subprocesses cannot inspect redirect hops in software without an external proxy. Interim fix (FIX-06): Disallow redirect-following flags in CLI runners. Permanent remediation: Dedicated Layer-2 Egress Proxy container with iptables enforcement. Binaries marked **lab-only**.

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
