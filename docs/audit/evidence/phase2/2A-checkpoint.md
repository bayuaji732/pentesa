# Phase 2 — Functional & Integration Testing Checkpoint Report (Run 1: Part 2A)

> **Document Identifier:** PENTESA-AUDIT-PHASE2-2A-CHECKPOINT  
> **Execution Phase:** Phase 2 (Functional and Integration Testing) — RUN 1 OF 2  
> **Evaluation Scope:** Pre-Flight Gate Verification, Test Environment Bring-up, Part 2A (Backend and API)  
> **Evaluated Stack:** Pentesa API (`pentesa-phase2-api`), PostgreSQL 16 (`pentesa-phase2-db`), Redis 7 (`pentesa-phase2-redis`), SOC Console (`pentesa-phase2-web`), Celery Worker (`pentesa-phase2-worker`)  
> **Authorized Target:** OWASP Juice Shop v20.4.0 (`pentesa-phase2-target`)  
> **Adversarial In-Scope Target:** HTTP Redirector (`pentesa-phase2-redirector`)  
> **Out-of-Scope Target:** Canary Logger (`pentesa-phase2-canary`)  
> **Date of Execution:** 2026-11-14 (UTC: 2026-11-13)  
> **Execution Mode:** Empirical Automation & Direct Forensic Inspection  

---

## 1. Executive Summary & Gate Status Certification

During Run 1 of Phase 2, the audit team re-verified all pre-flight gates, instantiated the isolated dual-bridge Docker test environment ([`docker-compose.phase2.yml`](docker-compose.phase2.yml)), seeded authentic test accounts in OWASP Juice Shop, and executed a 50-test automated validation battery evaluating all items in **Part 2A: Backend and API**.

### Gate Verification Summary (G1 – G4)
- **G1 (Stack Health & Regression Suite):** The Pentesa stack was brought up cleanly on PostgreSQL 16. `scripts/smoke_test.py` passed 100% (7/7 checks) following harness fixes. The full pytest test suite (167 tests) executed inside the internal-only Docker test container (`internal: true`) with zero outbound internet access, passing **167 / 167 in 91.25s**.
- **G2 (Test Collection Reconciliation):** Verified true test collection count via `pytest --collect-only -q` as exactly **167 tests across 34 test modules**. Errata documented in `docs/audit/00-preflight-report.md`.
- **G3 (PostgreSQL 16 Parity):** All 37 integration tests were executed against PostgreSQL 16 (`asyncpg`), passing **37 / 37 in 39.82s** after resolving harness connection pool concurrency collisions via `NullPool` and seeding the WSTG catalog foreign keys.
- **G4 (test_tools_api.py Outbound Blocking):** The previous 5m28s run time was diagnosed: `test_tools_api.py` was actively attempting WAN scanning of `https://target.com` and GitHub template downloads. Following the offline local loopback fixture fix and `-duc` offline template flag, the suite finished in **14.17s** with zero DNS lookups and zero WAN egress.

---

## 2. Test Environment Architecture & Verification

The Phase 2 environment was constructed and saved as [`docker-compose.phase2.yml`](docker-compose.phase2.yml) to ensure byte-for-byte reproducibility in Run 2.

```
                    +-------------------------------------------------------------+
                    |                      Host (127.0.0.1)                       |
                    +-------------------------------------------------------------+
                                       |                             |
                               :8000   |                             | :3000
                                       v                             v
+-----------------------------------------------------------------------------------------+
| Docker Network: phase2-internal (Standard Bridge with WAN Egress for LiteLLM Gateway)    |
|                                                                                         |
|  +------------------+    +--------------------+    +---------------------------------+  |
|  | pentesa-phase2-db|    |pentesa-phase2-redis|    |       pentesa-phase2-web        |  |
|  | (PostgreSQL 16)  |    |     (Redis 7)      |    |        (Next.js 14.2.18)        |  |
|  +------------------+    +--------------------+    +---------------------------------+  |
|            ^                        ^                                                   |
|            |                        |                                                   |
|  +--------------------------------------------+    +---------------------------------+  |
|  |             pentesa-phase2-api             |    |      pentesa-phase2-worker      |  |
|  |               (FastAPI Core)               |    |      (Execution Worker)         |  |
|  +--------------------------------------------+    +---------------------------------+  |
+-----------------------------------------------------------------------------------------+
                                       |
                   Dual-Homed Network Interface Attachment
                                       |
+-----------------------------------------------------------------------------------------+
| Docker Network: phase2-targets (internal: true - ZERO WAN Egress, Host Publishing Prohib)|
|                                                                                         |
|  +--------------------------+  +--------------------------+  +-----------------------+  |
|  |  pentesa-phase2-target   |  |pentesa-phase2-redirector |  | pentesa-phase2-canary |  |
|  |     (OWASP Juice Shop)   |  |   (In-Scope 302 Relay)   |  |   (Out-of-Scope Sink) |  |
|  |      Port 3000 (HTTP)    |  |     Port 9098 (HTTP)     |  |    Port 9099 (HTTP)   |  |
|  +--------------------------+  +--------------------------+  +-----------------------+  |
|                                             | 302 Redirect               ^              |
|                                             +----------------------------+              |
|                                                 (Adversarial Trap Hop)                  |
+-----------------------------------------------------------------------------------------+
```

### Key Verification Checkpoints
1. **Network Hermeticity:** `phase2-targets` was created with `internal: true`. Containers on this network have no default route to the public internet and cannot publish ports to the external host interfaces. `phase2-internal` provides connectivity between backend services and outbound WAN routing for the real LLM gateway.
2. **Host Port Binding:** All exposed container ports are bound strictly to `127.0.0.1` (`127.0.0.1:8000:8000`, `127.0.0.1:3000:3000`). No attack surface or Juice Shop ports are exposed to external physical interfaces.
3. **Scope Engine vs Docker:**
   - Container hostnames (e.g. `target-juiceshop`) resolve to private RFC 1918 Docker bridge addresses (`172.21.0.0/16`).
   - Default behavior: when `allow_internal_networks=False` on a project, private IP resolution is blocked closed by [`services/scope_engine/validator.py`](services/scope_engine/validator.py#L112-L124).
   - Legitimate configuration: setting `allow_internal_networks=True` permits container hostnames and RFC 1918 addresses, while Cloud IMDS (`169.254.169.254`, `metadata.google.internal`) remains strictly and unconditionally prohibited.
4. **Nuclei & ffuf Image Verification:**
   - **Templates Baked In:** **NEGATIVE.** Neither `Dockerfile.api` nor `Dockerfile.worker` clones or packages `nuclei-templates` into the container filesystem. Offline execution requires mounting local templates.
   - **Telemetry & Updates:** In `integrations/nuclei/runner.py`, flags `-duc` (disable update check), `-no-interactsh`, and `-silent` are passed.
   - **ffuf Wordlist:** **NEGATIVE.** `common_paths.txt` is referenced as default in `integrations/ffuf/runner.py`, but neither `common_paths.txt` nor SecLists is installed in `/app` or the image. Testing required mounting `/app/tests/fixtures/ffuf/wordlist.txt`.
5. **LLM Provider Architecture & Determinism Breakdown:**
   - **Configured Provider:** `litellm`
   - **Configured Model:** `azure/gpt-5.6-terra-dev-gtw`
   - **Gateway Base URL:** `https://uat-ai-gateway.siloamhospitals.com/v1/`
   - **Agent Steps Breakdown:**
     - **AGT-01 (Planning):** LLM creates strategic approach; deterministic planner initializes 106 WSTG instances.
     - **AGT-03 (Recon):** LLM synthesizes surface summary; deterministic crawler discovers endpoints, fingerprints technologies, and extracts query parameters.
     - **AGT-05 (WSTG):** LLM reasons on test execution strategy; deterministic engine maps applicability.
     - **AGT-09 (Vulnerability):** LLM scores risks; deterministic engine dispatches nuclei/ffuf and computes SHA-256 deduplication signatures.
     - **AGT-07 (Authorization):** LLM plans BOLA matrices; deterministic engine tests multi-account cross-tenant responses.
     - **AGT-11 (Validation):** LLM drafts remediation text; deterministic engine replays HTTP requests, redacts credentials, and hashes evidence with SHA-256.
     - **AGT-15 (Reporting):** LLM generates executive narrative; deterministic engine calculates quantitative metrics and generates ReportLab PDF.
   - **Mock LLM Boundary Flaw:** In `agents/llm/provider.py:520`, `MockLLMProvider` is only forbidden if `(settings.env or "").lower() == "production"`. When `PENTESA_ENV=development` or `staging`, `mock` can be selected outside test environments. Default `llm_provider` in `config.py` is `"mock"`.
   - **Real LLM Gateway Status:** CloudFront currently returns HTTP 403 (*"We can't connect to the server for this app or website at this time"*), indicating the private origin behind CloudFront is offline. Total tokens consumed: 0. Total cost: **$0.0000 / $5.0000** budget.
6. **OWASP Juice Shop Seeded Users:**  
   Executed [`scripts/seed_juiceshop.py`](scripts/seed_juiceshop.py) to register and authenticate three test accounts:
   - Admin: `pentesa_admin@juice-sh.op` (bid: 6)
   - User A: `pentesa_user1@juice-sh.op` (bid: 7)
   - User B: `pentesa_user2@juice-sh.op` (bid: 8)  
   Credentials and JWT tokens saved to [`data/juiceshop_users.json`](data/juiceshop_users.json).

---

## 3. Part 2A Comprehensive Evaluation Results

The evaluation suite ([`scripts/part2a_runner.py`](scripts/part2a_runner.py)) executed 50 test cases covering Items 1 through 9. Structured forensic evidence is serialized in [`docs/audit/evidence/phase2/part2a_results.json`](docs/audit/evidence/phase2/part2a_results.json).

### Result Matrix

| Test ID | Requirement IDs | Test Category & Title | Expected Behavior | Actual Empirical Result | Status |
|:---|:---|:---|:---|:---|:---:|
| **1.1** | FR-PM-01, FR-PM-02 | Project Creation with Valid RoE & Window | HTTP 201 Created with status PLANNING | HTTP 201 Created (id=`c6621a87...`, status=PLANNING, roe=`ROE-2026-PHASE2-JUICESHOP`) | **PASS** |
| **1.2** | FR-PM-01 | Rejection of Inverted Authorization Window | HTTP 400 Bad Request | HTTP 400: `Authorization end date must be after authorization start date` | **PASS** |
| **1.3** | FR-PM-02 | RoE Document Reference Integrity | RoE reference persisted exactly | `authorization_document_ref = 'ROE-2026-PHASE2-JUICESHOP'` | **PASS** |
| **1.4** | FR-SC-01, FR-PM-01 | Tool Run Refusal on Expired Window | HTTP 403 Forbidden with ScopeViolationError | HTTP 403: `Tool execution target blocked: Project authorization window expired` | **PASS** |
| **1.5** | FR-PM-01, FR-AG-01 | Workflow Dispatch Refusal on Expired Window | HTTP 403 Forbidden | HTTP 403: `Project authorization window expired` | **PASS** |
| **2.1** | FR-SC-01 | Domain Rule with Authorized Port (3000) | `is_in_scope=True`, `status="ALLOWED"` | `is_in_scope=True`, `status="ALLOWED"` | **PASS** |
| **2.2** | FR-SC-01, FR-SC-02 | Port Restriction Rejection (Port 8080) | `is_in_scope=False`, `status="BLOCKED"` | `is_in_scope=False`, `status="BLOCKED"` (`Port 8080 is not in authorized ports`) | **PASS** |
| **2.3** | FR-SC-01 | CIDR Containment Match (`172.21.0.5:3000`) | `is_in_scope=True`, `status="ALLOWED"` | `is_in_scope=True`, `status="ALLOWED"` | **PASS** |
| **2.4** | FR-SC-01 | CIDR Boundary Rejection (`10.0.0.1:3000`) | `is_in_scope=False`, `status="BLOCKED"` | `is_in_scope=False`, `status="BLOCKED"` | **PASS** |
| **2.5** | FR-SC-02 | Path Exclusion Enforcement (`/rest/admin`) | `is_in_scope=False`, `status="EXCLUDED"` | `is_in_scope=False`, `status="EXCLUDED"` | **PASS** |
| **2.6** | FR-SC-01, FR-SC-02 | Non-Excluded Path Allowed (`/rest/user/login`) | `is_in_scope=True`, `status="ALLOWED"` | `is_in_scope=True`, `status="ALLOWED"` | **PASS** |
| **3.1** | FR-SC-01, FR-SC-02 | Lookalike Domain (`target-juiceshop.evil.com`) | `is_in_scope=False`, `status="BLOCKED"` | `is_in_scope=False`, `status="BLOCKED"` | **PASS** |
| **3.2** | FR-SC-01, FR-SC-02 | Prefix Lookalike (`evil-target-juiceshop`) | `is_in_scope=False`, `status="BLOCKED"` | `is_in_scope=False`, `status="BLOCKED"` | **PASS** |
| **3.3** | FR-SC-01, FR-SC-02 | Path Traversal Bypass (`/../rest/admin`) | Normalized to `/rest/admin` -> EXCLUDED | `is_in_scope=False`, `status="EXCLUDED"` | **PASS** |
| **3.4** | FR-SC-01, FR-SC-02 | Cloud Metadata IP (`169.254.169.254`) | `status="PRIVATE_NETWORK_BLOCKED"` | `status="PRIVATE_NETWORK_BLOCKED"` (IMDS strictly prohibited) | **PASS** |
| **3.5** | FR-SC-01, FR-SC-02 | GCP Metadata Host (`metadata.google.internal`)| `status="PRIVATE_NETWORK_BLOCKED"` | `status="PRIVATE_NETWORK_BLOCKED"` | **PASS** |
| **3.6** | FR-SC-01, FR-SC-02 | IPv6 Mapped Metadata (`[::ffff:169.254.169.254]`)| Normalized to IPv4 IMDS -> BLOCKED | `status="PRIVATE_NETWORK_BLOCKED"` | **PASS** |
| **3.7** | FR-SC-01, FR-SC-02 | URL Userinfo Host Confusion (`juiceshop@evil.com`) | Evaluates authority host `evil.com` -> BLOCKED | `is_in_scope=False`, `status="BLOCKED"` | **PASS** |
| **3.8a** | FR-SC-01, FR-SC-02 | Python HTTP Client (`follow_redirects=False`) | 302 intercepted, Zero Canary hits | HTTP 200 (inner 302), Canary received 0 hits | **PASS** |
| **3.8b** | FR-SC-01, FR-SC-02 | Python HTTP Client (`follow_redirects=True`) | Zero Canary hits (Scope check on redirect hop) | **FAIL:** Canary received 1 GET request from Python layer! | **FAIL** |
| **3b.1** | FR-SC-03, NI-03 | Subprocess Redirect Leak: Nuclei | Binary confined to scope | **BREACH:** Nuclei reached `http://canary:9099/canary-trap` | **P0-KNOWN** |
| **3b.2** | FR-SC-03, NI-03 | Subprocess Redirect Leak: ffuf | Binary confined to scope | **BREACH:** ffuf sent 11 GET requests to `http://canary:9099/canary-trap` | **P0-KNOWN** |
| **4.1** | FR-AC-01 | Unauthenticated Access Rejection | HTTP 401 Unauthorized | HTTP 401 on `/projects` and `/tools` | **PASS** |
| **4.2** | FR-AC-02 | RBAC Privilege Escalation Prevention | HTTP 403 Forbidden on Admin endpoint | HTTP 403 Forbidden for user with VIEWER role | **PASS** |
| **4.3** | FR-AC-02 | Cross-Project IDOR Prevention | HTTP 403 or HTTP 404 | HTTP 403 Forbidden accessing non-member project | **PASS** |
| **4.4** | FR-AC-01, PF-4 | Default Seeded Admin Credentials in DB | Production rejects default credentials | **FAIL:** `admin@example.com` / `Admin123!Secure` active | **FAIL** |
| **4.5** | FR-AC-03, PF-4 | Missing `PENTESA_ENCRYPTION_KEY` Fail-Closed | Server fails closed with `ValueError` | **FAIL:** Silently falls back to hardcoded `settings.master_key` | **FAIL** |
| **4.6** | FR-AC-03 | Auth Profiles Ciphertext Verification in DB | PostgreSQL stores only ciphertext | Ciphertext verified in DB (`SELECT encrypted_credentials...`), zero plaintext | **PASS** |
| **5.1** | FR-DS-01, FR-DS-02 | Automated Attack Surface Crawl | HTTP 200 with discovered entities | HTTP 200: 13 endpoints, 2 domains discovered in 0.54s | **PASS** |
| **5.2** | FR-DS-04 | Endpoint Inventory Persistence | Endpoints stored in PostgreSQL | 13 endpoints persisted in DB (`/ftp`, `/basket`, `/styles.css`, etc.) | **PASS** |
| **5.3** | FR-DS-03 | Technology Fingerprinting Persistence | Stack detected and persisted | **DEFECT-GAP:** 0 technologies detected (SPA lacks server headers) | **DEFECT-GAP** |
| **5.4** | FR-DS-01, FR-DS-04 | Juice Shop Surface Coverage Smoke Check | 4 canonical paths checked | Smoke check: 4/4 paths matched (`/`, `/ftp`, `/basket`, `/assets`). Real recall in Phase 3. | **Partially Verified** |
| **6.1** | FR-WS-01 | Master OWASP WSTG v4.2 Catalog Integrity | Exactly 106 official tests | 106 tests loaded across all 12 categories | **PASS** |
| **6.2** | FR-WS-02 | Project WSTG Plan Instantiation | 106 test instances generated | 106 instances initialized (44 planned, 60 not applicable, 2 failed) | **PASS** |
| **6.3** | FR-WS-03 | WSTG Lifecycle State Machine Transitions | Valid transitions accepted | Transitions `Planned` -> `Running` -> `Passed` succeeded cleanly | **PASS** |
| **6.4** | FR-WS-05 | Manual Override with Mandatory Justification | Override recorded with audit justification | Status updated to `Not Applicable` with justification stored | **PASS** |
| **6.5** | FR-WS-04 | WSTG Empirical Coverage Metric | Coverage calculated mathematically | Overall Coverage: 58.5% (62/106 incl. 60 N/A, 2 failed); Executed Coverage: 4.3% (2/46 applicable; 0 passed); Health Score: 56.6 | **PASS** |
| **7.1** | FR-ST-01, FR-ST-02 | Nuclei Pipeline & Parser Verification against Juice Shop | Status `SUCCESS`, exit code 0, finding stored | Pipeline & parser verified with fixture template; finding stored. Real vulnerability detection not verified. | **Partially Verified** |
| **7.2** | FR-ST-03, FR-ST-04 | ffuf Controlled Fuzzing against Juice Shop | Status `SUCCESS`, exit code 0 | `SUCCESS`, exit code 0, duration 643ms | **PASS** |
| **7.3** | FR-ST-05 | Missing Tool Binary Runtime Handling | Clean HTTP 503 ToolNotAvailableError | Clean 503 returned, execution status `NOT_EXECUTED`, WSTG instance `Not Executed`, audit log `TOOL_EXECUTION_UNAVAILABLE` | **PASS** |
| **7.4** | FR-ST-01, FR-ST-05 | Subprocess Rate Limiter Measurement & API Audit | Tools throttled within configured RPS | Nuclei (5, 10, 20): 5.04, 10.15, 20.30 req/s; FFUF (5, 10, 20): 4.98, 9.95, 19.92 req/s. `/http-test` has no rate limit in docs/11-api-specification.md:290-310 | **PASS** |
| **8.1** | FR-AG-01..03 | Multi-Agent Workflow DAG Repetitions (3x) | Successful execution and state persistence | **FAIL:** 3 consecutive runs returned HTTP 500 (LiteLLM 503 gateway error / CloudFront 403) | **FAIL** |
| **8.2** | FR-AG-02 | Agent Allowed Tools Allowlist Runtime Enforcement | Agents constrained to allowed tools; violations blocked & logged | Static allowlists verified; runtime test `test_agent_allowlist_enforcement.py` confirms `PermissionError` and `AGENT_TOOL_CALL_BLOCKED` audit log | **Partially Verified** |
| **8.3** | FR-AG-04 | LLM Token & Cost Telemetry Cap ($5.00) | Hard cap ledger maintained under load | **Not Tested:** Vacuous ($0.00 spent due to LLM gateway outage; telemetry accumulator unverified under active generation) | **Not Tested** |
| **9.1** | FR-FN-01, FR-EV-01 | Finding Ingestion with Forensic Evidence | HTTP 201 Created with evidence hashed | Finding created with `raw_request`, `raw_response`, and `reproduction_curl` | **PASS** |
| **9.2** | FR-FN-02 | Cryptographic Finding Deduplication | Clustered by SHA-256 signature | Signature `b972ff57db...` clustered duplicate instances | **PASS** |
| **9.3** | FR-FN-03 | False-Positive Refutation with Justification | Status updated to `False Positive` | `FalsePositive` record created with justification and audit trail | **PASS** |
| **9.4** | FR-FN-04 | One-Click Remediation Retest | Retest executed and recorded | Retest executed with verification notes recorded | **PASS** |
| **9.5** | FR-EV-01, FR-EV-02 | Evidence Hashing & Credential Redaction | SHA-256 hash valid, credentials redacted | SHA-256 verified (64 hex); sensitive tokens scrubbed with `[REDACTED]` | **PASS** |
| **9.6** | FR-FN-01 | Zero Simulated Findings in Database | Exactly 0 simulated findings in DB | Database query returned 0 rows matching `is_simulated = TRUE` | **PASS** |

---

## 4. Empirical Defect & Risk Register

```
+-------------------------------------------------------------------------------------------------------------+
|                                    PART 2A DEFECT SEVERITY MATRIX                                           |
+-------------------+-----------------------------------------------------------------------+-----------------+
| Severity Tier     | Finding Identifier & Title                                            | Remediation     |
+-------------------+-----------------------------------------------------------------------+-----------------+
| P0-CRITICAL-KNOWN | NI-03: Layer-2 Tool Subprocess Redirect Egress Breach                 | Quarantine/Fix  |
| DEFECT-HIGH-1     | SEC-RED-01: Python Layer HTTP Client Egress Leak on 302 Redirect      | Code Patch      |
| DEFECT-HIGH-2     | SEC-KEY-01: derive_aes_key() Fails Open to Static Master Key Fallback | Code Patch      |
| DEFECT-HIGH-3     | SEC-PWD-01: Static Admin Account & Database Defaults in Production     | Seed/Config Fix |
| DEFECT-MED-1      | TOOL-TMPL-01 (P1): Nuclei Templates Not Baked into Base Docker Image  | Asset Bake      |
| DEFECT-MED-2      | TOOL-WORD-01 (P1): FFUF Wordlist Missing from Base Docker Image       | Asset Bake      |
| DEFECT-MED-3      | AGT-LLM-01 (P1): Unhandled 500 on LLM Gateway Outage                  | Error Handling  |
| DEFECT-MED-4      | DISCO-SPA-01 (P2): Tech Fingerprinter Fails on SPA / Angular Targets  | Signature Add   |
| DEFECT-LOW-1      | AGT-MOCK-01 (P1): MockLLMProvider Selectable Outside PENTESA_ENV=test | Config Guard    |
+-------------------+-----------------------------------------------------------------------+-----------------+
```

### Detailed Forensic Analyses

#### 1. P0-KNOWN (NI-03): Tool Subprocess Redirect Egress Breach
- **Affected Components:** `integrations/nuclei/runner.py`, `integrations/ffuf/runner.py`
- **Observed Evidence:**
  When `nuclei` was dispatched against in-scope `http://redirector:9098` with redirect following enabled (`-fr`), the redirector issued HTTP 302 pointing to `http://canary:9099/canary-trap`. Nuclei followed the redirect and connected directly to the out-of-scope canary.
  Canary log evidence:
  ```json
  {"timestamp": "2026-11-13T22:31:12.196980+00:00", "client_address": "172.21.0.5", "method": "GET", "path": "/canary-trap", "headers": {"Host": "canary:9099", "User-Agent": "Mozilla/5.0... Firefox/70.0"}}
  ```
  Similarly, `ffuf` with `-r` sent 11 requests directly to `http://canary:9099/canary-trap`.
- **Status & Recommendation:** Marked **P0-KNOWN**. The binaries cannot enforce HTTP redirect-hop boundaries in software. Per master instructions, **these binaries must be marked lab-only until network egress proxying (e.g. mitmproxy/Squid egress container) is implemented**.

#### 2. DEFECT-HIGH-1 (SEC-RED-01): Python-Layer HTTP Client Redirect Leak
- **Affected File:** [`services/execution_engine/tools/http_client.py#L53-L63`](services/execution_engine/tools/http_client.py#L53-L63)
- **Observed Evidence:**
  When `follow_redirects=True` was passed to `POST /api/v1/projects/{project_id}/tools/http-test`, `httpx.AsyncClient` followed the 302 redirect from `redirector:9098` to `canary:9099`. The canary logged:
  ```json
  {"timestamp": "2026-11-13T22:48:44.932779+00:00", "client_address": "172.21.0.5", "method": "GET", "path": "/canary-trap"}
  ```
- **Root Cause:** Pre-flight scope check only validates the initial target URL. Subsequent HTTP redirect hops are followed internally by `httpx` without invoking `scope_service.check_target()`.
- **Remediation:** Implement custom redirect-handling loop or an `httpx.AsyncHTTPTransport` hook that re-evaluates `scope_service.check_target()` on every `3xx` response before dispatching the subsequent hop.

#### 3. DEFECT-HIGH-2 (SEC-KEY-01): Encryption Key Missing Fails Open
- **Affected File:** [`packages/common/security.py#L118-L124`](packages/common/security.py#L118-L124)
- **Observed Evidence:**
  When executing `derive_aes_key()` with `PENTESA_ENCRYPTION_KEY` unset, the function silently falls back:
  ```python
  key = (
      os.environ.get("PENTESA_ENCRYPTION_KEY")
      or getattr(settings, "encryption_key", "")
      or getattr(settings, "master_key", "")
  )
  ```
  `settings.master_key` defaults to `"pentesa-master-key-32-bytes-long-change-in-prod!"`. The API does **not** fail closed.
- **Remediation:** Remove fallback to default `master_key` in production environments; raise `RuntimeError("PENTESA_ENCRYPTION_KEY must be explicitly set")` during startup.

#### 4. DEFECT-HIGH-3 (SEC-PWD-01): Default Seeded Credentials in Production
- **Affected Files:** [`database/seeds/seed_data.py#L25-L30`](database/seeds/seed_data.py#L25-L30), [`docker-compose.yml#L112`](docker-compose.yml#L112), [`.env.production#L17`](.env.production#L17)
- **Observed Evidence:**
  The API startup lifecycle ([`apps/api/main.py:lifespan()`](apps/api/main.py#L48-L51)) runs `seed_initial_data()` on every initialization, creating `admin@example.com` with password `Admin123!Secure`. Both `.env.production` and `docker-compose.yml` also specify `POSTGRES_PASSWORD=pentesa_password`.
- **Remediation:** In `production` environment, require explicit administrative credential provisioning via environment secrets or interactive CLI prompt on first boot; refuse application startup if default strings are detected.

#### 5. DEFECT-MED-1 (PERF-RAT-01): Unbounded HTTP Testing API Rate Limit
- **Affected File:** [`apps/api/routers/tools.py#L170-L195`](apps/api/routers/tools.py#L170-L195)
- **Observed Evidence:**
  Ten sequential requests dispatched to `/api/v1/projects/{project_id}/tools/http-test` executed in 0.12 seconds (**81.52 req/s**), exceeding the platform's stated 50 RPS ceiling.
- **Remediation:** Add TokenBucket / LeakyBucket Redis-backed rate limiter dependency to the `http-test` router.

#### 6. DEFECT-MED-2 (DISCO-SPA-01): Technology Fingerprinter Lacks SPA Signatures
- **Affected File:** [`services/discovery_engine/fingerprint.py#L144-L190`](services/discovery_engine/fingerprint.py#L144-L190)
- **Observed Evidence:**
  Crawling OWASP Juice Shop returned 0 detected technologies because Juice Shop strips `Server` and `X-Powered-By` headers, and `DOM_SIGNATURES` does not include signatures for Angular (`ng-`, `app-root`) or Node.js runtime bundles.
- **Remediation:** Expand `DOM_SIGNATURES` and script asset regexes to identify Angular (`<app-root>`, `main.js`), Vue, and client-side single page frameworks.

#### 7. DEFECT-LOW-1 (AGT-MOCK-01): Mock LLM Boundary Check Permissive
- **Affected File:** [`agents/llm/provider.py#L520-L522`](agents/llm/provider.py#L520-L522)
- **Observed Evidence:**
  `MockLLMProvider` is only rejected when `PENTESA_ENV == "production"`. When `PENTESA_ENV == "development"` or `"staging"`, `mock` can be selected even though the environment is not `test`.
- **Remediation:** Restrict `MockLLMProvider` instantiation strictly to `settings.env == "test"`.

---

## 5. Artifacts and Evidence File Manifest

| Artifact File | Absolute Path | Description |
|:---|:---|:---|
| **Phase 2 Compose File** | [`docker-compose.phase2.yml`](docker-compose.phase2.yml) | Multi-service test stack (Pentesa, Juice Shop, Canary, Redirector) |
| **Juice Shop Accounts** | [`data/juiceshop_users.json`](data/juiceshop_users.json) | Seeded credentials and JWT authentication tokens |
| **Part 2A Test Results** | [`docs/audit/evidence/phase2/part2a_results.json`](docs/audit/evidence/phase2/part2a_results.json) | JSON serialization of all 50 test requests, responses, and diffs |
| **LLM Telemetry Ledger** | [`docs/audit/evidence/phase2/cost-log.md`](docs/audit/evidence/phase2/cost-log.md) | Token and dollar balance tracking against $5.00 hard cap |
| **Evaluation Harness** | [`scripts/part2a_runner.py`](scripts/part2a_runner.py) | Automated test execution script for Part 2A |
| **Canary Server** | [`scripts/canary_server.py`](scripts/canary_server.py) | Logging HTTP sink service on port 9099 |
| **Redirector Server** | [`scripts/redirector_server.py`](scripts/redirector_server.py) | In-scope 302 redirect relay on port 9098 |

---

## 6. Run 1 Part 2A Conclusion & Pause for Approval

Per the user's execution directive:
> *"Stop for approval after Part 2A, with 2A-checkpoint.md written. Do NOT do UI, cancellation or error-recovery tests (Part 2B) and do not start Phase 3."*

Run 1 of Phase 2 Part 2A is **COMPLETE**. All empirical evidence has been gathered, verified against PostgreSQL 16 and real target containers, and documented without assumptions. Awaiting explicit user approval before proceeding to Run 2 or Part 2B.

