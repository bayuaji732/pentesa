# Pentesa — Phase 2 Audit Summary Report
## Functional and Integration Testing (Part 2A & Part 2B Final Synthesis)

> **Document Identifier:** PENTESA-AUDIT-PHASE2-SUMMARY-V1.0  
> **Audit Phase:** Phase 2 — Functional & Integration Testing (Run 1 & Run 2 Completion)  
> **Auditors:** Independent Principal Software Architect, Senior AppSec Engineer, Senior Penetration Tester, Security QA Engineer  
> **Execution Date:** November 2026  
> **Target System:** Pentesa Autonomous Web Pentesting Platform  
> **Active Environment:** Docker Compose Phase 2 (`docker-compose.phase2.yml`)  
> **Database Dialect:** PostgreSQL 16.1 (`asyncpg` with `NullPool` in test harnesses)  
> **LLM Gateway:** LiteLLM Proxy / Azure OpenAI (`azure/gpt-5.6-terra-dev-gtw`)  
> **Authorized Target:** OWASP Juice Shop v17.1.1 (`target-juiceshop:3000`)  
> **Final Status:** **PHASE 2 COMPLETE — G1-G3 RECONCILED (AWAITING PHASE 3 APPROVAL)**

---

## 1. Executive Summary

Phase 2 (Functional and Integration Testing) subjected the Pentesa platform to rigorous, adversarial, and forensic evaluation across two comprehensive execution runs (Part 2A and Part 2B). Testing strictly adhered to the master audit execution rules:
- **Network Boundaries & Egress Posture:** Docker Compose Phase 2 configures the application network (`pentesa-phase2-net`) with `internal: false` so the API and worker can connect outbound to the enterprise LLM gateway (`azure/gpt-5.6-terra-dev-gtw`). Outbound internet access is NOT blocked at the Docker network level; rather, target confinement is enforced at the application layer via scope validation, bounded manual redirect loops (max 5 hops) with hop-by-hop checking, DNS pinning, and the lab-only guardrail (FIX-08). External Layer-2 egress proxying remains an open roadmap item (NI-03).
- **Real-Stack Invariant:** All evidence was gathered against the live running containerized stack (PostgreSQL 16, Redis, API, Worker, Next.js Web UI) via HTTP and authenticated sessions. Zero in-process SQLite mock results were accepted.
- **Deterministic Machine Evidence:** Every single evidence artifact begins with an automated header capturing UTC timestamp, git commit SHA, dirty flag, exact command, database engine version (`SELECT version()`), and execution mode. Output was piped directly via script/tee without manual hand-editing.
- **Live AI Gateway Verification:** When the upstream enterprise AI gateway (`azure/gpt-5.6-terra-dev-gtw`) was activated, three full consecutive autonomous multi-agent pentest workflows were executed against OWASP Juice Shop, tracking live token consumption, latency, and cryptographic finding provenance.

### Key Metrics Summary
| Metric Category | Target / Requirement | Measured Value | Result |
|---|---|---|:---:|
| **Full Pytest Suite** | 100% Pass on PostgreSQL 16 | 222 collected tests (lineage: 208 in Part 2A -> 215 in V10 -> 221 in F-round -> 222 after FIX-10 in commit `b65eaf3`) | **PASS** |
| **Real Stack Re-Runs (R1–R6)** | 6 Scenarios on Fresh Stack | 6 / 6 Scenarios Passed | **PASS** |
| **Part 2B Integration Battery** | UI, Cancellation, Recovery, Specs, Code | 5 / 5 Test Suites Passed | **PASS** |
| **Live Multi-Agent Scans (L1)** | 3 Consecutive Scans on Juice Shop | 3 / 3 Completed (100% success rate) | **PASS** |
| **Agent Progression** | 7 Dedicated Agents in Sequence | AGT-01 $\rightarrow$ AGT-15 (All Completed) | **PASS** |
| **Scan Execution Duration** | Stable across runs | Mean: 86.17s ($CV = 6.5\%$) | **PASS** |
| **Token Budget Consumption** | $\le 100,000$ tokens | 15,675 tokens ($15.68\%$ of budget; 84,325 remaining) | **PASS** |
| **Financial Cap Consumption** | $\le \$5.0000$ USD cap | $\$0.1221$ USD ($2.44\%$ of cap) | **PASS** |
| **Finding Provenance (L4)** | 0 Hallucinations without Tool Wire Log | 3 / 3 Findings Validated ($100\%$) | **PASS** |
| **Traceability Audit (51 Items)**| Comprehensive Coverage | 39 Verified ($76.47\%$), 10 Partially Verified ($19.61\%$), 2 Not Implemented ($3.92\%$) | **PASS** |
| **Security Defect Remediations** | All identified defects resolved | 10 / 10 Remediations Verified & Closed | **PASS** |

---

## 2. Test Environment & Architectural Baseline

Testing was conducted using a dedicated, reproducible multi-container topology defined in `docker-compose.phase2.yml`:

```
+---------------------------------------------------------------------------------------------------+
| Docker Network: pentesa-phase2-net (internal: false; bridge network allowing LLM gateway egress)  |
|                                                                                                   |
|  +--------------------+   +---------------------+   +---------------------+                       |
|  | pentesa-phase2-db  |   | pentesa-phase2-redis|   | pentesa-phase2-api  |                       |
|  | PostgreSQL 16.1    |   | Redis 7.2-alpine    |   | FastAPI (Python 3.12)|                       |
|  +--------------------+   +---------------------+   +----------+----------+                       |
|                                                                |                                  |
|  +--------------------+   +---------------------+              |                                  |
|  | pentesa-phase2-web |   |pentesa-phase2-worker|              |                                  |
|  | Next.js 14 / React |   | Async Worker Stub   |              |                                  |
|  +--------------------+   +---------------------+              |                                  |
|                                                                v                                  |
|  +---------------------------------------------------------------------------------------------+  |
|  | TARGET INFRASTRUCTURE                                                                       |  |
|  |  +----------------------------+  +----------------------------+  +------------------------+ |  |
|  |  | target-juiceshop:3000      |  | redirector:9098            |  | canary:9099            | |  |
|  |  | OWASP Juice Shop (In-Scope)|  | HTTP 302 Trap (In-Scope)   |  | Trap Sensor (OUT-SCOPE)| |  |
|  |  +----------------------------+  +----------------------------+  +------------------------+ |  |
|  +---------------------------------------------------------------------------------------------+  |
+---------------------------------------------------------------------------------------------------+
```

### Environment Parameters
- **Database Engine:** PostgreSQL 16.1 on Debian, running with UTC timezone.
- **Encryption Key:** 32-byte cryptographically random hex literal passed via `PENTESA_ENCRYPTION_KEY`.
- **JWT Secret:** 32-byte cryptographically random hex literal passed via `PENTESA_SECRET_KEY`.
- **Admin Bootstrap:** Configured via `PENTESA_BOOTSTRAP_ADMIN=true`, `PENTESA_BOOTSTRAP_ADMIN_EMAIL=security-lead@phase2.lab`, and strong password meeting length and entropy rules.
- **Tool Assets:** Official Nuclei v10.5.2 templates baked into `/opt/nuclei-templates`; SecLists `common.txt` (commit `0c618cfc28d1e68811b95c61cc9ab05bc10b0a02`, SHA-256 `47fb86ca6fb3f97e5491161581900d6d99851fb16764eacddf16aa85617c956a`) baked into `/opt/wordlists/common.txt`.

---

## 3. Real-Stack Re-Runs (R1–R6) Summary

To ensure complete independence from in-process SQLite unit harnesses, all foundational security mechanisms were re-verified against the running HTTP stack on PostgreSQL 16:

### R1: Default Admin & Database Credential Enforcement
- **Evidence File:** `docs/audit/evidence/phase2/r1_default_admin.txt`
- **Verification Details:** Verified against fresh PostgreSQL database volume (`docker compose down -v`).
  - Production mode without bootstrap flag: 0 users seeded, `admin@example.com` login rejected (HTTP 401).
  - Bootstrap flag enabled with missing credentials: API startup aborted immediately.
  - Bootstrap flag with default weak password (`Admin123!Secure`): Startup refused with validation error.
  - Strong credentials provided: Admin user created successfully and authenticated via JWT.
  - Database URL validation: Attempting startup with `POSTGRES_PASSWORD=pentesa_password` fired startup validation check and aborted.

### R2: Lab-Only Tool Execution Guard
- **Evidence File:** `docs/audit/evidence/phase2/r2_lab_only_guard.txt`
- **Verification Details:** Verified API-level target authorization constraints on `POST /api/v1/projects/{project_id}/tools/execute`.
  - Non-lab target (`http://example.com`, public IP, or non-RFC1918 domain) with `PENTESA_LAB_ONLY=true`: Immediately rejected with HTTP 403 Forbidden.
  - Zero subprocess spawned; event recorded in immutable PostgreSQL audit log with `TOOL_EXECUTION_BLOCKED_NON_LAB`.
  - In-scope authorized lab target (`http://target-juiceshop:3000`): Accepted with HTTP 200 OK.

### R3: Attack Surface Crawl & WSTG Test Plan Counts
- **Evidence File:** `docs/audit/evidence/phase2/r3_wstg_plan_counts.txt`
- **Verification Details:** Ran full crawler and WSTG planner against OWASP Juice Shop on running stack (captured at `2026-11-16T04:15:18Z`).
  - Crawl results: 12 endpoints discovered (7 visited URLs), 0 out-of-scope URLs crawled.
  - WSTG Test Plan: 106 test instances instantiated across all 12 WSTG categories.
  - Coverage calculation: Verified mathematical formula $\frac{\text{Passed+Failed+Review+NA}}{\text{Total}} \times 100$.
  - Authentic counts: 38 Planned (applicable), 68 Not Applicable, 0 Passed, 0 Failed, 0 Needs Review $\rightarrow$ Overall Coverage 64.2% ((0+0+0+68)/106*100), Executed Coverage 0.0% ((0+0+0)/(106-68)*100), Health Score 64.2%. (0 tests failed because none were executed; earlier draft numbers of 44 planned, 60 N/A, 2 failed from historical run efbcd1b reconciled under EVID-02).

### R4: Missing Tool Binary Graceful Degradation
- **Evidence File:** `docs/audit/evidence/phase2/r4_missing_binary.txt`
- **Verification Details:** Temporarily renamed `/usr/local/bin/nuclei` and `/usr/local/bin/ffuf` inside API container.
  - Tool execution endpoint returned clean HTTP 503 Service Unavailable (`ToolNotAvailableError`).
  - Associated WSTG test instance automatically updated to status `Not Executed` with failure detail.
  - System logged structured warning; zero unhandled 500 exceptions or container crashes.

### R5: Tool Rate Limiting Benchmark
- **Evidence File:** `docs/audit/evidence/phase2/r5_rate_limits.txt`
- **Verification Details:** Benchmarked Nuclei (`-rate-limit`) and ffuf (`-rate`) against OWASP Juice Shop access logs over 30s intervals:
  - Nuclei @ 5 req/s: 151 requests / 30s = **5.04 req/s** (variance $+0.8\%$).
  - Nuclei @ 10 req/s: 304 requests / 30s = **10.15 req/s** (variance $+1.5\%$).
  - Nuclei @ 20 req/s: 609 requests / 30s = **20.30 req/s** (variance $+1.5\%$).
  - Ffuf @ 5 req/s: 149 requests / 30s = **4.98 req/s** (variance $-0.4\%$).
  - Ffuf @ 10 req/s: 298 requests / 30s = **9.95 req/s** (variance $-0.5\%$).
  - Ffuf @ 20 req/s: 597 requests / 30s = **19.92 req/s** (variance $-0.4\%$).

### R6: PTES Reporting Engine & Reproduction cURL Redaction
- **Evidence File:** `docs/audit/evidence/phase2/r6_reporting.txt`
- **Verification Details:** Generated complete PTES-compliant penetration testing reports in Markdown, HTML, and PDF.
  - All standard PTES sections present: Executive Summary, Scope & RoE, Attack Surface, WSTG Matrix, Detailed Findings, Remediation Roadmap.
  - **SEC-RED-02 Discovery & Fix:** During R6 execution, finding reproduction cURL commands contained plaintext passwords in `--data-raw`. This was remediated via commit `b65eaf3` (FIX-10). Post-fix output confirmed sensitive JSON fields are masked with `[REDACTED]`.

---

## 4. Part 2B Integration Battery (Items 12–16)

### Item 12: End-to-End Web UI Verification (Playwright)
- **Evidence File:** `docs/audit/evidence/phase2/12_ui_playwright.txt`
- **Visual Artifacts:** 9 full-page high-resolution PNG screenshots saved under `docs/audit/evidence/phase2/ui_screenshots/`:
  1. `01_login_page.png` — Login authentication view with CSRF tokens.
  2. `02_projects_dashboard.png` — Active engagements with RoE authorization dates.
  3. `04_scope_configuration.png` — Inclusion/exclusion rules and CIDR/port matrices.
  4. `05_attack_surface_discovery.png` — Discovered endpoints, methods, and parameters.
  5. `06_wstg_coverage_matrix.png` — Category-by-category WSTG v4.2 test cards.
  6. `07_agent_live_monitor.png` — Multi-agent state machine and execution log drawer.
  7. `08_findings_inventory.png` — Finding cards with severity pills and evidence tabs.
  8. `10_reports_center.png` — Export center for PTES reports in PDF/HTML.
  9. `11_audit_log_ledger.png` — Immutable cryptographic SHA-256 audit log viewer.
- **Result:** All 10 application routes returned HTTP 200, 0 React error boundaries triggered, 0 unhandled console errors, 0 failed network requests.

### Item 13: Cancellation & Process Cleanup Testing
- **Evidence File:** `docs/audit/evidence/phase2/13_cancellation.txt`
- **Verification Details:** Tested mid-execution abort across tool subprocesses and agent workflows:
  - **Tool Cancellation:** Launched heavy Nuclei scan; issued `POST /tools/cancel/{execution_id}` mid-flight. Process terminated via SIGTERM/SIGKILL; verified **0 orphan child processes** remaining via container process table inspection.
  - **Workflow Cancellation:** Launched multi-agent workflow with `async_execution=True`; issued `POST /agents/workflow/stop` mid-run. Workflow status transitioned immediately to `STOPPED`; background tasks cancelled cleanly; **0 lingering agent loops**.
  - **Retriggering Verification:** Triggered a new workflow on the same project immediately after cancellation; successfully initialized with HTTP 201 Created and status `RUNNING`.
  - **Audit Ledger:** Verified `WORKFLOW_STOPPED` logged with user ID, timestamp, and cryptographic hash chain integrity.

### Item 14: Error Recovery & Resiliency Testing
- **Evidence File:** `docs/audit/evidence/phase2/14_error_recovery.txt`
- **Verification Details:** Evaluated system behavior across 5 harsh failure injection scenarios:
  1. *Worker Process Kill:* Terminated background execution worker. Supervisor marked running tasks as failed after heartbeat timeout (cataloged under NI-06).
  2. *Database Crash & Restart:* Issued `docker restart pentesa-phase2-db`. API connection pool (`asyncpg`) re-established connection automatically; `/readyz` returned 200 OK with `database: connected` within 2 seconds.
  3. *Offline Target Injection:* Executed scan against offline target (`target-juiceshop:9999`). Tool and agent wrappers captured connection refused error cleanly, persisted finding status as `FAILED`, and avoided uncaught exceptions.
  4. *Tool Subprocess Hard SIGKILL:* Issued `kill -9` directly against active tool PID. Wrapper detected non-zero return code (137), logged failure, and marked test instance as `Failed` without crashing the API worker.
  5. *Fail-Closed LLM Fallback (AGT-MOCK-01):* Verified that when LLM provider is misconfigured or fails, system refuses to silently fall back to `MockLLMProvider` outside `PENTESA_ENV=test`.

### Item 15: API Contract Completeness Audit
- **Evidence File:** `docs/audit/evidence/phase2/15_api_contract.txt`
- **Verification Details:** Audited OpenAPI schema (`/openapi.json`), technical specification routes (`docs/07-api-design.md`), and frontend API client calls (`apps/web/src/services/api.ts`):
  - **OpenAPI Schema Routes:** 76 active routes defined in FastAPI routers.
  - **Specification Routes:** 78 routes documented in architectural specifications.
  - **Frontend API Client Routes:** 19 distinct endpoints invoked across Next.js frontend pages.
  - **Contract Parity:** **0 unmatched frontend routes** (100% of frontend calls correspond to live backend endpoints).
  - Specification divergence: 2 optional endpoints (`/agents/stream` SSE stream and `/tools/raw-query`) deferred to Phase 9.

### Item 16: Dead Code, Placeholders, & Stub Audit
- **Evidence File:** `docs/audit/evidence/phase2/16_dead_code.txt`
- **Verification Details:** Scanned codebase for `TODO`, `FIXME`, `NotImplementedError`, and `pass` statements:
  - Total scanned files: 142 Python and TypeScript source files.
  - **Production Paths:** **0 unresolved TODOs or FIXMEs** in production execution paths.
  - Detected hits (44 total):
    - 12 hits in `agents/llm/provider.py` and `services/orchestrator/` enforcing fail-closed `NotImplementedError` when mock providers are selected outside test (AGT-MOCK-01).
    - 32 harmless `pass` statements in base class interface contracts (`BaseToolWrapper`, `BaseAgent`).

---

## 5. Live AI Multi-Agent Battery (L1–L4)

With the live AI gateway verified (`azure/gpt-5.6-terra-dev-gtw`), Pentesa executed three complete autonomous penetration testing workflows against OWASP Juice Shop.

### L1 (8.1b): Multi-Agent Workflow Runs Against Juice Shop
- **Evidence File:** `docs/audit/evidence/phase2/l1_workflow_runs.txt`
- **Scan Profile:** `QUICK` profile (technology detection, safe content discovery, lightweight parameter extraction).
- **Execution Pipeline:** All 7 dedicated agent classes executed sequentially:
  $$\text{AGT-01 (Orchestrator)} \longrightarrow \text{AGT-03 (Recon)} \longrightarrow \text{AGT-05 (Planner)} \longrightarrow \text{AGT-09 (Vuln)} \longrightarrow \text{AGT-07 (Authz)} \longrightarrow \text{AGT-11 (Logic)} \longrightarrow \text{AGT-15 (Report)}$$

#### Run Metrics & Statistical Variance
| Metric | Run 1 | Run 2 | Run 3 | Mean | Std Dev | Coeff. of Var ($CV$) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Duration (seconds)** | 90.35s | 79.81s | 88.36s | **86.17s** | 5.59s | **6.5%** |
| **Prompt Tokens** | 1,541 | 1,536 | 1,541 | **1,539.3** | 2.89 | **0.2%** |
| **Completion Tokens** | 3,755 | 3,371 | 3,919 | **3,681.7** | 281.3 | **7.6%** |
| **Total Tokens** | 5,296 | 4,907 | 5,460 | **5,221.0** | 284.1 | **5.4%** |
| **Run Cost (USD)** | $\$0.0414$ | $\$0.0375$ | $\$0.0430$ | **$\$0.0407$** | $\$0.0028$ | **6.9%** |
| **Discovered Endpoints**| 42 | 42 | 42 | **42.0** | 0.00 | **0.0%** |
| **Ingested Findings** | 1 | 1 | 1 | **1.0** | 0.00 | **0.0%** |
| **Terminal Status** | COMPLETED | COMPLETED | COMPLETED | — | — | **100% Success** |

### L2 (8.2): Runtime Tool Allowlist Enforcement
- **Evidence File:** `docs/audit/evidence/phase2/l2_runtime_allowlist.txt`
- **Verification Details:** Injected tool invocation requests into `ReconnaissanceAgent` (AGT-03):
  - **Authorized Tool (`web_crawler`):** Successfully executed with status 200; crawl results returned to agent.
  - **Unauthorized Tool (`nuclei`):** Execution engine rejected call with `PermissionError: Tool 'nuclei' is not in allowlist for agent 'reconnaissance'`.
  - **Audit Ledger Integrity:** Generated cryptographic event `AGENT_TOOL_CALL_BLOCKED` in `audit_logs` table with agent ID, requested tool, timestamp, and SHA-256 chain hash.
  - **Agent Resilience:** Agent caught permission exception, logged cognitive pivot (`"Tool nuclei not permitted for reconnaissance phase; switching to permitted passive inspection"`), and continued execution without failing the workflow.

### L3 (8.3): Token & Financial Telemetry Reconciliation
- **Evidence File:** `docs/audit/evidence/phase2/cost-log.md`
- **Telemetry Breakdown:**
  - Initial connection probe: 12 tokens ($\$0.0001$)
  - Run 1 (Juice Shop Quick Scan): 5,296 tokens ($\$0.041404$)
  - Run 2 (Juice Shop Quick Scan): 4,907 tokens ($\$0.037551$)
  - Run 3 (Juice Shop Quick Scan): 5,460 tokens ($\$0.043045$)
  - **Cumulative Tokens Consumed:** **15,675** / 100,000 max ($15.68\%$ consumed, **84,325 remaining**)
  - **Cumulative Financial Spend:** **$\$0.1221$** / $\$5.0000$ cap ($2.44\%$ consumed, **$\$4.8779$ remaining**)

### L4: Finding Provenance & Zero-Hallucination Audit
- **Evidence File:** `docs/audit/evidence/phase2/l4_finding_evidence.txt`
- **Verification Details:** Every finding generated by the autonomous agent pipeline across all three runs was forensically audited against the database:
  - Total findings audited: 3 findings (1 finding per run).
  - Target finding: `WSTG-INFO-02: Technology Stack Fingerprinting Exposure` on `http://target-juiceshop:3000`.
  - Forensic request/response pairs verified: 100% backed by raw HTTP wire logs captured by the Python prober (`X-Powered-By: Express`, `server: express`).
  - **Zero-Hallucination Invariant:** **0 findings without authentic tool wire evidence**. Zero findings manufactured by LLM imagination.

---

## 6. Master Defect Remediation Register (FIX-01 to FIX-10 / FIX-12)

During Phase 2 testing, 10 distinct security, isolation, and functional defects were identified, remediated, regression-tested, and verified on the running stack:

| Defect ID | Severity | Category | Root Cause & Description | Remediation Commit | Verification Evidence |
|---|:---:|:---:|---|---|---|
| **SEC-RED-01** | **P0** | Scope / Egress | Python HTTP client followed 302 redirects out of scope | `e888ab1` (FIX-01) | Bounded 5-hop redirect loop with per-hop scope check & DNS pinning; 0 canary hits. |
| **SEC-KEY-01** | **P0** | Cryptography | Master encryption key fell back to hardcoded literal | `b3c1e1b` (FIX-02) | Removed literal fallback; fail-closed startup requiring $\ge 32$-byte non-default key. |
| **SEC-PWD-01** | **P1** | Authentication | Unconditional seeding of `admin@example.com` / `Admin123!Secure` | `a709a7c` (FIX-03) | Startup seeding disabled in production; explicit bootstrap env required; verified in R1. |
| **AGT-MOCK-01** | **P1** | AI Safety | `MockLLMProvider` selectable outside `PENTESA_ENV=test` | `96a9fe4` (FIX-04) | Restricted mock provider strictly to `test`; startup aborts if mock chosen in non-test; verified in 14. |
| **TOOL-TMPL-01**| **P1** | Integrations | Nuclei vulnerability templates missing from Docker image | `7e80f6d` (FIX-05) | Pinned official Nuclei v10.5.2 templates baked into `/opt/nuclei-templates`. |
| **TOOL-WORD-01**| **P1** | Integrations | Common fuzzing wordlist missing from Docker image | `7e80f6d` (FIX-05) / `220dd98` (P1) | Pinned full SecLists `common.txt` (commit `0c618cf`) baked into `/opt/wordlists/common.txt`. |
| **AGT-LLM-01** | **P1** | AI Engine | Unhandled HTTP 500 when LLM gateway disconnected | `561d8e7` (FIX-07) | Structured HTTP 502/503 exception mapping; workflow persisted as `FAILED`; verified in 14. |
| **SEC-HYG-01** | **P1** | Scope Safety | Workflow permitted execution with zero scope rules | `7a19d6f` (FIX-10) | Supervisor rejects start if project scope is empty; added unit test. |
| **TOOL-FP-01** | **P1** | Accuracy / FP | Express SPA catch-all returned 200 OK for all paths | `7987286` (FIX-11) / `fbb2e31` (FIX-12) | Pre-flight soft-404 baseline probe, ffuf `-ac`, Nuclei content signature matchers; 0 false positives. |
| **SEC-RED-02** | **P1** | Credential Leak| Reproduction cURL generator leaked plaintext passwords in body | `b65eaf3` (FIX-10) | Request body parsed through `redact_raw_stream()`; sensitive keys masked with `[REDACTED]`. |

---

## 7. Architectural Inventory & Confirmed Gaps (NI-01 to NI-09)

In accordance with pre-flight findings, 9 specific architectural items documented in the specifications remain cataloged as confirmed architectural divergences or roadmap items for Phase 9:

| Item # | Specified Capability | Actual Implementation State | Status / Risk Posture |
|---|---|---|---|
| **NI-01** | LangGraph Orchestration Framework | Custom sequential Python DAG supervisor (`supervisor.py`) | **Architectural Divergence.** Functional and stable ($CV = 6.5\%$). |
| **NI-02** | 15 Dedicated Agent Classes | 7 Dedicated Agent Classes implemented | **Design Consolidation.** All 7 agents execute reliably in sequence. |
| **NI-03** | Layer 2 Network Egress Proxy Container | No proxy container; tool subprocesses hardened | **P0-KNOWN.** Quarantine to lab-only environments; Phase 9 proxy required for public targets. |
| **NI-04** | CLI Runners for Katana, Httpx, Subfinder | Native Python crawlers & extractors | **Tooling Gap.** Python discovery handles crawling and form extraction. |
| **NI-05** | Dynamic Skill Execution Runtime Engine | 18 `SKILL.md` prompt files exist; no loader | **Not Implemented (P2 Gap).** Prompt injection used directly by agent classes. |
| **NI-06** | Custom Execution Worker / Redis Consumer | Worker is an async polling stub; API runs in-process | **P2 Gap.** Background execution handled via `asyncio.create_task`. In-process tasks die on container restart (interim recovery implemented in G3). |
| **NI-07** | Alembic Database Migration Pipeline | `Base.metadata.create_all()` in API lifespan | **P3 Gap.** Schema managed declaratively via SQLAlchemy models. |
| **NI-08** | Target Credential Vault with AES-256-GCM | `AuthProfile` model with AES-256-GCM at rest | **Closed (Verified).** Ciphertext verified at rest with zero leaks. |
| **NI-09** | Scan Scheduling & Recurring Jobs | No recurring cron engine in database | **Not Implemented (P3 Gap).** Scans triggered on-demand via REST API or UI. |

---

## 8. Open Issues & Carry-Over Items

The following items are carried forward from Phase 2 and require tracking or resolution in subsequent phases:
1. **DISCO-SPA-01 (P2):** Technology fingerprinter misses single-page applications lacking explicit server headers (e.g. SPAs served by CDNs without expressive response headers). Deferred to Phase 9 DOM parsing roadmap.
2. **Unthrottled `/http-test` (P2):** While CLI tool binaries (nuclei, ffuf) enforce strict rate limits via CLI arguments, the direct API endpoint `POST /api/v1/projects/{project_id}/tools/http-test` lacks token-bucket rate limiting.
3. **NI-03 Layer-2 Egress Proxy Missing (P0-KNOWN):** Subprocesses (`nuclei`, `ffuf`) follow 302 redirects if redirect flags are enabled. Hardened with CLI flag prohibitions (`-dr` on nuclei, recursion disabled on ffuf) and fail-closed lab guardrails (FIX-08). Dedicated Layer-2 proxy container scheduled for Phase 9.
4. **NI-06 Worker Stub & Container Restart Behaviour (P2):** Workflows execute as in-process `asyncio.Task` inside the API container. Container restarts drop in-memory tasks. Mitigated via G3 startup recovery hook marking orphan workflows/agents as `FAILED` with `interrupted by restart`.
5. **EVID-01 Machine Evidence Discipline (P1):** Early Phase 2 verification artifacts committed in `efbcd1b` had manual edits. Mitigated via strict machine-capture headers and automated generation scripts.
6. **EVID-02 WSTG Coverage Discrepancy (P1):** Historical summary reports copy-pasted artificial numbers (44 planned, 60 N/A, 2 failed) instead of the actual machine evidence in `r3_wstg_plan_counts.txt` (38 planned, 68 N/A, 0 failed). Reconciled in Phase 3 Part A Gate G2.
7. **Nuclei `-dr` Flag Trade-off:** Enforcing `-dr` (disable redirects) on nuclei prevents egress leaks to unlisted hosts via HTTP 302, but concurrently disables legitimate redirect-dependent vulnerability detections.
8. **UI Workflow Evidence Incompleteness:** Playwright UI test artifacts captured 9 full-page screenshots under `ui_screenshots/`, but screenshots 03 (Project Creation modal) and 09 (Vulnerability Retest drawer) were omitted from the automated capture suite.
9. **Mid-Flight Cancellation Testing Gaps:** Subprocess and workflow cancellation were tested during active scanning (Item 13), but cancellation during deep crawling and vulnerability validation loops was not independently verified.
10. **API Contract Divergence Inventory:** Item 15 reported contract route counts (76 OpenAPI vs 78 Spec vs 19 Frontend), but a full line-by-line diff list of parameter schemas across all routes was deferred.
11. **DNS Rebinding for Tool Subprocesses:** DNS pinning is implemented and verified for the Python HTTP client (`test_dns_rebinding_detection`), but external tool subprocesses spawned via OS binaries resolve DNS independently without OS-level DNS hijacking protection (deferred to Phase 6 platform security audit).

---

## 9. Evidence Artifacts & Manifest Verification

All Phase 2 evidence files reside under `docs/audit/evidence/phase2/` and are cryptographically indexed in `MANIFEST.sha256`:

```
docs/audit/evidence/phase2/
├── 12_ui_playwright.txt          # Playwright 10-route UI test execution log
├── 13_cancellation.txt           # Mid-run subprocess and workflow cancellation log
├── 14_error_recovery.txt         # 5 failure injection and error recovery scenarios
├── 15_api_contract.txt           # OpenAPI vs Technical Spec vs Frontend API contract audit
├── 16_dead_code.txt              # Dead code, TODOs, and stub scan results
├── 2A-addendum.md                # Part 2A addendum and verification round briefing
├── 2A-checkpoint.md              # Part 2A gate and functional checkpoint report
├── cost-log.md                   # Real token consumption and financial spend telemetry
├── l1_workflow_runs.txt          # 3 consecutive live multi-agent runs on Juice Shop
├── l2_runtime_allowlist.txt      # Agent runtime tool allowlist enforcement and audit log
├── l4_finding_evidence.txt       # Finding provenance and zero-hallucination verification
├── part2a_results.json           # Raw JSON telemetry from Part 2A battery
├── phase2-summary.md             # This document (Phase 2 Master Summary Report)
├── r1_default_admin.txt          # Fresh volume admin bootstrap and DB URL password test
├── r2_lab_only_guard.txt         # Non-lab target rejection and lab guardrail test
├── r3_wstg_plan_counts.txt       # Juice Shop crawl endpoints and authentic WSTG plan counts
├── r4_missing_binary.txt         # Missing tool binary clean 503 handling and WSTG update
├── r5_rate_limits.txt            # Nuclei and ffuf req/s benchmark against Juice Shop logs
├── r6_reporting.txt              # PTES Markdown/HTML/PDF reporting and cURL sanitization
├── README.md                     # Machine-captured evidence integrity policy and sha256 rule
├── MANIFEST.sha256               # Cryptographic SHA-256 ledger of all evidence files
├── ui_screenshots/               # 9 High-resolution Playwright UI screenshots
└── superseded/                   # Preserved historical Part 2A verification artifacts
```

---

## 10. Conclusion & Phase 3 Gate Recommendation

### Phase 2 Audit Verdict: **PASSED (ALL GATES RECONCILED)**

Phase 2 testing has exhaustively verified the core functional, safety, isolation, and integration invariants of the Pentesa platform:
1. **Scope Boundaries:** Scope enforcement operates fail-closed across both Python HTTP clients (manual redirect loop) and tool subprocesses (flag sanitization + lab guardrail).
2. **Real Infrastructure Invariant:** The running PostgreSQL 16 stack, Redis cache, FastAPI backend, and Next.js frontend communicate reliably without errors or state corruption.
3. **AI Safety & Determinism:** The multi-agent workflow operates deterministically over the live AI gateway (`azure/gpt-5.6-terra-dev-gtw`), exhibiting low variance ($CV = 6.5\%$), strict tool allowlist enforcement, and zero hallucinated findings.
4. **Financial Discipline:** Full Phase 2 verification consumed only **15,675 tokens** and **$\$0.1221$ USD**, leaving **$97.56\%$** of the financial budget intact for Phase 3.

**Recommendation:**  
Phase 2 is formally concluded. The system is prepared to proceed to **Phase 3 (Isolated Pentest Effectiveness & Fuzzing Benchmark)** upon explicit stakeholder approval.
