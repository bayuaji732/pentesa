# Pentesa — Requirement-to-Implementation Traceability Matrix

> **Document Identifier:** PENTESA-AUDIT-02-TRACEABILITY-V1.3  
> **Audit Phase:** Phase 3 — Pentest Effectiveness Benchmark Conclusion  
> **Auditors:** Independent Principal Software Architect, Senior AppSec Engineer, Senior Penetration Tester, Security QA Engineer  
> **Date:** November 2026  
> **Methodology:** Direct Source Code Inspection + Isolated Running-Stack Vulnerability Benchmarking  

---

## 1. Traceability Status Definitions

- **Verified:** Fully implemented in source code and backed by passing execution tests or live API endpoints.
- **Partially Verified:** Core business logic is implemented and functional, but ancillary infrastructure (e.g., container proxy, external binary) is missing or consolidated.
- **Mock / Stub:** Component exists in codebase but relies on simulated fallback logic, hardcoded results, or idle loops.
- **Not Implemented:** Specified in requirements/documentation but completely absent from the codebase.
- **Not Tested:** Implemented in code but not yet verified with an automated or live execution test.

---

## 2. Comprehensive Traceability Matrix (49 Functional Requirements)

### 2.1 Project Management (PRD §4.1 / SRS Module A)

| Req ID | Requirement Description | Implementation Files | Status | Execution Evidence / Verification Notes |
|---|---|---|---|---|
| **FR-PM-01** | Create/manage distinct projects with unique UUIDs, names, descriptions, owners | `database/models/project.py`<br>`apps/api/routers/projects.py`<br>`apps/web/src/app/projects/page.tsx` | **Verified** | Verified via Project API CRUD endpoints and frontend workspace view. Note: In Phase 6/6b platform testing (`P6B-TC-RBAC-01`, demo-smoke), `GET /api/v1/projects/{project_id}` raises HTTP 500 (`MissingGreenlet` in Pydantic `ProjectResponse` serialization) for any project with members. Cataloged as `DEFECT-API-02` (re-rated to P1 - Critical, CVSS 6.5). Fix patch provided in `docs/audit/patches/DEFECT-API-02.diff`. |
| **FR-PM-02** | Define Rules of Engagement (RoE) including authorized testing windows | `database/models/project.py`<br>`services/orchestrator/supervisor.py`<br>`apps/web/src/app/scope/page.tsx` | **Verified** | Verified window constraints in `supervisor.py` lines 106–114. |
| **FR-PM-03** | Store authentication profiles with AES-256-GCM encryption at rest | `database/models/auth_profile.py`<br>`packages/common/security.py` | **Verified** | Verified via `test_credential_encryption_and_redaction.py`; `AuthProfile` model encrypts payload at rest with AES-256-GCM; database ciphertext verified with zero plaintext leak (Part 2A check 4.6); fail-closed key derivation enforced in FIX-02 (`b3c1e1b`). Re-verified in Phase 6 Platform Security Audit (`P6-TC-LEAK-01`, `P6-TC-LEAK-02`); AES-256-GCM ciphertext confirmed in PostgreSQL `auth_profiles` with zero plaintext leakage; credential passwords masked in API JSON responses. |
| **FR-PM-04** | Enforce automatic project expiration: scans refuse execution past end date | `services/orchestrator/supervisor.py`<br>`services/scope_engine/service.py` | **Verified** | `test_scope_service_project_authorization_window` passed; raises `ProjectAuthorizationExpiredError`. |
| **FR-PM-05** | Maintain project-level immutable audit history recording all actions | `packages/common/audit.py`<br>`database/models/audit.py`<br>`apps/api/routers/audit.py`<br>`apps/web/src/app/audit-logs/page.tsx` | **Verified** | Cryptographic SHA-256 hash chain and tamper detection verified (`test_audit_chain.py` passed). Re-verified in Phase 6 (`P6-TC-AUDIT-01`); SHA-256 hash chaining from genesis block (`0`*64) confirmed; record tampering detected at index 2. |

---

### 2.2 Scope Management & Enforcement (PRD §4.2 / SRS Module B)

| Req ID | Requirement Description | Implementation Files | Status | Execution Evidence / Verification Notes |
|---|---|---|---|---|
| **FR-SC-01** | Define in-scope domains, wildcards (`*.example.com`), CIDRs, ports | `database/models/scope.py`<br>`services/scope_engine/validator.py`<br>`apps/api/routers/scope.py` | **Verified** | `test_parse_port_range`, `test_domain_regex_compilation`, `test_scope_validator_domains_and_ports` passed. |
| **FR-SC-02** | Excluded hosts, regex path exclusions (`/logout`, `/admin/delete`) | `services/scope_engine/validator.py` | **Verified** | `test_scope_validator_path_exclusions_and_traversal` passed. Traversal bypasses safely rejected. |
| **FR-SC-03** | Dual-layer scope check (Layer 1 App + Layer 2 Egress Proxy) | `services/scope_engine/service.py`<br>`integrations/nuclei/runner.py`<br>`integrations/ffuf/runner.py` | **Partially Verified** | Layer 1 Application-level validation verified; tool subprocess wrappers interim-hardened against redirect flags and arbitrary CLI injection via FIX-06 (`5cede9b`) and fail-closed lab guardrail FIX-08 (`aac2f64`). Re-evaluated in Phase 6 (`P6-TC-EGRESS-01`, `P6-TC-SSRF-03`): Layer 1 filtering verified with 0 canary hits, but Layer 2 dedicated network Egress Proxy container is absent (cataloged as NI-03, P0-KNOWN, tool binaries restricted to Lab-Only pending Phase 9 egress container). |
| **FR-SC-04** | Redirect protection: Validate every redirect hop | `packages/common/http_client.py`<br>`services/execution_engine/tools/http_client.py`<br>`services/discovery_engine/crawler.py` | **Verified** | Bounded manual redirect loop (max 5 hops) with per-hop scope validation, DNS pinning, and cross-host credential/cookie stripping implemented via FIX-01 (`e888ab1`); verified via `test_safe_redirect_loop.py` (4/4 pass). |
| **FR-SC-05** | Prevent DNS rebinding attacks via DNS pinning | `services/scope_engine/dns_pinning.py` | **Verified** | `test_dns_rebinding_detection` passed. |
| **FR-SC-06** | Scope change audit trail recording authorizing user | `apps/api/routers/scope.py`<br>`apps/api/dependencies.py` | **Verified** | Rule creation and deletion trigger `record_audit_log` with user UUID and IP. |

---

### 2.3 Attack Surface Discovery & Inventory (PRD §4.3 / SRS Module C)

| Req ID | Requirement Description | Implementation Files | Status | Execution Evidence / Verification Notes |
|---|---|---|---|---|
| **FR-DS-01** | Subdomain enumeration (`subfinder`, passive DNS) | `services/discovery_engine/service.py` | **Partially Verified** | Handled via Python discovery; external `subfinder` binary runner not implemented. |
| **FR-DS-02** | Scope-aware web crawling supporting HTML & SPA endpoints | `services/discovery_engine/crawler.py` | **Verified** | Python `httpx` + `BeautifulSoup4` crawler with scope check on every URL. |
| **FR-DS-03** | Endpoint extraction from HTML forms, JS bundles, OpenAPI specs | `services/discovery_engine/extractor.py` | **Verified** | 9 unit tests passed in `test_parameter_extraction.py` (forms, JSON, JS, OpenAPI, robots, sitemap). |
| **FR-DS-04** | Hidden path and content discovery (`ffuf`) | `integrations/ffuf/runner.py`<br>`services/execution_engine/tools/wordlists/common.txt` | **Partially Verified** | Smoke check matched 4/4 canonical paths; controlled fuzzing verified against Juice Shop. In Phase 3 benchmarking, ffuf baseline successfully discovered hidden paths across all 5 benchmark targets. However, the discovery engine crawler does not invoke ffuf automatically when blind crawling headless targets returning 404 on `/` with zero HTML links (`pentesa-bench`), resulting in zero discovered endpoints. Documented as `P2-RECON-01` in roadmap. |
| **FR-DS-05** | Centralized Endpoint Inventory with parameters and schema | `database/models/discovery.py`<br>`apps/api/routers/discovery.py`<br>`apps/web/src/app/discovery/page.tsx` | **Verified** | Endpoints and parameters persisted to DB and rendered in UI with methods, parameters, and auth flags. |
| **FR-DS-06** | Technology fingerprinting identifying frameworks and servers | `services/discovery_engine/fingerprint.py` | **Partially Verified** | Unit tests pass in `test_technology_detection.py`, but technology fingerprinter misses SPAs lacking server headers (DISCO-SPA-01 open, deferred to Phase 9 DOM parsing roadmap). |

---

### 2.4 OWASP WSTG Test Planning & Coverage (PRD §4.4 / SRS Module D)

| Req ID | Requirement Description | Implementation Files | Status | Execution Evidence / Verification Notes |
|---|---|---|---|---|
| **FR-WP-01** | Comprehensive test catalog covering all 12 WSTG v4.2 categories | `services/execution_engine/wstg_catalog_data.py`<br>`database/models/wstg.py` | **Verified** | 100% of WSTG v4.2 categories and test cases present; `test_catalog_structure_and_completeness` passed. |
| **FR-WP-02** | Project-specific test plan generation mapped to endpoints | `services/execution_engine/planner.py`<br>`agents/wstg/wstg_agent.py` | **Verified** | Test instances instantiated per project; mapped dynamically based on discovered technologies. |
| **FR-WP-03** | Explicit test statuses (`Planned`, `Passed`, `Failed`, `N/A`, etc.) | `database/models/wstg.py`<br>`packages/schemas/wstg.py` | **Verified** | Status state transitions verified (`test_wstg_status_transitions` passed). |
| **FR-WP-04** | Mathematical coverage calculation: $\frac{\text{Passed+Failed+Review+NA}}{\text{Total}} \times 100$ | `services/execution_engine/coverage.py` | **Verified** | Verified formula against authentic raw machine evidence in `r3_wstg_plan_counts.txt`: Overall Coverage 64.2% ((0+0+0+68)/106*100), Executed Coverage 0.0% ((0+0+0)/(106-68)*100), Health Score 64.2%. (Corrected from earlier draft artificial numbers; 0 tests failed because none were executed). |
| **FR-WP-05** | Manual override for security engineers with mandatory justification | `apps/api/routers/wstg.py` (PATCH instance) | **Verified** | PATCH endpoint validates justification string and updates instance status. |

---

### 2.5 Automated Security Testing Integration (PRD §4.5 / SRS Module E)

| Req ID | Requirement Description | Implementation Files | Status | Execution Evidence / Verification Notes |
|---|---|---|---|---|
| **FR-ST-01** | Tool execution wrapper for Nuclei with scope validation | `integrations/nuclei/runner.py`<br>`apps/api/routers/tools.py` | **Partially Verified** | Nuclei pipeline, parser, and finding ingestion verified. Pinned templates baked into Docker image and per-probe timeout separated from subprocess execution timeout via FIX-05 (`7e80f6d`). In Phase 3 benchmarking, Nuclei baseline detected exposures on Juice Shop (7 findings including Swagger API, robots.txt), DVWA (11 findings), and crAPI (5 findings). Zero out-of-scope or canary hits confirmed across all runs. |
| **FR-ST-02** | Tool execution wrappers for httpx, katana, ffuf | `integrations/ffuf/runner.py`<br>`apps/api/routers/tools.py` | **Partially Verified** | Ffuf binary v2.1.0 verified with controlled fuzzing; production wordlist verified. In Phase 3 benchmarking, ffuf discovered paths across all 5 benchmark targets. Katana/httpx CLI runners absent (NI-04). |
| **FR-ST-03** | Custom Python security check harness | `services/execution_engine/tools/http_client.py`<br>`agents/authorization/authz_agent.py`<br>`agents/vulnerability/vuln_agent.py` | **Verified** | Python-based HTTP prober with header injection, CORS, and IDOR testing active. |
| **FR-ST-04** | Strict process sandboxing: Zero dynamic shell execution from LLM | `services/execution_engine/tools/base.py` | **Verified** | `create_subprocess_exec` uses typed `argv: List[str]`; shell strings strictly prohibited. Re-verified in Phase 6 Platform Security Audit (`P6-TC-TOOL-01`): comprehensive static AST audit confirmed zero `os.system` or `os.popen` invocations across all services. |
| **FR-ST-05** | Global and per-target rate limiting | `services/execution_engine/tools/base.py`<br>`integrations/ffuf/runner.py`<br>`apps/api/routers/auth.py` | **Partially Verified** | Rate limiting benchmark verified against Juice Shop logs (nuclei: 5.04, 10.15, 20.30 req/s; ffuf: 4.98, 9.95, 19.92 req/s). Re-evaluated in Phase 6 and Phase 6b wire suite (`P6-TC-AUTH-04`, `P6B-TC-AUTH-01`): User authentication endpoint `POST /api/v1/auth/login` lacks rate limiting, permitting sequential failed attempts without throttling (`DEFECT-AUTH-03` / P2). `/http-test` and auth endpoints await global rate limiting in Phase 9. |

---

### 2.6 AI Agent System (PRD §4.6 / SRS Module F)

| Req ID | Requirement Description | Implementation Files | Status | Execution Evidence / Verification Notes |
|---|---|---|---|---|
| **FR-AG-01** | Multi-agent architecture built on stateful graph workflows | `services/orchestrator/supervisor.py`<br>`apps/api/routers/agents.py` | **Partially Verified** | Custom Python sequential DAG supervisor used instead of LangGraph (cataloged as NI-01). In Phase 3 benchmarking, execution reliability reached 100.0% in final batch (18/18 runs). In Phase 5 evaluation (`P5-TC-HANDOFF-01`), sequential DAG handoff across all 7 concrete agents (`AGT-01 -> AGT-03 -> AGT-05 -> AGT-09 -> AGT-07 -> AGT-11 -> AGT-15`) was verified with 100% state snapshot preservation. Classified as **Partially Verified** citing NI-01 (custom DAG in `supervisor.py` rather than specified LangGraph cyclic graph) and open gateway circuit-breaking item `P2-REL-01`. Evidence: `docs/audit/evidence/phase3/3B-run-classification.md`, `docs/audit/evidence/phase5/score_p5.txt`. |
| **FR-AG-02** | 15 dedicated agents with distinct responsibilities | `agents/` | **Partially Verified** | 7 dedicated agent classes implemented (consolidated from 15, cataloged as NI-02). Evaluated in Phase 5 agent inventory (`docs/audit/evidence/phase5/5A-agent-inventory.md`) and benchmark battery (`P5-TC-SCHEMA-01`): all 7 concrete agent classes accepted input and returned valid `PentestWorkflowState` conforming to Pydantic schemas. Static tool allowlists defined and enforced per agent. Classified as **Partially Verified** due to design consolidation from 15 to 7 concrete classes (NI-02). Evidence: `docs/audit/evidence/phase5/5A-agent-inventory.md`, `docs/audit/evidence/phase5/score_p5.txt`. |
| **FR-AG-03** | Strict Agent-Tool boundary: agents emit JSON; engine executes | `agents/base.py` (`log_tool_call`) | **Verified** | Verified in Part 2B (L2) and re-verified in Phase 5 benchmark battery (`P5-TC-ALLOW-01`, `P5-TC-ALLOW-02`, `P5-TC-ALLOW-03`): authorized tool (`wstg_planner` on AGT-01) executed and persisted to `AgentToolCall`; unauthorized tool (`nuclei_runner` on AGT-01) was strictly blocked with `PermissionError` and audit logged `AGENT_TOOL_CALL_BLOCKED`; tool subprocess runners safely stripped dangerous redirect flags (`-follow-redirects`, `-r`) and clamped rate limits. Status: **Verified**. Evidence: `docs/audit/evidence/phase2/l2_runtime_allowlist.txt`, `docs/audit/evidence/phase5/score_p5.txt`. |
| **FR-AG-04** | Full agent observability: thought traces, tool calls, token/cost telemetry | `database/models/agent.py`<br>`agents/base.py`<br>`apps/api/routers/agents.py` | **Partially Verified** | Thought traces, tool executions, and cost telemetry verified in live LLM runs (`P5-TC-LIVE-01`, `P5-TC-LIVE-02`: 4,836 tokens / $0.0459 USD in `cost-log.md`). In Phase 6 (`P6-TC-INJECT-01`), live adversarial prompt injection against the real LLM (`azure/gpt-5.6-terra-dev-gtw`) was successfully verified (156 tokens / $0.0010 USD; model refused override and maintained data/instruction boundary). However, hallucination resistance failed in `P5-TC-HALLUC-01` (`DEFECT-AGENT-01`). Classified as **Partially Verified** pending empirical evidence gating. Evidence: `docs/audit/evidence/phase6/score_p6.txt`, `docs/audit/06-agent-evaluation.md`, `docs/audit/07-security-assessment.md`. |

---

### 2.7 Vulnerability Validation & Evidence Collection (PRD §4.7 / SRS Module G)

| Req ID | Requirement Description | Implementation Files | Status | Execution Evidence / Verification Notes |
|---|---|---|---|---|
| **FR-VV-01** | 10-step finding lifecycle | `database/models/finding.py`<br>`apps/api/routers/findings.py` | **Verified** | `FindingStatusHistory` tracks transitions from Detected to Confirmed/False Positive. In Phase 3 benchmarking, candidate findings from probers remained unpromoted for passive header issues (documented as `P2-FIND-01`), but active probers successfully transitioned confirmed exploits with full reproduction evidence and SHA-256 digests when endpoints were seeded. |
| **FR-VV-02** | Evidence artifact collection (raw bytes, headers, curl command) | `services/evidence_engine/collector.py`<br>`services/evidence_engine/curl_generator.py` | **Verified** | `test_generate_reproduction_curl`, `test_serialize_raw_http_wire_format` passed. Plaintext credential leak in cURL body resolved via FIX-10 (`b65eaf3`). In Phase 3 benchmarking, confirmed findings on seeded `pentesa-bench` captured raw HTTP request, raw HTTP response, and runnable reproduction curl command with request/response SHA-256 hashes. |
| **FR-VV-03** | Evidence integrity: SHA-256 hash for request/response pairs | `services/evidence_engine/hasher.py` | **Verified** | `test_compute_evidence_hash` passed. In Phase 3 benchmarking, request_hash_sha256 and response_hash_sha256 computed and persisted for every confirmed finding. |
| **FR-VV-04** | Sensitive data masking: automatically redact cards, passwords, tokens | `services/evidence_engine/redactor.py` | **Verified** | 3 unit tests passed (`test_mask_sensitive_headers`, `test_redact_raw_stream_credentials`, `test_redact_raw_stream_credit_card`). Body redaction in reproduction commands enforced via FIX-10 (`b65eaf3`). |
| **FR-VV-05** | Automated reproduction harness: re-execute minimal payloads | `agents/validation/validation_agent.py` | **Partially Verified** | Validation agent executes independent reproduction probes, but empirical evaluation in Phase 5 benchmark (`P5-TC-HALLUC-01`) proved that `ValidationAgent` blindly trusts LLM `is_valid: true` without gating on reproduction status codes. When an upstream LLM hallucinated a vulnerability on a non-existent endpoint returning HTTP 404, the finding was promoted to `confirmed_findings` (`DEFECT-AGENT-01`). Classified as **Partially Verified** pending empirical evidence gating. Evidence: `docs/audit/evidence/phase5/score_p5.txt`, `docs/audit/06-agent-evaluation.md`. |

---

### 2.8 Authorization & Business Logic Testing (PRD §4.8 / SRS Module H)

| Req ID | Requirement Description | Implementation Files | Status | Execution Evidence / Verification Notes |
|---|---|---|---|---|
| **FR-AB-01** | Multi-identity test execution (User A vs User B, Admin vs Member) | `agents/authorization/authz_agent.py` | **Not Implemented** | `safe_request` sends unauthenticated requests with `headers=None`. `PentestWorkflowState` lacks identity/credential fields. `multi_identity_prober` is a mock stub. Evaluated in Phase 4 capability audit (`docs/audit/evidence/phase4/4A-capability-inventory.md`). Defect: `DEFECT-AUTH-02`. |
| **FR-AB-02** | Automated BOLA/IDOR detection | `agents/authorization/authz_agent.py` | **Failed** | Execution evidence from Phase 4 rerun (`score_pentesa-bench_run1..3.txt`, `score_crapi_run1..3.txt`): Target endpoint reach is verified in container access logs (`GET /api/user/%7Buser_id%7D/profile`), but AGT-07 left `{user_id}` un-interpolated, substituted static path numbers `1` and `2` failing to discover target object `1002`, and issued unauthenticated requests rejected with HTTP 401 on crAPI and Juice Shop. 0 TP detected on live target. Endpoint reach is proven, distinguishing "Failed" from "Not Reached". |
| **FR-AB-03** | Horizontal and vertical privilege escalation testing | `agents/authorization/authz_agent.py` | **Not Implemented** | No role-tier comparison or authenticated session context swap exists in active testing agents or orchestrator workflows. Defect: `DEFECT-AUTH-02` (`P4-AUTH-01`). |
| **FR-AB-04** | Business logic anomaly detection without destructive actions | `agents/authorization/authz_agent.py` | **Failed** | Execution evidence from Phase 4 rerun (`score_pentesa-bench_run1..3.txt`): Target endpoint reach is verified in container access logs (`GET`, `TRACE`, `TRACK`, `DEBUG` to `/order/checkout` returning 405 Method Not Allowed), but prober failed to construct valid POST bodies or detect price tampering, and did not test coupon race concurrency. 0 findings produced. Endpoint reach is proven, distinguishing "Failed" from "Not Reached". |
| **FR-AB-05** | Flag suspicious anomalies as `Needs Manual Review` | `agents/authorization/authz_agent.py`<br>`services/execution_engine/runners.py` | **Partially Verified** | `GenericProbeRunner` transitions WSTG items to `NEEDS_REVIEW`, but finding schema lacks `FLAGGED_FOR_HUMAN_REVIEW` status; unconfirmed business candidates are dropped by `ValidationAgent`. Defect: `DEFECT-BUSL-01`. |

---

### 2.9 Findings Management & Deduplication (PRD §4.9 / SRS Module I)

| Req ID | Requirement Description | Implementation Files | Status | Execution Evidence / Verification Notes |
|---|---|---|---|---|
| **FR-FM-01** | Findings dashboard with multi-dimensional filtering | `apps/web/src/app/findings/page.tsx`<br>`apps/api/routers/findings.py` | **Verified** | Filterable by Severity, Status, WSTG category, and search query. Verified in UI test: `docs/audit/evidence/phase2/12_ui_playwright.txt`. |
| **FR-FM-02** | Intelligent deduplication based on endpoint, parameter, and CWE | `services/evidence_engine/finding_service.py` | **Verified** | `test_benchmark_deduplication_hashing` passed. |
| **FR-FM-03** | False positive management with recorded justification | `database/models/finding.py`<br>`apps/api/routers/findings.py` | **Verified** | POST `/{finding_id}/false-positive` endpoint stores rationale in `false_positives` table. Verified in UI test: `docs/audit/evidence/phase2/12_ui_playwright.txt`. |
| **FR-FM-04** | One-click retest capability | `apps/api/routers/findings.py` | **Verified** | POST `/{finding_id}/retest` endpoint invokes automated validation prober. Verified in UI test: `docs/audit/evidence/phase2/12_ui_playwright.txt`. |

---

### 2.10 PTES Reporting Engine (PRD §4.10 / SRS Module J)

| Req ID | Requirement Description | Implementation Files | Status | Execution Evidence / Verification Notes |
|---|---|---|---|---|
| **FR-RP-01** | Generate PTES-aligned reports in PDF and standalone HTML | `services/reporting_engine/renderer.py` | **Verified** | `test_report_renderer_html` and `test_report_renderer_pdf` passed; verified on running stack in R6 (`docs/audit/evidence/phase2/r6_reporting.txt`). |
| **FR-RP-02** | Comprehensive report sections (Cover, Exec Summary, WSTG, Findings, etc.) | `services/reporting_engine/context_builder.py`<br>`templates/ptes_standard.html` | **Verified** | Full PTES report context compiled from database entities. |
| **FR-RP-03** | Report customization (logo, client details, tester signatures) | `database/models/report.py`<br>`services/reporting_engine/context_builder.py` | **Verified** | `report_templates` table and customizable metadata parameters supported. |
| **FR-RP-04** | Report versioning: immutable snapshot preserved at publication | `database/models/report.py`<br>`apps/api/routers/reports.py` | **Verified** | Report records store complete snapshot JSON and generated file paths. |

---

## 3. Implementation Statistics Summary (Strict Recount)

The table below summarizes the exact row-by-row count across all 10 modules:

| Module | Total Reqs | Verified | Partially Verified | Failed | Not Tested | Not Implemented |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **2.1 Project Management (FR-PM)** | 5 | 5 | 0 | 0 | 0 | 0 |
| **2.2 Scope Enforcement (FR-SC)** | 6 | 5 | 1 | 0 | 0 | 0 |
| **2.3 Attack Surface Discovery (FR-DS)** | 6 | 3 | 3 | 0 | 0 | 0 |
| **2.4 OWASP WSTG Test Planning (FR-WP)** | 5 | 5 | 0 | 0 | 0 | 0 |
| **2.5 Automated Security Testing (FR-ST)** | 5 | 2 | 3 | 0 | 0 | 0 |
| **2.6 AI Agent System (FR-AG)** | 4 | 1 | 3 | 0 | 0 | 0 |
| **2.7 Vulnerability Validation (FR-VV)** | 5 | 4 | 1 | 0 | 0 | 0 |
| **2.8 Authorization & Business Logic (FR-AB)** | 5 | 0 | 1 | 2 | 0 | 2 |
| **2.9 Findings Management (FR-FM)** | 4 | 4 | 0 | 0 | 0 | 0 |
| **2.10 PTES Reporting Engine (FR-RP)** | 4 | 4 | 0 | 0 | 0 | 0 |
| **Documented Arch Subsystems (NI-05, NI-09)** | 2 | 0 | 0 | 0 | 0 | 2 |
| **TOTALS (Comprehensive Traceability)** | **51** | **33 (64.71%)** | **12 (23.53%)** | **2 (3.92%)** | **0 (0.00%)** | **4 (7.84%)** |

> **Audit Note on "Not Implemented" Classification:**  
> Of the 49 PRD functional requirements, 33 are Verified, 12 are Partially Verified, 2 are Failed (FR-AB-02, FR-AB-04), and 2 are Not Implemented (FR-AB-01, FR-AB-03) (0 Not Tested). Crucially, 2 major documented architectural capabilities are also Not Implemented: NI-05 (Dynamic Skill Execution Runtime Engine) and NI-09 (Scan Scheduling & Recurring Jobs), bringing total Not Implemented items to 4. A claim of "0 Not Implemented / 0 Not Tested" is not credible and has been corrected. In addition, architectural divergences and gaps (NI-01 through NI-09) are cataloged explicitly below.

---

## 4. Explicit Inventory of Not Implemented Items

The following items are specified in the architecture and design documentation (`docs/01`–`docs/24`), but are **Not Implemented** in the codebase:

| Item # | Document Reference | Specified Capability | Actual Implementation State | Severity / Classification |
|---|---|---|---|---|
| **NI-01** | `docs/01-prd.md` §4.6<br>`docs/04-agent-architecture.md`<br>`ADR-002` | **LangGraph Orchestration Framework** (Stateful cyclic graph, PostgreSQL checkpoints, conditional branch edges) | **Not Implemented.** `langgraph` is not in `requirements.txt`. Orchestrator uses a custom sequential Python class (`services/orchestrator/supervisor.py`). | **Architectural Divergence** |
| **NI-02** | `docs/01-prd.md` §4.6 (FR-AG-02)<br>`docs/05-agent-specifications.md` | **8 Dedicated Agent Classes** (Scope, Surface Mapping, Auth Testing, Input Validation, Fuzzing, False Positive, Evidence Collection, Business Logic) | **Not Implemented as Separate Classes.** Only 7 agent classes exist; the other 8 responsibilities are consolidated directly into services and active agents. | **Design Consolidation** |
| **NI-03** | `docs/01-prd.md` §4.2 (FR-SC-03)<br>`docs/08-scope-enforcement.md` §3 | **Layer 2 Network Egress Proxy Container** (Envoy/Squid with eBPF/socket filters intercepting all TCP egress) | **Open (Lab-Only, Hardened).** No egress proxy container in `docker-compose.yml`. Tool subprocess runners interim-hardened via FIX-06 (`5cede9b`) and fail-closed lab guardrail FIX-08 (`aac2f64`). Tool binaries restricted to lab environments pending Phase 9 containerized proxy. | **P0-KNOWN (Scope Guardrail)** |
| **NI-04** | `docs/01-prd.md` §4.3 (FR-DS-01)<br>`docs/09-tool-integrations.md` §5.2-5.4 | **CLI Tool Runners for Katana, Httpx, and Subfinder** | **Not Implemented.** No runner classes exist in `integrations/`. Crawling and parameter extraction are done natively in Python (`services/discovery_engine/`). | **P2 (Tooling Gap)** |
| **NI-05** | `docs/16-skill-system.md` §5 | **Dynamic Skill Execution Runtime Engine** (Dynamic loading and executing of `SKILL.md` bundles with JSON Schema parameter validation) | **Not Implemented.** Zero Python files load or execute files from `skills/`. The 18 `SKILL.md` files are documentation/prompts only. | **P2 (Extensibility Gap)** |
| **NI-06** | `docs/01-prd.md` §4.6<br>`docs/18-deployment-architecture.md` | **Custom Execution Worker / Redis Task Consumer (Not Celery)** | **Not Implemented.** `services/execution_engine/worker.py` is a custom async idle polling loop stub (`asyncio.sleep(2)`), not a Celery worker. The API server executes workflows in-process via `asyncio.create_task`. | **P2 (Scalability Gap)** |
| **NI-07** | `docs/10-database-design.md` §7 | **Alembic Database Migration Pipeline** (Versioned schema migrations with reversible up/down scripts) | **Not Implemented.** No `alembic.ini` or migration revisions exist; tables are created via `Base.metadata.create_all()` in `apps/api/main.py`. | **P3 (Maintainability Gap)** |
| **NI-08** | `docs/01-prd.md` §4.1 (FR-PM-03)<br>`docs/10-database-design.md` §3.9 | **Target Credential Vault Tables with AES-256-GCM at Rest** (`auth_profiles`, `test_credentials`) | **Resolved (Closed).** Implemented via `database/models/auth_profile.py` (`AuthProfile` model with AES-256-GCM ciphertext storage at rest); fail-closed key derivation enforced in FIX-02 (`b3c1e1b`); verified via `test_credential_encryption_and_redaction.py` (3/3 pass). | **Closed (Verified)** |
| **NI-09** | `docs/10-database-design.md` §3.10 | **Scan Scheduling & Recurring Jobs Tables** (`scan_schedules`, `scan_jobs`) | **Not Implemented.** No automated recurring scan scheduler or cron engine is implemented in the database or backend. | **P3 (Feature Gap)** |
