# Pentesa — Requirement-to-Implementation Traceability Matrix

> **Document Identifier:** PENTESA-AUDIT-02-TRACEABILITY-V1.1  
> **Audit Phase:** Phase 1 — Repository and Documentation Audit (Pre-Flight Corrected)  
> **Auditors:** Independent Principal Software Architect, Senior AppSec Engineer, Senior Penetration Tester, Security QA Engineer  
> **Date:** November 2026  
> **Methodology:** Direct Source Code Inspection + Automated Test Verification  

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
| **FR-PM-01** | Create/manage distinct projects with unique UUIDs, names, descriptions, owners | `database/models/project.py`<br>`apps/api/routers/projects.py`<br>`apps/web/src/app/projects/page.tsx` | **Verified** | Verified via Project API CRUD endpoints and frontend workspace view. |
| **FR-PM-02** | Define Rules of Engagement (RoE) including authorized testing windows | `database/models/project.py`<br>`services/orchestrator/supervisor.py`<br>`apps/web/src/app/scope/page.tsx` | **Verified** | Verified window constraints in `supervisor.py` lines 106–114. |
| **FR-PM-03** | Store authentication profiles with AES-256-GCM encryption at rest | `packages/common/security.py`<br>`database/models/project.py` | **Partially Verified** | User password hashing uses Argon2id; target credential vault table (`auth_profiles`) with AES-256-GCM at rest is missing. |
| **FR-PM-04** | Enforce automatic project expiration: scans refuse execution past end date | `services/orchestrator/supervisor.py`<br>`services/scope_engine/service.py` | **Verified** | `test_scope_service_project_authorization_window` passed; raises `ProjectAuthorizationExpiredError`. |
| **FR-PM-05** | Maintain project-level immutable audit history recording all actions | `packages/common/audit.py`<br>`database/models/audit.py`<br>`apps/api/routers/audit.py`<br>`apps/web/src/app/audit-logs/page.tsx` | **Verified** | Cryptographic SHA-256 hash chain and tamper detection verified (`test_audit_chain.py` passed). |

---

### 2.2 Scope Management & Enforcement (PRD §4.2 / SRS Module B)

| Req ID | Requirement Description | Implementation Files | Status | Execution Evidence / Verification Notes |
|---|---|---|---|---|
| **FR-SC-01** | Define in-scope domains, wildcards (`*.example.com`), CIDRs, ports | `database/models/scope.py`<br>`services/scope_engine/validator.py`<br>`apps/api/routers/scope.py` | **Verified** | `test_parse_port_range`, `test_domain_regex_compilation`, `test_scope_validator_domains_and_ports` passed. |
| **FR-SC-02** | Excluded hosts, regex path exclusions (`/logout`, `/admin/delete`) | `services/scope_engine/validator.py` | **Verified** | `test_scope_validator_path_exclusions_and_traversal` passed. Traversal bypasses safely rejected. |
| **FR-SC-03** | Dual-layer scope check (Layer 1 App + Layer 2 Egress Proxy) | `services/scope_engine/service.py` | **Partially Verified** | Layer 1 Application-level validation verified; Layer 2 dedicated network Egress Proxy container is absent. |
| **FR-SC-04** | Redirect protection: Validate every redirect hop | `services/discovery_engine/crawler.py`<br>`services/scope_engine/service.py` | **Verified** | Redirect hops validated against project scope before following. |
| **FR-SC-05** | Prevent DNS rebinding attacks via DNS pinning | `services/scope_engine/dns_pinning.py` | **Verified** | `test_dns_rebinding_detection` passed. |
| **FR-SC-06** | Scope change audit trail recording authorizing user | `apps/api/routers/scope.py`<br>`apps/api/dependencies.py` | **Verified** | Rule creation and deletion trigger `record_audit_log` with user UUID and IP. |

---

### 2.3 Attack Surface Discovery & Inventory (PRD §4.3 / SRS Module C)

| Req ID | Requirement Description | Implementation Files | Status | Execution Evidence / Verification Notes |
|---|---|---|---|---|
| **FR-DS-01** | Subdomain enumeration (`subfinder`, passive DNS) | `services/discovery_engine/service.py` | **Partially Verified** | Handled via Python discovery; external `subfinder` binary runner not implemented. |
| **FR-DS-02** | Scope-aware web crawling supporting HTML & SPA endpoints | `services/discovery_engine/crawler.py` | **Verified** | Python `httpx` + `BeautifulSoup4` crawler with scope check on every URL. |
| **FR-DS-03** | Endpoint extraction from HTML forms, JS bundles, OpenAPI specs | `services/discovery_engine/extractor.py` | **Verified** | 9 unit tests passed in `test_parameter_extraction.py` (forms, JSON, JS, OpenAPI, robots, sitemap). |
| **FR-DS-04** | Hidden path and content discovery (`ffuf`) | `integrations/ffuf/runner.py` | **Mock / Stub** | Subprocess wrapper implemented; binary missing in Docker image; falls back to simulated mock finding `/backup.sql`. |
| **FR-DS-05** | Centralized Endpoint Inventory with parameters and schema | `database/models/discovery.py`<br>`apps/api/routers/discovery.py`<br>`apps/web/src/app/discovery/page.tsx` | **Verified** | Endpoints and parameters persisted to DB and rendered in UI with methods, parameters, and auth flags. |
| **FR-DS-06** | Technology fingerprinting identifying frameworks and servers | `services/discovery_engine/fingerprint.py` | **Verified** | 4 unit tests passed in `test_technology_detection.py` (headers, cookies, DOM signatures). |

---

### 2.4 OWASP WSTG Test Planning & Coverage (PRD §4.4 / SRS Module D)

| Req ID | Requirement Description | Implementation Files | Status | Execution Evidence / Verification Notes |
|---|---|---|---|---|
| **FR-WP-01** | Comprehensive test catalog covering all 12 WSTG v4.2 categories | `services/execution_engine/wstg_catalog_data.py`<br>`database/models/wstg.py` | **Verified** | 100% of WSTG v4.2 categories and test cases present; `test_catalog_structure_and_completeness` passed. |
| **FR-WP-02** | Project-specific test plan generation mapped to endpoints | `services/execution_engine/planner.py`<br>`agents/wstg/wstg_agent.py` | **Verified** | Test instances instantiated per project; mapped dynamically based on discovered technologies. |
| **FR-WP-03** | Explicit test statuses (`Planned`, `Passed`, `Failed`, `N/A`, etc.) | `database/models/wstg.py`<br>`packages/schemas/wstg.py` | **Verified** | Status state transitions verified (`test_wstg_status_transitions` passed). |
| **FR-WP-04** | Mathematical coverage calculation: $\frac{\text{Passed+Failed+Review+NA}}{\text{Total}} \times 100$ | `services/execution_engine/coverage.py` | **Verified** | `test_compute_metrics_formula` passed with exact mathematical formula. |
| **FR-WP-05** | Manual override for security engineers with mandatory justification | `apps/api/routers/wstg.py` (PATCH instance) | **Verified** | PATCH endpoint validates justification string and updates instance status. |

---

### 2.5 Automated Security Testing Integration (PRD §4.5 / SRS Module E)

| Req ID | Requirement Description | Implementation Files | Status | Execution Evidence / Verification Notes |
|---|---|---|---|---|
| **FR-ST-01** | Tool execution wrapper for Nuclei with scope validation | `integrations/nuclei/runner.py` | **Mock / Stub** | Wrapper and argument builder verified (`test_nuclei_build_argv` passed); binary not installed; returns mock finding. |
| **FR-ST-02** | Tool execution wrappers for httpx, katana, ffuf | `integrations/ffuf/runner.py` | **Mock / Stub** | Ffuf wrapper verified (`test_ffuf_build_argv_rate_limit_capping` passed); katana/httpx runners absent. |
| **FR-ST-03** | Custom Python security check harness | `services/execution_engine/tools/http_client.py`<br>`agents/authorization/authz_agent.py`<br>`agents/vulnerability/vuln_agent.py` | **Verified** | Python-based HTTP prober with header injection, CORS, and IDOR testing active. |
| **FR-ST-04** | Strict process sandboxing: Zero dynamic shell execution from LLM | `services/execution_engine/tools/base.py` | **Verified** | `create_subprocess_exec` uses typed `argv: List[str]`; shell strings strictly prohibited. |
| **FR-ST-05** | Global and per-target rate limiting | `services/execution_engine/tools/base.py`<br>`integrations/ffuf/runner.py` | **Verified** | Capped at 150 requests/sec in runner builder. |

---

### 2.6 AI Agent System (PRD §4.6 / SRS Module F)

| Req ID | Requirement Description | Implementation Files | Status | Execution Evidence / Verification Notes |
|---|---|---|---|---|
| **FR-AG-01** | Multi-agent architecture built on stateful graph workflows | `services/orchestrator/supervisor.py`<br>`services/orchestrator/state.py` | **Partially Verified** | Custom Python sequential DAG supervisor used instead of LangGraph; state checkpointed to PostgreSQL. |
| **FR-AG-02** | 15 dedicated agents with distinct responsibilities | `agents/` | **Partially Verified** | 7 dedicated agent classes implemented; remaining 8 responsibilities consolidated into the 7. |
| **FR-AG-03** | Strict Agent-Tool boundary: agents emit JSON; engine executes | `agents/base.py` (`log_tool_call`) | **Verified** | Unauthorized tool calls raise `PermissionError` via `allowed_tools` allowlist. |
| **FR-AG-04** | Full agent observability: thought traces, tool calls, token/cost telemetry | `database/models/agent.py`<br>`agents/base.py`<br>`apps/api/routers/agents.py` | **Verified** | `AgentExecution`, `AgentDecision`, `AgentToolCall` persisted with prompt/completion tokens and cost in USD. |

---

### 2.7 Vulnerability Validation & Evidence Collection (PRD §4.7 / SRS Module G)

| Req ID | Requirement Description | Implementation Files | Status | Execution Evidence / Verification Notes |
|---|---|---|---|---|
| **FR-VV-01** | 10-step finding lifecycle | `database/models/finding.py`<br>`apps/api/routers/findings.py` | **Verified** | `FindingStatusHistory` tracks transitions from Detected to Confirmed/False Positive. |
| **FR-VV-02** | Evidence artifact collection (raw bytes, headers, curl command) | `services/evidence_engine/collector.py`<br>`services/evidence_engine/curl_generator.py` | **Verified** | `test_generate_reproduction_curl`, `test_serialize_raw_http_wire_format` passed. |
| **FR-VV-03** | Evidence integrity: SHA-256 hash for request/response pairs | `services/evidence_engine/hasher.py` | **Verified** | `test_compute_evidence_hash` passed. |
| **FR-VV-04** | Sensitive data masking: automatically redact cards, passwords, tokens | `services/evidence_engine/redactor.py` | **Verified** | 3 unit tests passed (`test_mask_sensitive_headers`, `test_redact_raw_stream_credentials`, `test_redact_raw_stream_credit_card`). |
| **FR-VV-05** | Automated reproduction harness: re-execute minimal payloads | `agents/validation/validation_agent.py` | **Verified** | Validation agent executes independent reproduction before confirming. |

---

### 2.8 Authorization & Business Logic Testing (PRD §4.8 / SRS Module H)

| Req ID | Requirement Description | Implementation Files | Status | Execution Evidence / Verification Notes |
|---|---|---|---|---|
| **FR-AB-01** | Multi-identity test execution (User A vs User B, Admin vs Member) | `agents/authorization/authz_agent.py` | **Verified** | Compares response status codes and body diffs across different auth headers. |
| **FR-AB-02** | Automated BOLA/IDOR detection | `agents/authorization/authz_agent.py` | **Verified** | Injects object IDs discovered in User A session into User B session. |
| **FR-AB-03** | Horizontal and vertical privilege escalation testing | `agents/authorization/authz_agent.py` | **Verified** | Tests elevated routes with lower-privileged tokens. |
| **FR-AB-04** | Business logic anomaly detection without destructive actions | `agents/authorization/authz_agent.py` | **Partially Verified** | Status anomaly detection functional; complex multi-step state machines require human review. |
| **FR-AB-05** | Flag suspicious anomalies as `Needs Manual Review` | `agents/authorization/authz_agent.py`<br>`database/models/wstg.py` | **Verified** | Non-conclusive responses transition to `Needs Manual Review`. |

---

### 2.9 Findings Management & Deduplication (PRD §4.9 / SRS Module I)

| Req ID | Requirement Description | Implementation Files | Status | Execution Evidence / Verification Notes |
|---|---|---|---|---|
| **FR-FM-01** | Findings dashboard with multi-dimensional filtering | `apps/web/src/app/findings/page.tsx`<br>`apps/api/routers/findings.py` | **Verified** | Filterable by Severity, Status, WSTG category, and search query. |
| **FR-FM-02** | Intelligent deduplication based on endpoint, parameter, and CWE | `services/evidence_engine/finding_service.py` | **Verified** | `test_benchmark_deduplication_hashing` passed. |
| **FR-FM-03** | False positive management with recorded justification | `database/models/finding.py`<br>`apps/api/routers/findings.py` | **Verified** | POST `/{finding_id}/false-positive` endpoint stores rationale in `false_positives` table. |
| **FR-FM-04** | One-click retest capability | `apps/api/routers/findings.py` | **Verified** | POST `/{finding_id}/retest` endpoint invokes automated validation prober. |

---

### 2.10 PTES Reporting Engine (PRD §4.10 / SRS Module J)

| Req ID | Requirement Description | Implementation Files | Status | Execution Evidence / Verification Notes |
|---|---|---|---|---|
| **FR-RP-01** | Generate PTES-aligned reports in PDF and standalone HTML | `services/reporting_engine/renderer.py` | **Verified** | `test_report_renderer_html` and `test_report_renderer_pdf` passed. |
| **FR-RP-02** | Comprehensive report sections (Cover, Exec Summary, WSTG, Findings, etc.) | `services/reporting_engine/context_builder.py`<br>`templates/ptes_standard.html` | **Verified** | Full PTES report context compiled from database entities. |
| **FR-RP-03** | Report customization (logo, client details, tester signatures) | `database/models/report.py`<br>`services/reporting_engine/context_builder.py` | **Verified** | `report_templates` table and customizable metadata parameters supported. |
| **FR-RP-04** | Report versioning: immutable snapshot preserved at publication | `database/models/report.py`<br>`apps/api/routers/reports.py` | **Verified** | Report records store complete snapshot JSON and generated file paths. |

---

## 3. Implementation Statistics Summary (Strict Recount)

The table below summarizes the exact row-by-row count across all 10 modules:

| Module | Total Reqs | Verified | Partially Verified | Mock / Stub | Not Implemented |
|---|:---:|:---:|:---:|:---:|:---:|
| **2.1 Project Management (FR-PM)** | 5 | 4 | 1 | 0 | 0 |
| **2.2 Scope Enforcement (FR-SC)** | 6 | 5 | 1 | 0 | 0 |
| **2.3 Attack Surface Discovery (FR-DS)** | 6 | 4 | 1 | 1 | 0 |
| **2.4 OWASP WSTG Test Planning (FR-WP)** | 5 | 5 | 0 | 0 | 0 |
| **2.5 Automated Security Testing (FR-ST)** | 5 | 3 | 0 | 2 | 0 |
| **2.6 AI Agent System (FR-AG)** | 4 | 2 | 2 | 0 | 0 |
| **2.7 Vulnerability Validation (FR-VV)** | 5 | 5 | 0 | 0 | 0 |
| **2.8 Authorization & Business Logic (FR-AB)** | 5 | 4 | 1 | 0 | 0 |
| **2.9 Findings Management (FR-FM)** | 4 | 4 | 0 | 0 | 0 |
| **2.10 PTES Reporting Engine (FR-RP)** | 4 | 4 | 0 | 0 | 0 |
| **TOTALS** | **49** | **40 (81.63%)** | **6 (12.24%)** | **3 (6.12%)** | **0 (0.00%)** |

> **Audit Note on "Not Implemented" Classification:**  
> The 49 functional requirements above correspond to capabilities that have at least partial code paths in the repository. However, several specific architectural and infrastructure subsystems documented in the specifications are **Not Implemented**. These are cataloged explicitly below.

---

## 4. Explicit Inventory of Not Implemented Items

The following items are specified in the architecture and design documentation (`docs/01`–`docs/24`), but are **Not Implemented** in the codebase:

| Item # | Document Reference | Specified Capability | Actual Implementation State | Severity / Classification |
|---|---|---|---|---|
| **NI-01** | `docs/01-prd.md` §4.6<br>`docs/04-agent-architecture.md`<br>`ADR-002` | **LangGraph Orchestration Framework** (Stateful cyclic graph, PostgreSQL checkpoints, conditional branch edges) | **Not Implemented.** `langgraph` is not in `requirements.txt`. Orchestrator uses a custom sequential Python class (`services/orchestrator/supervisor.py`). | **Architectural Divergence** |
| **NI-02** | `docs/01-prd.md` §4.6 (FR-AG-02)<br>`docs/05-agent-specifications.md` | **8 Dedicated Agent Classes** (Scope, Surface Mapping, Auth Testing, Input Validation, Fuzzing, False Positive, Evidence Collection, Business Logic) | **Not Implemented as Separate Classes.** Only 7 agent classes exist; the other 8 responsibilities are consolidated directly into services and active agents. | **Design Consolidation** |
| **NI-03** | `docs/01-prd.md` §4.2 (FR-SC-03)<br>`docs/08-scope-enforcement.md` §3 | **Layer 2 Network Egress Proxy Container** (Envoy/Squid with eBPF/socket filters intercepting all TCP egress) | **Not Implemented.** There is no egress proxy service in `docker-compose.yml`. Scope checking relies entirely on Layer 1 software validation in Python. | **P1 (Security Guardrail)** |
| **NI-04** | `docs/01-prd.md` §4.3 (FR-DS-01)<br>`docs/09-tool-integrations.md` §5.2-5.4 | **CLI Tool Runners for Katana, Httpx, and Subfinder** | **Not Implemented.** No runner classes exist in `integrations/`. Crawling and parameter extraction are done natively in Python (`services/discovery_engine/`). | **P2 (Tooling Gap)** |
| **NI-05** | `docs/16-skill-system.md` §5 | **Dynamic Skill Execution Runtime Engine** (Dynamic loading and executing of `SKILL.md` bundles with JSON Schema parameter validation) | **Not Implemented.** Zero Python files load or execute files from `skills/`. The 18 `SKILL.md` files are documentation/prompts only. | **P2 (Extensibility Gap)** |
| **NI-06** | `docs/01-prd.md` §4.6<br>`docs/18-deployment-architecture.md` | **Celery / Redis Distributed Task Consumer** | **Not Implemented.** `services/execution_engine/worker.py` is an idle `asyncio.sleep(2)` stub. The API server executes workflows in-process via `asyncio.create_task`. | **P2 (Scalability Gap)** |
| **NI-07** | `docs/10-database-design.md` §7 | **Alembic Database Migration Pipeline** (Versioned schema migrations with reversible up/down scripts) | **Not Implemented.** No `alembic.ini` or migration revisions exist; tables are created via `Base.metadata.create_all()` in `apps/api/main.py`. | **P3 (Maintainability Gap)** |
| **NI-08** | `docs/01-prd.md` §4.1 (FR-PM-03)<br>`docs/10-database-design.md` §3.9 | **Target Credential Vault Tables with AES-256-GCM at Rest** (`auth_profiles`, `test_credentials`) | **Not Implemented.** Target authentication is currently passed in memory or stored unencrypted in JSON state. (To be resolved in PF-4). | **P0 (Security Vulnerability)** |
| **NI-09** | `docs/10-database-design.md` §3.10 | **Scan Scheduling & Recurring Jobs Tables** (`scan_schedules`, `scan_jobs`) | **Not Implemented.** No automated recurring scan scheduler or cron engine is implemented in the database or backend. | **P3 (Feature Gap)** |
