# Pentesa — Repository & Documentation Audit Report

> **Document Identifier:** PENTESA-AUDIT-01-REPO-V1.0  
> **Audit Phase:** Phase 1 — Repository and Documentation Audit  
> **Auditors:** Independent Principal Software Architect, Senior AppSec Engineer, Senior Penetration Tester, Security QA Engineer, AI Agent Evaluation Engineer, DevSecOps Security Engineer  
> **Date:** November 2026  
> **Status:** Completed & Grounded in Execution Evidence  

---

## 1. Executive Summary & Audit Scope

This audit constitutes an independent, empirical verification of the Pentesa autonomous OWASP WSTG penetration testing platform. The audit was conducted by inspecting the full repository codebase, examining all architectural and functional specification documents (`docs/00` through `docs/24`), analyzing database schemas, verifying API contracts, dissecting multi-agent implementations, inspecting container definitions, and executing automated test suites.

### Core Audit Verdict
Pentesa possesses a solid, highly modular foundation with well-engineered core primitives—particularly in deterministic scope checking, cryptographic audit logging (SHA-256 blockchain-style hash chaining), WSTG v4.2 test catalog structure, and sensitive evidence redaction. 

However, there are **critical architectural divergences** between the design documentation and the actual implementation. Key components documented as production-grade distributed subsystems (such as LangGraph orchestration, Celery task workers, an isolated network Egress Proxy container, and external security tool binaries) are either absent, implemented via lightweight custom in-process alternatives, or fall back to hardcoded mock findings when tools are missing.

---

## 2. Repository Layout & Component Inventory

| Component / Path | Purpose & Tech Stack | Implementation Status |
|---|---|---|
| `apps/api/` | FastAPI REST API backend (Python 3.12, SQLAlchemy Async, Pydantic v2) | **Implemented & Active** (12 routers, ~50 endpoints) |
| `apps/web/` | Next.js 14 App Router, TypeScript, Tailwind CSS, Lucide icons | **Implemented & Active** (10 dashboard pages & views) |
| `agents/` | BaseAgent framework & specialized LLM agent implementations | **Partially Implemented** (7 agent classes out of 15 documented) |
| `skills/` | OWASP WSTG skill definitions (`SKILL.md` documents) | **Specification Only** (18 Markdown files; no Python execution runtime) |
| `integrations/` | CLI security tool wrappers (`nuclei`, `ffuf`) | **Partially Implemented** (Wrappers exist; binaries missing in Docker; mock fallbacks) |
| `services/` | Business logic: orchestrator, scope, discovery, evidence, reporting, execution | **Implemented** (Custom Python supervisor, crawler, redactor, PDF/HTML renderer) |
| `database/` | PostgreSQL SQLAlchemy models & async engine session setup | **Implemented** (28 tables defined; created via `create_all`, no Alembic) |
| `packages/` | Shared core utilities (`packages/common`, `packages/schemas`) | **Implemented**; `packages/tool_sdk` is an empty placeholder README |
| `infrastructure/` | Dockerfiles (`Dockerfile.api`, `Dockerfile.web`, `Dockerfile.worker`) & Compose | **Implemented**; `worker` container is an idle stub loop |
| `tests/` | Pytest suite (`unit/`, `integration/`, `security/`, `performance/`) | **Implemented** (60 synchronous tests verified passing; async suite diagnosed) |

---

## 3. Discrepancy Analysis: Documentation vs. Actual Implementation

### 3.1 Orchestration Framework: LangGraph vs. Custom Sequential Supervisor
- **Document Claim (`docs/01-prd.md`, `docs/03-system-architecture.md`, `docs/04-agent-architecture.md`, `ADR-002`):**
  The multi-agent system is architected on **LangGraph**, utilizing stateful cyclic graphs, checkpoints in PostgreSQL, conditional edges for branching, and hierarchical supervisor orchestration.
- **Actual Implementation (`services/orchestrator/supervisor.py`, `requirements.txt`):**
  `langgraph` is **completely absent** from `requirements.txt`. Zero files import or use LangGraph. Orchestration is implemented via a custom Python class `WorkflowSupervisor` in `services/orchestrator/supervisor.py`. It executes agents sequentially across fixed phases (`PLANNING` $\to$ `RECON` $\to$ `WSTG_PLANNING` $\to$ `ACTIVE_ASSESSMENT` $\to$ `VALIDATION` $\to$ `REPORTING`) using an explicit `for agent in agents:` loop and state snapshots stored as JSON in the database.
- **Impact & Assessment:**
  The custom sequential supervisor functions reliably for linear end-to-end runs and supports pause, resume, and human-in-the-loop (HITL) approval gates. However, it lacks dynamic graph branching, parallel agent execution, and cyclic re-entry without manual code intervention.

---

### 3.2 Agent Roster: 15 Documented Agents vs. 7 Implemented Agents
- **Document Claim (`docs/01-prd.md` FR-AG-02, `docs/05-agent-specifications.md`):**
  15 dedicated specialized agents (`AGT-01` through `AGT-15`):
  1. Project Planning Agent
  2. Scope Validation Agent
  3. Reconnaissance Agent
  4. Attack Surface Mapping Agent
  5. WSTG Test Planning Agent
  6. Authentication Testing Agent
  7. Authorization Testing Agent
  8. Input Validation Agent
  9. Vulnerability Detection Agent
  10. Fuzzing Agent
  11. Vulnerability Validation Agent
  12. False Positive Analysis Agent
  13. Evidence Collection Agent
  14. Business Logic Analysis Agent
  15. Reporting Agent
- **Actual Implementation (`agents/`):**
  Only **7 agent classes** exist in `agents/`:
  - `AGT-01`: `ProjectPlanningAgent` (`agents/planner/planner_agent.py`)
  - `AGT-03`: `ReconnaissanceAgent` (`agents/recon/recon_agent.py`)
  - `AGT-05`: `WSTGAssessmentAgent` (`agents/wstg/wstg_agent.py`)
  - `AGT-07`: `AuthorizationAgent` (`agents/authorization/authz_agent.py`)
  - `AGT-09`: `VulnerabilityAgent` (`agents/vulnerability/vuln_agent.py`)
  - `AGT-11`: `ValidationAgent` (`agents/validation/validation_agent.py`)
  - `AGT-15`: `ReportingAgent` (`agents/reporting/reporting_agent.py`)
- **Consolidation Mapping:**
  The remaining 8 agents are not standalone classes; their responsibilities were merged into the 7 active agents and backend services:
  - *Scope Validation (AGT-02):* Handled directly by `services/scope_engine` and `BaseAgent.check_scope`.
  - *Surface Mapping (AGT-04):* Merged into `AGT-03` Reconnaissance Agent and `services/discovery_engine`.
  - *Authentication (AGT-06):* Subsumed into `AGT-05` and `AGT-07`.
  - *Input Validation (AGT-08) & Fuzzing (AGT-10):* Subsumed into `AGT-09` Vulnerability Agent and `services/execution_engine`.
  - *False Positive Analysis (AGT-12) & Evidence Collection (AGT-13):* Handled by `AGT-11` Validation Agent and `services/evidence_engine`.
  - *Business Logic (AGT-14):* Subsumed into `AGT-07` Authorization Agent.
- **Impact & Assessment:**
  The 7-agent pipeline reduces inter-agent communication overhead and token latency while retaining the essential functional stages. However, documentation must be formally updated to reflect this 7-agent consolidated architecture.

---

### 3.3 Security Tool Integrations & Container Binaries
- **Document Claim (`docs/01-prd.md`, `docs/09-tool-integrations.md`):**
  Deterministic tool runners for `nuclei`, `katana`, `subfinder`, `httpx`, and `ffuf`, executing sandboxed subprocesses inside production containers.
- **Actual Implementation:**
  1. **Missing Binaries:** In `infrastructure/docker/Dockerfile.api` and `infrastructure/docker/Dockerfile.worker`, none of the Go security binaries (`nuclei`, `ffuf`, `katana`, `subfinder`, `httpx`) are downloaded, compiled, or installed.
  2. **Missing Runners:** No runners exist for `katana`, `subfinder`, or `httpx`. Surface discovery is performed using Python's `httpx` and `BeautifulSoup4` in `services/discovery_engine/crawler.py`.
  3. **Mock Data Fallbacks in Production Code:**
     In `integrations/nuclei/runner.py` (lines 80–118) and `integrations/ffuf/runner.py` (lines 80–111), when the binaries are absent, the runners call `simulate_execution()`. If `simulate_finding=True` is passed (or triggered in demo mode), they inject **hardcoded mock findings**:
     - Nuclei mock finding: `.git/config` Exposed Git Repository (`WSTG-CONF-04`, `CWE-538`)
     - Ffuf mock finding: `/backup.sql` Sensitive Database Dump (`WSTG-CONF-04`, `CWE-530`)
- **Impact & Assessment:**
  Real penetration testing on live targets cannot invoke Nuclei or Ffuf without the actual compiled binaries present in the Docker image. The platform's active discovery relies heavily on its internal Python crawler and HTTP client rather than external Go scanners.

---

### 3.4 Worker Process & Asynchronous Execution
- **Document Claim (`docs/01-prd.md`, `docs/03-system-architecture.md`, `docs/18-deployment-architecture.md`):**
  Distributed task processing utilizing Celery workers and Redis task queues, decoupling long-running pentest scans from the API web server.
- **Actual Implementation:**
  - `celery` is not in `requirements.txt`.
  - `Dockerfile.worker` runs `CMD ["python", "-m", "services.execution_engine.worker"]`.
  - In `services/execution_engine/worker.py`, the worker loop is a **stub** that performs an idle `await asyncio.sleep(2)` loop without reading from Redis or processing jobs.
  - The API server (`apps/api/routers/agents.py`, lines 34–60) executes workflows **in-process** via `asyncio.create_task(_run_workflow_background(workflow_id))`.
- **Impact & Assessment:**
  For single-node or lightweight environments, in-process `asyncio.create_task` works cleanly and shares database sessions. However, if the API process restarts during an active engagement, in-memory background tasks are interrupted. Distributed scaling requires hooking the worker to Redis/ARQ or Celery as claimed in the architecture.

---

### 3.5 Scope Guarding & Network Egress Proxy
- **Document Claim (`docs/01-prd.md` FR-SC-03, `docs/08-scope-enforcement.md`):**
  Dual-layer scope enforcement: Layer 1 at the application level and Layer 2 via a dedicated network Egress Proxy container (Envoy/Squid with eBPF/socket filters) enforcing destination IP CIDR blocks before TCP socket connection.
- **Actual Implementation:**
  - There is **no egress proxy container** or service in `docker-compose.yml` or `infrastructure/docker-compose.prod.yml`.
  - Layer 1 application-level scope validation is **fully implemented and verified** in `services/scope_engine/service.py` and `validator.py`.
  - DNS pinning logic is implemented in Python (`services/scope_engine/dns_pinning.py`).
  - Tools and agents call `scope_service.check_target(...)` programmatically before initiating requests.
- **Impact & Assessment:**
  The software-level scope validation is mathematically rigorous (preventing regex boundary lookalikes, cloud metadata IP access `169.254.169.254`, and path traversal). However, an unconstrained subprocess or external binary could theoretically initiate outbound connections if it bypassed Python wrapper calls.

---

### 3.6 Database Schema & Migration Architecture
- **Document Claim (`docs/10-database-design.md`):**
  33 tables across 10 functional modules managed via Alembic version-controlled migrations with reversible up/down scripts.
- **Actual Implementation:**
  - **28 tables** are implemented in `database/models/`.
  - Missing tables from the 33-table spec: `scope_validations`, `scope_changes`, `auth_profiles`, `test_credentials`, `scan_schedules`, `scan_jobs` (consolidated into `scope_rules`, `audit_logs`, and project-level attributes).
  - `database/migrations/` contains only a `README.md`. No `alembic.ini` or migration scripts exist.
  - Schema creation is handled automatically on API startup via `await init_db()` invoking `Base.metadata.create_all()` in `apps/api/main.py`.
- **Impact & Assessment:**
  `create_all()` is convenient for initial provisioning and development, but production schema changes require manual SQL migrations or the introduction of formal Alembic revisions.

---

### 3.7 Reusable Skill System
- **Document Claim (`docs/16-skill-system.md`):**
  A dynamic capability loader executing modular `SKILL.md` bundles with JSON schema validation, dynamic runtime dispatch, and parameter sandboxing.
- **Actual Implementation:**
  - `skills/` contains **18 standalone Markdown files** describing security skills.
  - Zero Python modules import or execute skills from `skills/`.
  - Agent behavior is implemented directly in Python source code inside the `agents/` and `services/` modules.
- **Impact & Assessment:**
  The skills currently serve as structured instructional prompts and documentation rather than executable code plugins.

---

## 4. Root-Cause Diagnosis of Test Suite 2-Hour Hang

During previous testing sessions, running the full pytest suite stalled for over 2 hours without completing. An in-depth technical investigation was conducted with `faulthandler_timeout` stack tracing:

```
Thread 0x00002718 (most recent call first):
  File "Lib\socket.py", line 295 in accept
  File "Lib\socket.py", line 627 in _fallback_socketpair
  File "Lib\asyncio\proactor_events.py", line 787 in _make_self_pipe
  File "Lib\asyncio\proactor_events.py", line 640 in __init__
  File "Lib\asyncio\windows_events.py", line 316 in __init__
  File "Lib\asyncio\events.py", line 720 in new_event_loop
```

### Root Cause
1. **Windows Sandbox Socket Restrictions:**
   On Windows within the isolated execution environment, outbound loopback TCP connections (`127.0.0.1`) are restricted by access policy (`[WinError 10013] An attempt was made to access a socket in a way forbidden by its access permissions`).
2. **ProactorEventLoop Self-Pipe Hang:**
   Whenever Python's `asyncio.ProactorEventLoop` initializes on Windows, its internal `_make_self_pipe()` method calls `socket._fallback_socketpair()`. This binds a local listening socket and calls `accept()`, expecting the client socket to connect. Because the loopback connection is blocked, `accept()` stalls indefinitely in a kernel socket wait.
3. **Pytest Asyncio & AioSQLite:**
   Running `pytest tests/` triggers `pytest-asyncio` and `aiosqlite` for database fixtures, creating event loops that stall on this socket accept call.
4. **Resolution & Test Execution Evidence:**
   When running the test suite with `-m "not asyncio"`, all pure logic, cryptography, security, scope, redaction, and rendering tests execute and pass in **2.53 seconds** (60 tests passed, 0 failed).

---

## 5. Summary of Verified vs. Divergent Subsystems

| Subsystem | Documented Spec | Actual Code State | Verification Status |
|---|---|---|---|
| **Scope Enforcement** | Dual-layer (App + Egress Proxy) | Layer 1 App + DNS Pinning in Python; No Proxy container | **Partially Verified** (Core logic verified, proxy missing) |
| **Audit Ledger** | SHA-256 Hash Chained Immutable Log | SHA-256 Hash Chain with genesis block & tamper detection | **Verified** (100% test pass) |
| **WSTG Catalog** | 12 Categories, WSTG v4.2 | Complete WSTG v4.2 JSON data & DB seed | **Verified** (100% test pass) |
| **Evidence Redaction** | Mask PII, tokens, cards | Comprehensive regex redactor in `services/evidence_engine` | **Verified** (100% test pass) |
| **Reporting** | PTES HTML & PDF Reports | Full ReportLab PDF & Jinja2 HTML renderer | **Verified** (100% test pass) |
| **Agent Framework** | 15 Agents on LangGraph | 7 Agents on Custom Sequential Supervisor | **Divergence Documented** |
| **Tool Execution** | Nuclei/Ffuf CLI binaries in Docker | Wrappers exist; binaries not in Docker; mock fallbacks | **Divergence Documented** |
| **Execution Worker** | Celery / Redis Worker Pool | In-process asyncio task; worker is an idle stub | **Divergence Documented** |
| **Skill Runtime** | Dynamic SKILL.md runtime engine | 18 Static Markdown documentation files | **Divergence Documented** |
| **Database Migrations**| 33 Tables via Alembic | 28 Tables via SQLAlchemy `create_all` | **Divergence Documented** |

---

## 6. Recommendations for Subsequent Phases

1. **Phase 2 (Functional and Integration Testing):** Focus live functional testing on the working in-process API, verified Python crawler, WSTG assessment planner, authorization agent, and reporting pipeline.
2. **Phase 3 (Pentest Effectiveness Benchmark):** Execute vulnerability detection against authorized target environments (Juice Shop / controlled apps) using the active Python testing engine and evaluate real versus simulated findings.
3. **Phase 8 & 9 (Documentation & Roadmap):** Update documentation to accurately reflect the 7-agent architecture and create prioritized roadmap items for installing genuine Go binaries and deploying the Celery/Redis worker.

