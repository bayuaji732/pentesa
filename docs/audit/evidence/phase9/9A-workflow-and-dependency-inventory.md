# Phase 9: Workflow Engine & Dependency Inventory

> **Document Identifier:** `9A-WORKFLOW-DEPENDENCY-INVENTORY-V1.0`  
> **Evaluation Date:** `2026-11-24`  
> **Scope:** Workflow engine architecture, execution worker reality, task scheduling, database schema checkpoints, Python and npm dependencies, dead code, and proposed actions.

---

## 1. Workflow Engine Architecture Audit

### 1.1 LangGraph Usage & Reality
- **Documentation Claims:** PRD §4.2, SRS §3.1, and several early documentation drafts claim the 7-agent workflow is "orchestrated and governed by LangGraph".
- **Codebase Grep (`langgraph`):** **0 occurrences** across all Python modules, `requirements.txt`, `pyproject.toml`, Dockerfiles, and runtime configurations.
- **Reality:** LangGraph was **never implemented**. The workflow engine is an entirely custom Directed Acyclic Graph (DAG) state machine implemented in:
  - `services/orchestrator/supervisor.py` (`MultiAgentWorkflowSupervisor`)
  - `services/orchestrator/graph.py` (DAG state transitions)
- **Evaluation:** The custom DAG achieved 18/18 workflow completions with 100% agent handoff fidelity and $0.00 supervisor crash rates. Replacing it with LangGraph would introduce high dependency weight without functional benefit.

### 1.2 Celery & Redis Task Broker Reality
- **Documentation Claims:** Architecture §6, SRS §4.3, and `NI-06` reference a "distributed Celery task broker consuming queues via Redis".
- **Codebase Grep (`celery`):** **0 occurrences** in code, `requirements.txt`, or Dockerfiles.
- **Worker Process Reality (`services/execution_engine/worker.py`):**
  ```python
  # services/execution_engine/worker.py:48-56
  while not SHUTDOWN_EVENT.is_set():
      try:
          # Poll task queues or perform heartbeat maintenance
          await asyncio.sleep(2)
      except asyncio.CancelledError:
          break
  ```
  The worker container (`pentesa-worker`) runs an idle sleep loop. It connects to neither Redis nor PostgreSQL for task dispatch.
- **Workflow Task Dispatch Reality (`apps/api/routers/agents.py:46-55`):**
  ```python
  _ACTIVE_WORKFLOW_TASKS: Dict[uuid.UUID, asyncio.Task] = {}
  task = asyncio.create_task(_run_workflow_background(workflow_id, step_delay_seconds=delay))
  _ACTIVE_WORKFLOW_TASKS[workflow_id] = task
  ```
  Workflows execute **in-process and in-memory** inside the `pentesa-api` FastAPI web server process.
- **Impact (`DEFECT-REL-01`):**
  If `pentesa-api` restarts, crashes, or is redeployed mid-workflow, all active scans in `_ACTIVE_WORKFLOW_TASKS` terminate irrevocably without auto-resumption (`NFR-REL-01` Failed).

### 1.3 State Checkpoint Tables & Resumption Engine
- **PostgreSQL Checkpoint Audit:**
  - `workflow_executions` table (`database/models/agent.py:111-136`) contains `current_phase`, `status`, and `state_data` (JSONType).
  - `supervisor.py:301-325` updates and commits `workflow.state_data` after each agent completes, storing `workflow_snapshot` and `completed_agent_ids`.
  - Pause (`POST /api/v1/agents/workflows/{id}/pause`) and resume (`POST /api/v1/agents/workflows/{id}/resume`) successfully read `workflow.state_data["workflow_snapshot"]`.
- **Finding:** Checkpointing infrastructure **already exists** in PostgreSQL! The single missing component is decoupling execution from the API web process by publishing workflow job IDs to Redis and consuming them in `pentesa-worker`.

---

## 2. Dependency Audit (Python & npm)

### 2.1 Python Dependencies (`requirements.txt`)

| Package | Declared Version | Imported In Codebase | Purpose & Audit Notes | Proposed Action |
|---|---|:---:|---|---|
| `fastapi` | `>=0.110.0` | **Yes** | Core REST API framework | Keep |
| `uvicorn[standard]` | `>=0.28.0` | **Yes** | ASGI server (`apps/api/main.py`) | Keep |
| `pydantic` | `>=2.6.0` | **Yes** | Schema validation & DTOs | Keep |
| `pydantic-settings`| `>=2.2.0` | **Yes** | Environment config parsing | Keep |
| `python-multipart` | `>=0.0.9` | **Yes** | Form-data parsing for auth login | Keep |
| `email-validator` | `>=2.0.0` | **Yes** | User email validation | Keep |
| `sqlalchemy[asyncio]` | `>=2.0.28` | **Yes** | Async ORM & query builder | Keep |
| `greenlet` | `>=3.0.0` | **Yes** | SQLAlchemy async relationship support | Keep |
| `alembic` | `>=1.13.1` | **Yes** | Database schema migrations | Keep |
| `asyncpg` | `>=0.29.0` | **Yes** | Native PostgreSQL async driver | Keep |
| `aiosqlite` | `>=0.20.0` | **No** (Only fallback) | Local SQLite fallback driver (`DEFECT-CFG-01`) | **Purge in Wave 0** (fail closed on missing Postgres URL) |
| `pyjwt` | `>=2.8.0` | **Yes** | JWT token minting and signature verification | Keep |
| `passlib[bcrypt]` | `>=1.7.4` | **Yes** | Legacy password hashing wrapper | **Deprecate**: Migrate directly to `bcrypt` in Wave 0 |
| `bcrypt` | `>=4.1.2` | **Yes** | Direct secure password hashing | Keep |
| `cryptography` | `>=42.0.5` | **Yes** | AES-256-GCM vault encryption (Fernet) | Keep |
| `httpx` | `>=0.27.0` | **Yes** | Async HTTP prober (`safe_request`) | Keep |
| `jinja2` | `>=3.1.2` | **Yes** | PTES HTML report templating | Keep |
| `reportlab` | `>=4.1.0` | **Yes** | PDF report rendering engine | Keep |
| `pytest` | `>=8.1.0` | **Yes** | Test runner | Keep (Dev/Test) |
| `pytest-asyncio` | `>=0.23.5` | **Yes** | Async test execution | Keep (Dev/Test) |
| `pytest-cov` | `>=5.0.0` | **Yes** | Coverage metrics | Keep (Dev/Test) |
| `redis` | *Undeclared* | **Yes** | Redis client installed in Dockerfile | **Add to `requirements.txt`** |

### 2.2 npm Dependencies (`apps/web/package.json`)

| Package | Declared Version | Purpose & Audit Notes | Proposed Action |
|---|---|---|---|
| `next` | `14.2.18` | App Router frontend; 35 advisories in npm registry (`DEFECT-DEP-01`) | **Upgrade to `14.2.35`** (Smallest-jump) in Wave 0/1 |
| `react` | `^18.3.1` | React core framework | Keep on 18.x (avoid React 19 breaking changes) |
| `react-dom` | `^18.3.1` | React DOM renderer | Keep on 18.x |
| `clsx` | `^2.1.1` | Class composition utility | Keep |
| `tailwind-merge` | `^2.5.4` | Tailwind class deduplication | Keep |
| `lucide-react` | `^0.454.0` | Icon set | Keep |
| `tailwindcss` | `^3.4.15` | CSS utility framework | Keep |
| `postcss` | `^8.4.49` | CSS post-processor; embedded in Next.js build | Upgrade with Next.js |

---

## 3. Unused Services, Containers & Dead Code

| Component / Artifact | Path / Location | Current Reality | Proposed Action |
|---|---|---|---|
| **`pentesa-worker` Loop** | `services/execution_engine/worker.py` | Runs `asyncio.sleep(2)` without task ingestion | Refactor to consume Redis queue (`ADR-001`) |
| **`aiosqlite` Fallback** | `apps/api/config.py`, `database/session.py` | Local SQLite fallback (`pentesa.db`) when env missing | **Remove fallback**; fail closed with clear error |
| **`Subfinder` Allowlist**| `agents/recon/recon_agent.py:41` | Allowlisted without wrapper or container binary | Remove from allowlist until `NI-03` implemented |
| **`_ACTIVE_WORKFLOW_TASKS`** | `apps/api/routers/agents.py:46` | Ephemeral in-memory dict | Replace with Redis job submission |
| **Duplicate `STATUS` File**| Repo root `./STATUS` | Duplicate of master prompt | Purged in hygiene cleanup |
| **Unreferenced `.scratch`**| Repo root, `.venv` | Temporary scripts and unhashed test logs | Purged in hygiene cleanup |

---

## 4. Proposed Cleanup & Remediation Wave Alignment

1. **Wave 0 (Config & Hygiene):**
   - Purge `aiosqlite` from `requirements.txt` and eliminate SQLite fallback in `database/session.py`.
   - Add explicit `deploy.resources.limits` to `docker-compose.yml`.
   - Update `next` in `apps/web/package.json` to `14.2.35` and set `dangerouslyAllowSVG: false`.
2. **Wave 1 (Data Trust):**
   - Correct `FindingResponse` schema to include `endpoint`, `method`, `target`, `parameter`.
   - Ensure CVSS calculator runs for all findings.
3. **Wave 2 (Safety):**
   - Enforce `asyncio.timeout()` in `safe_request()` for cumulative stream deadline.
   - Enforce `except asyncio.CancelledError:` and process cleanup in `BaseToolWrapper`.
4. **Wave 3 (Durability):**
   - Implement Redis queue consumer in `services/execution_engine/worker.py` (`ADR-001 Option B`).
