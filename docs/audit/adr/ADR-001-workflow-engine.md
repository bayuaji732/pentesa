# ADR-001: Workflow Engine Architecture & Worker Task Decoupling

> **Document Identifier:** `ADR-001-WORKFLOW-ENGINE`  
> **Status:** PROPOSED  
> **Date:** 2026-11-24  
> **Auditors / Authors:** Independent Principal Architect, AppSec & Systems Evaluation Team  
> **Supersedes:** `docs/decisions/ADR-002-langgraph-agent-orchestration.md`

---

## 1. Context & Problem Statement

The Pentesa documentation claims that the 7-agent penetration testing workflow is governed by LangGraph and backed by a distributed Celery worker queue consuming tasks from Redis (`docs/01-prd.md`, `docs/03-system-architecture.md`, `NI-06`).

Empirical auditing across Phases 1 through 8 revealed:
1. **LangGraph is Absent:** Zero lines of LangGraph code or dependencies exist. The workflow engine is an entirely custom Directed Acyclic Graph (DAG) state machine in `services/orchestrator/supervisor.py` and `graph.py`.
2. **Celery is Absent:** Celery is not installed.
3. **Execution Worker is an Idle Stub:** `services/execution_engine/worker.py` runs an idle loop (`await asyncio.sleep(2)`).
4. **Workflows Run In-Memory in API Process:** `apps/api/routers/agents.py` dispatches scans via `asyncio.create_task` and tracks them in an ephemeral in-memory dictionary `_ACTIVE_WORKFLOW_TASKS`.
5. **Vulnerability to Process Crashes (`DEFECT-REL-01` / `NFR-REL-01`):** If the API server restarts or redeploys, all active scans terminate permanently without automatic resumption.
6. **Empirical Success of Custom DAG:** Despite the missing worker queue, the custom DAG achieved **18/18 workflow completions with 100% agent handoff fidelity**, zero supervisor deadlocks, and verified approval pause/resume functionality.

---

## 2. Options Considered

### Option A: Replace Custom DAG with LangGraph + PostgreSQL Checkpointer
- **Pros:** Aligns with early aspirational marketing/spec documentation; native cyclic graph abstractions.
- **Cons:** High architectural risk. Requires rewriting 1,200+ lines of verified, passing orchestrator code; introduces 35+ external dependencies; requires porting custom human approval gates and token accounting; no evidence that current DAG logic is broken.

### Option B: Retain Custom DAG + PostgreSQL Checkpoints + Redis Queue Worker (RECOMMENDED)
- **Pros:**
  1. Preserves the proven, 100% passing custom DAG logic and handoff state serialization.
  2. Leverages the existing `workflow_executions` table (`database/models/agent.py`) where `workflow.state_data["workflow_snapshot"]` is already persisted after each agent transition.
  3. Replaces in-memory `_ACTIVE_WORKFLOW_TASKS` with a lightweight, native async Redis queue consumer in `services/execution_engine/worker.py`.
  4. On worker startup, the worker queries PostgreSQL for workflows where `status = 'RUNNING'`, resuming execution from the last persisted phase within 15 seconds (`NFR-REL-01`).
  5. Minimal dependency footprint (uses already installed `redis` client).

### Option C: Implement Celery Task Broker per Original Spec
- **Pros:** Familiar enterprise task queue pattern.
- **Cons:** High complexity and impedance mismatch. Celery is synchronous-first and operates poorly with native `asyncio` coroutines; requires `asgiref` / `async_to_sync` wrappers; adds heavy dependencies (`kombu`, `billiard`, `amqp`); complex signal handling.

---

## 3. Decision

We choose **Option B: Retain the Custom DAG, persist PostgreSQL step checkpoints, and implement an active Redis task consumer in `services/execution_engine/worker.py`**.

---

## 4. Implementation Specification

1. **Redis Task Submission:** In `apps/api/routers/agents.py`, replace `asyncio.create_task()` with `await redis_client.rpush("pentesa:queue:workflows", str(workflow_id))`.
2. **Active Worker Consumer:** In `services/execution_engine/worker.py`, implement `brpop("pentesa:queue:workflows", timeout=2)` to dequeue jobs and execute DAG steps.
3. **Resumption Engine:** On worker startup, query `WorkflowExecution` where `status = 'RUNNING'`, re-enqueue orphaned IDs, and resume execution from `state_data["workflow_snapshot"]`.
4. **Approval Integration:** Approval pause/resume continues to operate directly on `workflow_executions.status` and `approval_requests`.
