# Phase 8 Specification: Reliability, Performance, Concurrency, and Resource Limits (8A-Spec)

**Document Identifier:** PENTESA-AUDIT-P8-SPEC-V1.0  
**Phase:** Phase 8 Reliability, Performance, Concurrency & Resource Limits Benchmark  
**Author:** Independent Security & Performance Audit Team  
**Evaluation Target:** Production Stack (`pentesa-prod` on `pentesa-internal`) & Benchmark Lab (`pentesa-bench` on `pentesa-bench-net`)  
**Standard References:**  
- [`docs/01-prd.md`](file:///c:/Users/User2/Documents/work/pentesa/docs/01-prd.md) (Product Requirements Document — Section 7 Non-Functional Requirements)  
- [`docs/02-srs.md`](file:///c:/Users/User2/Documents/work/pentesa/docs/02-srs.md) (System Requirements Specification — Sections 5.1, 5.2, 5.3, 5.4)  
- [`docs/03-system-architecture.md`](file:///c:/Users/User2/Documents/work/pentesa/docs/03-system-architecture.md) (System Architecture — Sections 5.2, 5.3)  
- [`docs/18-deployment-architecture.md`](file:///c:/Users/User2/Documents/work/pentesa/docs/18-deployment-architecture.md) (Production Deployment Guide)  
- [`docs/audit/00-master-prompt.md`](file:///c:/Users/User2/Documents/work/pentesa/docs/audit/00-master-prompt.md) (Master Audit Prompt — Part 2 Phase 8 Execution)  

---

## 1. Master Requirements & Verification Matrix

| Requirement ID | Category | Specification Source | Metric / Threshold Requirement | Implementation Reality & Code Evidence | Baseline Audit Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **NFR-DEP-01** | Deployment / Startup | PRD §7, SRS §5.1 | `docker compose up -d` brings up all services into healthy state in $< 180\text{ s}$. | Docker Compose v2 with service healthchecks (`/healthz`, `/readyz`, pg_isready, redis-ping). | **Verified** (Subject to timed live tests) |
| **NFR-PERF-01** | API Latency | PRD §7, SRS §5.1 | P95 latency $< 200\text{ ms}$ for endpoint inventory queries and dashboard views under 5,000 items. | Async FastAPI endpoints backed by SQLAlchemy async session and indexed PostgreSQL tables. | **Verified** (Subject to 5,000 & 10,000 seeded load test) |
| **NFR-SCAL-01** | Scalability & Pagination | PRD §7, SRS §5.1 | Support large web applications with up to 10,000 discovered endpoints per project via indexed JSONB and cursor pagination. | `apps/api/routers/discovery.py:110-138` implements `offset` / `limit` pagination. Cursor pagination is **Not Implemented**. Findings router (`apps/api/routers/findings.py:31-46`) has no pagination. | **Partially Implemented** (Offset/limit active; Cursor pagination missing) |
| **NFR-PERF-02** | Rate Control | PRD §4.5, SRS §5.1 | Outbound scan rate control: configurable concurrency and requests per second, enforced within $\pm 5\%$ of configured target RPS. | `integrations/ffuf/runner.py:63` (`-rate`) and `integrations/nuclei/runner.py:65` (`-rate-limit`) pass flags to CLI tools. | **Verified** (Subject to 5 & 20 RPS wire benchmark) |
| **NFR-SAFE-01** | Circuit Breaker | PRD §4.5 vs Arch §5.3 | Backoff pause when 5xx errors exceed threshold (PRD: 15%/30s; Arch: 20%/60s). | Zero circuit breaker logic exists in `services/execution_engine/worker.py`, `services/orchestrator/supervisor.py`, or `integrations/`. | **Not Implemented** |
| **NFR-REL-01** | Fault Tolerance / Resumption | PRD §7, Arch §5.3 | Long-running scans survive worker restarts via persistent state checkpoints in PostgreSQL; state resumption within 15 seconds. | Celery and LangGraph not implemented (`NI-01`). Worker (`services/execution_engine/worker.py`) is an idle sleep loop. Workflows run in-memory via `_ACTIVE_WORKFLOW_TASKS` in API container (`apps/api/routers/agents.py:35`). | **Not Implemented** |
| **NFR-REL-02** | Tool Fault Isolation | PRD §7, SRS §5.4 | Inability of a single tool or agent to complete must not crash overall scan workflow; graceful capture, test marked `Error`. | Subprocess wrapped in `asyncio.create_subprocess_exec` inside `try...except` in `services/execution_engine/tools/base.py:180-252`. | **Verified** (Subject to live exception injection) |
| **NFR-AUD-01** | Audit Log Integrity | PRD §7, SRS §5.4 | Cryptographic append-only hash chain must maintain single unbroken chain under concurrent operations (no forks, no duplicate `prev_hash`). | PostgreSQL advisory lock (`_AUDIT_CHAIN_LOCK_KEY = 72839104`) in `packages/common/audit_writer.py`. | **Verified** (Subject to 20/50 concurrent call battery) |
| **NFR-RES-01** | Process Cancellation | SRS §4.4 | Instant termination of running scan job via API/timeout without orphan/zombie processes; temp files purged. | Subprocess killed via `proc.kill()` on `TimeoutError` in `tools/base.py:221`. Unhandled `asyncio.CancelledError` risks orphan processes. | **Verified** (Subject to zombie process verification) |
| **NFR-HOST-01** | Hostile Response Handling | SRS §5.2 | Platform resilience against pathological HTTP responses: 50MB body, slow-drip, infinite streams, redirect loops, huge headers. | Httpx streaming client with timeouts and size bounds; redirect loop detection in `services/execution_engine/tools/http_client.py`. | **Verified** (Subject to bench fixture tests) |
| **NFR-LIM-01** | Resource Bounds | PRD §7, Arch §6 | Strict memory, CPU, PID bounds on containers; Docker log rotation; bounded volume storage per finding. | Inspect `docker-compose.yml` and container runtime inspect configurations. | **Verified** (Subject to inspect audit) |

---

## 2. Granular Specification Inconsistencies & Defect Pre-Analysis

### 2.1 Specification Inconsistency: Circuit Breaker Thresholds
- **PRD Statement ([`docs/01-prd.md:115`](file:///c:/Users/User2/Documents/work/pentesa/docs/01-prd.md#L115) & [`docs/02-srs.md:201`](file:///c:/Users/User2/Documents/work/pentesa/docs/02-srs.md#L201)):**
  Enforce error-rate circuit breakers pausing scans when target error rate exceeds **15% over a 30-second sliding window**.
- **Architecture Statement ([`docs/03-system-architecture.md:400`](file:///c:/Users/User2/Documents/work/pentesa/docs/03-system-architecture.md#L400)):**
  If target error responses (HTTP 500, 502, 503, 504) exceed **20% over a 60-second window**, the execution queue triggers an automatic backoff pause.
- **Code Reality:**
  Neither threshold is implemented in code. Neither `services/execution_engine` nor `services/orchestrator` monitors sliding error windows.

### 2.2 Specification Inconsistency: Distributed Worker vs In-Process Execution
- **Architecture & Deployment Statements ([`docs/03-system-architecture.md:390-399`](file:///c:/Users/User2/Documents/work/pentesa/docs/03-system-architecture.md#L390-L399), [`docs/18-deployment-architecture.md:214`](file:///c:/Users/User2/Documents/work/pentesa/docs/18-deployment-architecture.md#L214)):**
  Workflows run via Celery workers with `acks_late=True` connected to Redis queues, persisting LangGraph checkpoints after every node transition directly to PostgreSQL.
- **Code Reality:**
  1. Celery is absent.
  2. `pentesa-worker` executes `python -m services.execution_engine.worker`, which is an empty heartbeat loop sleeping 2 seconds (`services/execution_engine/worker.py:48-56`).
  3. Workflows are spawned in-process within `pentesa-api` via `asyncio.create_task()` stored in memory (`apps/api/routers/agents.py:36,64`).
  4. Resumption requires an existing status of `PAUSED` or `WAITING_APPROVAL` (`services/orchestrator/supervisor.py:455`). A worker or API container crash terminates all running tasks irrevocably.
  5. `NFR-REL-01` is **Not Implemented**.

### 2.3 Specification Inconsistency: Cursor vs Offset Pagination
- **PRD Statement ([`docs/01-prd.md:241`](file:///c:/Users/User2/Documents/work/pentesa/docs/01-prd.md#L241)):**
  `NFR-SCAL-01`: Support large web applications with up to 10,000 discovered endpoints per project using cursor pagination.
- **Code Reality:**
  `apps/api/routers/discovery.py:110-136` uses standard SQL `LIMIT ... OFFSET ...` pagination. Under 10,000 records, large offsets cause database table scans and degrade performance. Cursor pagination (`id > cursor` or Keyset) is **Not Implemented**.

---

## 3. Test Battery Execution Plan (Sub-Areas a–j)

1. **Sub-Area a (Startup Timing):**
   - Execute 3 consecutive cycles of `docker compose -p pentesa-prod down` (preserving named volumes) followed by `docker compose -p pentesa-prod --env-file .env.production up -d`.
   - Measure elapsed time until `/healthz` and `/readyz` return HTTP 200.
   - Threshold: Mean $< 180\text{ s}$.

2. **Sub-Area b (API Performance & Scale):**
   - Seed throwaway project (`p8test-scale`) with 5,000 and 10,000 endpoints using batch insertion.
   - Measure P50/P95/P99 latency across $\ge 200$ requests each for:
     - Endpoint inventory (`GET /api/v1/projects/{id}/discovery/endpoints`)
     - Findings list (`GET /api/v1/projects/{id}/findings`)
     - Dashboard summary (`GET /api/v1/projects/{id}`)
     - Pagination traversals across pages.
   - Concurrency tiers: 1, 10, and 50 concurrent clients for 60 seconds each.
   - Threshold: P95 $< 200\text{ ms}$ at 5,000 items.

3. **Sub-Area c (Rate Control Accuracy):**
   - Execute tool wrappers (ffuf and nuclei) against `bench-pentesa-app` configured at 5 RPS and 20 RPS.
   - Capture requests per second logged by target access log.
   - Threshold: Measured RPS within $\pm 5\%$ of configured rate.

4. **Sub-Area d (Circuit Breaker Evaluation):**
   - Target HTTP fixture returning controlled 5xx error responses.
   - Observe whether scanner throttles, pauses, or triggers backoff per PRD (15%/30s) or Arch (20%/60s).
   - Expected Result: Recorded as **Not Implemented** / Mismatch documented.

5. **Sub-Area e (Resilience & Fault Isolation):**
   - Worker / API kill mid-workflow: measure restart time and state integrity.
   - Tool failure injection (missing binary `nonexistent_tool`, hard timeout, unhandled exception): verify workflow state transitions to `Error` without crashing the supervisor.
   - Service restart (Postgres, Redis, API) under light load: measure recovery time.
   - SIGTERM graceful shutdown verification.

6. **Sub-Area f (Workflow Concurrency):**
   - Execute 1, 3, and 5 parallel workflows against `pentesa-bench` using Mock LLM provider.
   - Monitor for state clobbering, duplicate work, database connection pool exhaustion.
   - Sample container stats (CPU %, RAM, PIDs) every 2 seconds.

7. **Sub-Area g (Cryptographic Audit Integrity under Concurrency):**
   - 20 and 50 concurrent audit-producing API calls (logins, status changes, finding creations).
   - Run cryptographic verification (`verify_audit_chain`): assert 0 forks, 0 duplicate `prev_hash`, 0 missing blocks.
   - 20 concurrent identical finding POSTs (race condition and deduplication evaluation).

8. **Sub-Area h (Process Cancellation & Cleanup):**
   - Start active scan against bench target; cancel via API endpoint (`POST /projects/{id}/agents/workflow/stop`).
   - Timeout enforcement test.
   - Check container process table for orphan/zombie processes (`ps aux`); check temp directories (`/tmp`).

9. **Sub-Area i (Hostile Target Response Resilience):**
   - Probe hostile HTTP fixtures:
     - 50 MB response body payload.
     - Slow-drip response (1 byte every 2 seconds).
     - Endless streaming chunked response.
     - Infinite HTTP 302 redirect loop.
     - Giant HTTP response header (64 KB header).
   - Assert client enforce timeouts, memory cap, and terminates without hanging.

10. **Sub-Area j (Container Resource Limits & Configuration Review):**
    - Inspect Docker Compose and `docker inspect` for memory limits (`mem_limit`), CPU quotas (`cpus`), PID limits (`pids_limit`), restart policies (`restart: unless-stopped`), and Docker log rotation (`json-file` max-size/max-file).
    - Measure evidence and report volume growth per finding.

---

## 4. Abort & Safety Thresholds
Testing must immediately halt and fail-safe if any of the following conditions occur:
- Sustained P95 latency $> 5.0\text{ s}$ over 30 seconds.
- Cumulative API error rate $> 20\%$.
- Unplanned container restart (crash-loop).
- Host system RAM utilization $> 85\%$.
- Any network request reaching `bench-canary-sensor:9099` (P0 Egress Violation).
