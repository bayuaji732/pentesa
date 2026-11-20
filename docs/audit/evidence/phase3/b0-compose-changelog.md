# Pentesa Benchmark — Phase 3 Gate B0 Compose Changelog

**Document Identifier:** PENTESA-AUDIT-B0-COMPOSE-CHANGELOG-V1.0  
**Phase:** Phase 3 (Pentest Effectiveness Benchmark) — Pre-Flight Gate B0  
**Date:** 2026-11-17  
**Status:** COMPLETE  

---

## 1. Summary of Compose Modifications

This changelog documents all configuration adjustments performed under Gate B0-2 and B0-3 to ensure network isolation, compose namespacing, localhost binding, and environment variable interoperability with `.env.production`. Zero secret values are printed or stored in this record.

| File | Change Category | Specific Action Taken | Rationale / Invariant |
| :--- | :--- | :--- | :--- |
| `docker-compose.yml` | Namespacing | Added top-level `name: pentesa-prod` | Prevents container and network name collisions across environments. |
| `docker-compose.yml` | Port Binding | Bound API port to `127.0.0.1:8000:8000` | Prevents exposing API service to local physical network interfaces. |
| `docker-compose.yml` | Port Binding | Bound Web console port to `127.0.0.1:3000:3000` | Restricts SOC console access strictly to local host. |
| `docker-compose.yml` | Variable Interop | Mapped `PENTESA_SECRET_KEY=${JWT_SECRET:-${PENTESA_SECRET_KEY:?}}` | Ensures compatibility with `.env.production` naming conventions. |
| `docker-compose.yml` | Variable Interop | Mapped `PENTESA_ENCRYPTION_KEY=${PENTESA_ENCRYPTION_KEY:-${PENTESA_MASTER_KEY:?}}` | Ensures compatibility with `.env.production` naming conventions. |
| `docker-compose.test.yml` | Namespacing | Added top-level `name: pentesa-test` | Isolates pytest runner containers and networks from production/bench. |
| `benchmark/docker-compose.bench.yml` | Namespacing | Added top-level `name: pentesa-bench` | Establishes dedicated benchmark target namespace. |
| `docker-compose.phase2.yml` | Namespacing & Retirement | Added `name: pentesa-lab`, torn down without `-v`, then removed via `git rm -f` | Retired historical Phase 2 stack to eliminate hardcoded secrets in working tree; preserved at tag `phase2-final`. |
| `infrastructure/docker-compose.prod.yml` | Defect Logging | Added `name: pentesa-prod`; logged as P3 defect (stale / duplicate) | Marked stale due to hardcoded default passwords rejected by startup validation; duplicate of root file. |
| `docker-compose.bench-attach.yml` (renamed from `docker-compose.override.yml`) | Network Attachment | Converted auto-loading override into explicit overlay attaching `api` and `worker` to external `pentesa-bench-net` | Prevents auto-attachment to bench network on plain `docker compose up`; requires explicit `-f docker-compose.bench-attach.yml` during bench runs. |

---

## 2. Git Diff for Root `docker-compose.yml`

```diff
diff --git a/docker-compose.yml b/docker-compose.yml
index 0bc37c7..6119e7b 100644
--- a/docker-compose.yml
+++ b/docker-compose.yml
@@ -1,3 +1,5 @@
+name: pentesa-prod
+
 services:
   # ---------------------------------------------------------------------------
   # 1. Pentesa Core API Backend
@@ -11,14 +13,14 @@ services:
     env_file:
       - .env.production
     ports:
-      - "8000:8000"
+      - "127.0.0.1:8000:8000"
     environment:
       - PENTESA_ENV=production
       - PENTESA_DEBUG=false
       - PENTESA_DATABASE_URL=postgresql+asyncpg://${POSTGRES_USER:-pentesa_user}:${POSTGRES_PASSWORD:?}@db:5432/${POSTGRES_DB:-pentesa}
       - PENTESA_REDIS_URL=redis://redis:6379/0
-      - PENTESA_SECRET_KEY=${JWT_SECRET:?}
-      - PENTESA_ENCRYPTION_KEY=${PENTESA_ENCRYPTION_KEY:?}
+      - PENTESA_SECRET_KEY=${JWT_SECRET:-${PENTESA_SECRET_KEY:?}}
+      - PENTESA_ENCRYPTION_KEY=${PENTESA_ENCRYPTION_KEY:-${PENTESA_MASTER_KEY:?}}
       - PENTESA_LLM_PROVIDER=${PENTESA_LLM_PROVIDER:-litellm}
       - PENTESA_REPORT_STORAGE_DIR=/app/data/reports
       - PENTESA_EVIDENCE_STORAGE_DIR=/app/data/evidence
@@ -57,8 +59,8 @@ services:
       - PENTESA_DEBUG=false
       - PENTESA_DATABASE_URL=postgresql+asyncpg://${POSTGRES_USER:-pentesa_user}:${POSTGRES_PASSWORD:?}@db:5432/${POSTGRES_DB:-pentesa}
       - PENTESA_REDIS_URL=redis://redis:6379/0
-      - PENTESA_SECRET_KEY=${JWT_SECRET:?}
-      - PENTESA_ENCRYPTION_KEY=${PENTESA_ENCRYPTION_KEY:?}
+      - PENTESA_SECRET_KEY=${JWT_SECRET:-${PENTESA_SECRET_KEY:?}}
+      - PENTESA_ENCRYPTION_KEY=${PENTESA_ENCRYPTION_KEY:-${PENTESA_MASTER_KEY:?}}
       - PENTESA_LLM_PROVIDER=${PENTESA_LLM_PROVIDER:-litellm}
       - PENTESA_REPORT_STORAGE_DIR=/app/data/reports
       - PENTESA_EVIDENCE_STORAGE_DIR=/app/data/evidence
@@ -90,7 +92,7 @@ services:
     container_name: pentesa-web
     restart: unless-stopped
     ports:
-      - "3000:3000"
+      - "127.0.0.1:3000:3000"
     environment:
       - NODE_ENV=production
       - API_INTERNAL_URL=http://api:8000
```


---

## 3. Step 3 Reproducibility Proof: Explicit Benchmark Network Attachment

To ensure production runs remain completely detached from benchmark networks by default while allowing deterministic attachment during benchmark runs without manual `docker network connect`, `docker-compose.override.yml` was renamed to `docker-compose.bench-attach.yml` (invoked explicitly via `-f docker-compose.yml -f docker-compose.bench-attach.yml`):
```yaml
services:
  api:
    networks:
      - pentesa-bench-net
  worker:
    networks:
      - pentesa-bench-net

networks:
  pentesa-bench-net:
    name: pentesa-bench-net
    external: true
```

### Verification & Teardown Proof:
1. **Safety Guard Enforced**: Teardown attempt via `reset_bench.py` against `docker-compose.yml` (`pentesa-prod`) was strictly rejected by the safety guard:
   ```text
   CRITICAL SAFETY VIOLATION: Refusing to run 'down -v'!
   Expected compose project name 'pentesa-bench', but observed 'pentesa-prod'.
   ```
2. **Benchmark Stack Recreated**: The benchmark stack was brought down (`docker compose -f benchmark/docker-compose.bench.yml -p pentesa-bench down`) and recreated (`up -d`).
3. **Automatic DNS & Reachability Confirmed**:
   With no manual network connect commands, `pentesa-api` queried `bench-pentesa-app:8080`:
   ```bash
   docker exec pentesa-api curl -fs http://bench-pentesa-app:8080/healthz
   # Output: {"status":"ok","app":"pentesa-bench","version":"1.0.0"}
   ```

---

## 4. Phase 4 Test Fixture Addition: Workflow State Inconsistency (Step 2)

To satisfy Phase 4 testing requirements for Workflow State Inconsistency (Area 7 / `WSTG-BUSL-06` / `CWE-840`) without modifying the frozen Phase 3 ground truth, the following test endpoints were added to `benchmark/bench_app/main.py`:
- `POST /workflow/order`: Initializes purchase workflow, creates pending order with status `PENDING_PAYMENT`.
- `POST /workflow/pay`: Records payment, transitions order status to `PAID`.
- `POST /workflow/complete` (**Vulnerable Variant**): Completes order and confirms shipment without verifying that order status is `PAID` (permits payment step circumvention).
- `POST /workflow/secure-complete` (**Secure Control Variant**): Strictly validates that order status is `PAID`; returns HTTP 400 Bad Request on workflow sequence circumvention.
- **Deterministic Reset**: `INITIAL_STATE` and `reset_state()` in `benchmark/bench_app/main.py` include `"workflows": {}`, deterministically cleared upon calling `/api/reset`.
- **Image Rebuilt**: `target-pentesa-bench` image rebuilt and container `bench-pentesa-app` restarted cleanly.

