# Pentesa — Platform Deployment & Testing Environments

> **Document Identifier:** PENTESA-ENVIRONMENTS-V2.0  
> **Status:** Authoritative Architecture Reference  
> **Governance:** Strict Environment Isolation Standard (No Cross-Environment State Contamination)  

---

## 1. Overview & Isolation Topology

Pentesa maintains strict separation across three official containerized environments:

```
+----------------------------------------------------------------------------------------------------+
|                                    HOST MACHINE (Windows / Docker)                                 |
+------------------------------------+-----------------------------------+---------------------------+
| 1. DEVELOPMENT (`pentesa-dev`)     | 2. PRODUCTION (`pentesa-prod`)     | 3. LAB TARGETS (`bench`)  |
| - Compose: `docker-compose.yml`    | - Compose: `docker-compose.yml`   | - Compose: `.bench.yml`   |
| - API: 127.0.0.1:8000              | - API: 127.0.0.1:8000             | - crAPI, JuiceShop, DVWA  |
| - Web: 127.0.0.1:3000              | - Web: 127.0.0.1:3000             | - WebGoat, pentesa-bench  |
| - Config: `.env` (debug/local)     | - Config: `.env.production`       | - bench-canary-sensor     |
| - Net: `pentesa-internal`          | - Net: `pentesa-internal`         | - Net: `pentesa-bench-net`|
|                                    |                                   |        `pentesa-canary-net`|
+------------------------------------+-----------------------------------+---------------------------+
```

---

## 2. Granular Environment Specifications

### 2.1 Development Environment (`pentesa-dev`)
- **Configuration:** `.env` (local dev settings, verbose logging, debug instrumentation).
- **Compose Manifest:** [`docker-compose.yml`](file:///c:/Users/User2/Documents/work/pentesa/docker-compose.yml) (plain `docker compose up -d` starts strictly on `pentesa-internal`; benchmark target network attachment is strictly explicit via `-f docker-compose.yml -f docker-compose.bench-attach.yml` for benchmark cycles).
- **Purpose:** Day-to-day feature development, unit testing, and fast-feedback local loops.
- **Port Allocations:**
  - `pentesa-api`: `127.0.0.1:8000`
  - `pentesa-web`: `127.0.0.1:3000`
  - `pentesa-db`: Internal `5432`
  - `pentesa-redis`: Internal `6379`
- **Network Boundaries:** `pentesa-internal` bridge network.

---

### 2.2 Production Engagement Stack (`pentesa-prod`)
- **Configuration:** Untracked `.env.production` (`PENTESA_ENV=production`, `PENTESA_DEBUG=false`, AES-256-GCM vault).
- **Compose Manifest:** [`docker-compose.yml`](file:///c:/Users/User2/Documents/work/pentesa/docker-compose.yml) (plain `docker compose up -d` starts strictly on `pentesa-internal`; benchmark target network attachment is strictly explicit via `-f docker-compose.yml -f docker-compose.bench-attach.yml` for benchmark cycles).
- **Project Name:** `pentesa-prod`
- **Purpose:** Primary platform runtime for user engagements, authorized production assessments, and audited platform security benchmark verification.
- **Port Allocations:**
  - `pentesa-api`: `127.0.0.1:8000`
  - `pentesa-web`: `127.0.0.1:3000`
  - `pentesa-db`: Internal `5432` (unexposed to host loopback)
  - `pentesa-redis`: Internal `6379` (unexposed to host loopback)
- **Volume Isolation:** `pentesa-pgdata`, `pentesa-redisdata`, `pentesa-reports`, `pentesa-evidence`.
- **Network Boundaries:** `pentesa-internal` bridge network.
- **Safety Rule:** Audit testing against `pentesa-prod` is permitted strictly under the Phase 6 Supplement protocol: mandatory pre-test full backup (`pg_dump` + volume replicas), throwaway `p6test-` accounts only, zero direct database modifications outside rolled-back transactions, temporary network attachment with verified detachment, and full restoration verification back to baseline.

---

### 2.3 Vulnerability Benchmark Target Lab (`pentesa-bench`)
- **Compose Manifest:** `benchmark/docker-compose.bench.yml`
- **Project Name:** `benchmark`
- **Purpose:** Running-stack targets for vulnerability detection evaluation.
- **Components:**
  - `bench-pentesa-app`: Custom vulnerable FastAPI fixture with SQLi, SSTI, BOLA, price tampering, coupon races.
  - `bench-juiceshop`: OWASP Juice Shop v15.
  - `bench-crapi-*`: OWASP crAPI microservice suite.
  - `bench-dvwa`: Damn Vulnerable Web Application.
  - `bench-webgoat`: OWASP WebGoat.
  - `bench-canary-sensor`: Internal honeypot / canary sensor (`9099`) used to verify zero out-of-scope egress.
- **Networks:** `pentesa-bench-net`, `pentesa-canary-net`.

---

## 3. Retired Environments

### 3.1 Security Audit Stack (`pentesa-sec`) — RETIRED
- **Status:** **RETIRED & DECOMMISSIONED**
- **Git Retirement Tag:** `p6-sec-env-retired`
- **Manifest Preservation:** [`docker-compose.sec.yml`](file:///c:/Users/User2/Documents/work/pentesa/docker-compose.sec.yml) is preserved in git history and tagged under `p6-sec-env-retired`.
- **Decommissioning Proof:**
  - Spun down via `docker compose -p pentesa-sec --env-file .env.sec -f docker-compose.sec.yml down -v`.
  - All ephemeral volumes (`pentesa-sec-pgdata`, `pentesa-sec-redisdata`, `pentesa-sec-reports`, `pentesa-sec-evidence`) purged.
  - Ephemeral bridge network `pentesa-sec-internal` deleted.
  - Untracked configuration file `.env.sec` securely deleted from host.

---

## 4. Production Environment (`pentesa-prod`) Operational Policy (ENV RULES v2)

In accordance with ENV RULES v2, snapshot restores and pre-test backups have been decommissioned:
- **Test-Only Data:** The target `pentesa-prod` database contains only benchmark and evaluation data; no real client assets exist.
- **Critical Asset Protection:** The sole asset requiring protection is `.env.production`. It must never be deleted, overwritten, or printed.
- **Throwaway Entities:** Any test users and projects must use designated prefixes (`p6test-`, `p7test-`, `p8test-`). Projects must be deleted via API; users must be deactivated via API (due to `P3-API-01`).
- **Network Boundaries:** Temporary bench/canary network attachments (`pentesa-bench-net`, `pentesa-canary-net`) are attached strictly during tests requiring them, detached immediately upon test completion, and verified detached via `docker inspect`.
- **End-of-Step State Verification:**
  - Delete or deactivate all throwaway objects.
  - Verify prod API healthy (`/healthz` 200, `/readyz` 200).
  - Real admin login returns HTTP 200.
  - Default `admin@example.com` returns HTTP 401 Unauthorized.
  - `benchmark-admin` is verified inactive (`is_active = false`).
  - `pentesa-api` and `pentesa-worker` are detached from `pentesa-bench-net` and `pentesa-canary-net`.
  - Live audit chain verified cryptographically.
- **Disaster Recovery:** If `pentesa-prod` breaks beyond repair, the recovery procedure is:
  ```powershell
  docker compose -p pentesa-prod down -v
  docker compose -p pentesa-prod --env-file .env.production up -d
  ```
  The platform bootstraps fresh from `.env.production`. No backups are kept.

---

## 5. Repository Hygiene

To prevent artifact drift, clutter, and unverified files across benchmark evaluation cycles:
- **Scratch Workspace:** All temporary scripts, exploratory code, and intermediate dumps must reside in `.scratch/` (gitignored).
- **Harness Placement:** Test runners, cleanup scripts, and fixtures must be located exclusively in `benchmark/pN/` (e.g. `benchmark/p6/`, `benchmark/p7/`, `benchmark/p8/`).
- **Evidence Placement:** All raw output, forensic captures, matrices, and cost logs must be stored exclusively in `docs/audit/evidence/phaseN/` with forensic headers and recorded in `MANIFEST.sha256`.
- **Step Cleanliness Gate:** At the conclusion of every benchmark step, the working tree must be clean:
  ```powershell
  git status
  git clean -nd  # Dry-run check for untracked files
  ```
- **Planned Final Purge (Post-Phase 10):**
  Upon completion of Phase 10:
  1. Tag release `audit-final`.
  2. Archive all `RETIRED-BUT-REFERENCED` scratch runners and transitional scripts to an archive branch off `main`.
  3. Retain `docs/audit/`, frozen ground truth matrices (`ground_truth_pN.yaml`), deterministic scorers (`score_pN.py`), and `docker-compose.bench.yml` for future regression benchmarking.
  4. Wipe the `pentesa-prod` stack (`docker compose -p pentesa-prod down -v`), re-bootstrap clean from `.env.production`, and tear down all benchmark target resources.

