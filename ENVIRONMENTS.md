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

## 4. Production Environment (`pentesa-prod`) Backup & Recovery Procedure

### 4.1 Pre-Test Backup Archive (Stored Outside Repository)
- **Backup Directory:** `c:\Users\User2\Documents\work\pentesa-prod-backup-p6`
- **Database Dump File:** `c:\Users\User2\Documents\work\pentesa-prod-backup-p6\prod_dump.sql` (PostgreSQL 16 logical dump via `pg_dump`)
- **Volume Replicas:**
  - `c:\Users\User2\Documents\work\pentesa-prod-backup-p6\reports\` (`/app/data/reports`)
  - `c:\Users\User2\Documents\work\pentesa-prod-backup-p6\evidence\` (`/app/data/evidence`)
- **Pre-Test Baseline State (`pentesa-prod`):**
  - `users`: 2 rows (`benchmark-admin@pentesa.lab`, `ahmad.aji@siloamhospitals.com`)
  - `projects`: 28 rows
  - `findings`: 39 rows
  - `finding_evidence`: 39 rows
  - `audit_logs`: 1247 rows
  - `audit_logs` Head Record ID: `af4f6452-16cc-40a5-841b-860503ecdf72`
  - `audit_logs` Head Hash: `b01c7509be114f6a697a79abd058cfa60cb7525a129f0546a9c86dd1c93f7cbc`
  - `audit_logs` Head Prev Hash: `80a385345924541eedda8c6c5995e927673480cf9d1e453b41d584d7823c1efb`

### 4.2 Restoration & Rollback Execution Procedure
In the event of database mutation or upon completion of Phase 6 testing on `pentesa-prod`, execute the following restoration sequence:

1. **Terminate Active Database Connections & Re-create Database:**
   ```bash
   docker exec -i pentesa-db psql -U pentesa_user -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'pentesa' AND pid <> pg_backend_pid();"
   docker exec -i pentesa-db psql -U pentesa_user -d postgres -c "DROP DATABASE IF EXISTS pentesa WITH (FORCE);"
   docker exec -i pentesa-db psql -U pentesa_user -d postgres -c "CREATE DATABASE pentesa OWNER pentesa_user;"
   ```

2. **Restore PostgreSQL Logical Dump:**
   ```powershell
   docker cp c:\Users\User2\Documents\work\pentesa-prod-backup-p6\prod_dump.sql pentesa-db:/tmp/prod_dump.sql
   docker exec pentesa-db psql -U pentesa_user -d pentesa -f /tmp/prod_dump.sql
   docker exec pentesa-db rm /tmp/prod_dump.sql
   ```

3. **Restore Report & Evidence Volume Artifacts:**
   ```powershell
   docker cp c:\Users\User2\Documents\work\pentesa-prod-backup-p6\reports\. pentesa-api:/app/data/reports
   docker cp c:\Users\User2\Documents\work\pentesa-prod-backup-p6\evidence\. pentesa-api:/app/data/evidence
   ```

4. **Restart API & Worker Services:**
   ```powershell
   docker restart pentesa-api pentesa-worker
   ```

5. **Post-Restoration State Verification:**
   - Confirm row counts match baseline (`users` = 2, `projects` = 28, `findings` = 39, `finding_evidence` = 39, `audit_logs` = 1247).
   - Verify audit log chain head hash equals `b01c7509be114f6a697a79abd058cfa60cb7525a129f0546a9c86dd1c93f7cbc`.
   - Confirm real admin authentication succeeds on `http://127.0.0.1:8000/api/v1/auth/login`.
   - Confirm `admin@example.com` returns HTTP 401 Unauthorized.
   - Confirm `pentesa-api` and `pentesa-worker` are completely detached from `pentesa-bench-net` and `pentesa-canary-net`.
