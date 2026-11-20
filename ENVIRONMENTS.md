# Pentesa — Platform Deployment & Testing Environments

> **Document Identifier:** PENTESA-ENVIRONMENTS-V1.0  
> **Status:** Living Architecture Reference  
> **Governance:** Strict Environment Isolation Standard (No Cross-Environment State Contamination)  

---

## 1. Overview & Isolation Topology

To guarantee forensic integrity and prevent destructive test operations against active engagements or baseline targets, Pentesa enforces strict separation across three containerized compose projects and one in-process harness:

```
+----------------------------------------------------------------------------------------------------+
|                                    HOST MACHINE (Windows / Docker)                                 |
+------------------------------------+-----------------------------------+---------------------------+
| 1. CORE STACK (`pentesa-prod`)      | 2. AUDIT STACK (`pentesa-sec`)    | 3. LAB TARGETS (`bench`)  |
| - Compose: `docker-compose.yml`    | - Compose: `docker-compose.sec.yml`| - Compose: `.bench.yml`   |
| - API: 127.0.0.1:8000              | - API: 127.0.0.1:8001             | - crAPI, JuiceShop, DVWA  |
| - Web: 127.0.0.1:3000              | - DB:  127.0.0.1:5433             | - WebGoat, pentesa-bench  |
| - DB:  Internal 5432               | - Redis: 127.0.0.1:6381           | - bench-canary-sensor     |
| - Volumes: `pentesa-pgdata`, etc.  | - Volumes: `pentesa-sec-pgdata`   | - Net: `pentesa-bench-net`|
| - Net: `pentesa-internal`          | - Net: `pentesa-sec-internal`     |        `pentesa-canary-net`|
+------------------------------------+-----------------------------------+---------------------------+
```

---

## 2. Granular Environment Specifications

### 2.1 Production Engagement Stack (`pentesa-prod`)
- **Compose Manifest:** [`docker-compose.yml`](file:///c:/Users/User2/Documents/work/pentesa/docker-compose.yml)
- **Project Name:** `pentesa-prod`
- **Purpose:** Primary platform runtime for user engagements and authorized production assessments.
- **Port Allocations:**
  - `pentesa-api`: `127.0.0.1:8000`
  - `pentesa-web`: `127.0.0.1:3000`
  - `pentesa-db`: Internal `5432` (unexposed to host loopback)
  - `pentesa-redis`: Internal `6379` (unexposed to host loopback)
- **Volume Isolation:** `pentesa-pgdata`, `pentesa-redisdata`, `pentesa-reports`, `pentesa-evidence`.
- **Network Boundaries:** `pentesa-internal` bridge network.
- **Secrets & Configuration:** Sourced from untracked `.env.production`.
- **Access Rule:** **Audit scripts and Phase 6 security attacks must NEVER target or touch `pentesa-prod` containers or volumes.**

---

### 2.2 Security Audit & Attack Surface Stack (`pentesa-sec`)
- **Compose Manifest:** [`docker-compose.sec.yml`](file:///c:/Users/User2/Documents/work/pentesa/docker-compose.sec.yml)
- **Project Name:** `pentesa-sec`
- **Purpose:** Dedicated, ephemeral, fully isolated testing target for Phase 6 Platform Security Assessment (evaluating authentication bypass, RBAC escalation, IDOR, SSRF, command injection, and data boundary enforcement).
- **Environment Semantics:** `PENTESA_ENV=production`, `PENTESA_DEBUG=false`, `PENTESA_BOOTSTRAP_ADMIN=false`.
- **Port Allocations (Guaranteed Non-Conflicting):**
  - `pentesa-sec-api`: `127.0.0.1:8001`
  - `pentesa-sec-db`: `127.0.0.1:5433` (accessible for out-of-band tenant seeding and direct ledger inspection)
  - `pentesa-sec-redis`: `127.0.0.1:6381`
- **Dedicated Volumes (Fresh & Isolated):**
  - `pentesa-sec-pgdata` (PostgreSQL 16 relational store for security tenant data)
  - `pentesa-sec-redisdata` (Redis 7 task queue cache)
  - `pentesa-sec-reports` (Report artifact store)
  - `pentesa-sec-evidence` (Evidence artifact store)
- **Network Bridges:**
  - `pentesa-sec-internal` (isolated container-to-container communication)
  - `pentesa-bench-net` (access to target lab instances)
  - `pentesa-canary-net` (access to canary sensor for strict SSRF/egress verification)
- **Tenant Seeding:** Sourced via out-of-band script [`benchmark/p6/seed_sec_environment.py`](file:///c:/Users/User2/Documents/work/pentesa/benchmark/p6/seed_sec_environment.py) reading untracked `.env.sec`. Zero credentials printed to logs or committed to git.

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

### 2.4 In-Process Deterministic Harness
- **Framework:** `AsyncSessionLocal` on SQLite (`aiosqlite`), `MockHttpTransport` (in-memory).
- **Purpose:** Sub-millisecond deterministic architecture, schema, allowlist, and AST checks (Phase 5).
- **Scope:** Zero network traffic, zero LLM expenditure, ephemeral in-memory state.
