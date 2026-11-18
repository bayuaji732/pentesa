# Pentesa Environments and Operations Guide

This document establishes the official operational standard for Pentesa environments. The platform maintains exactly three supported environments: **Production (`prod`)**, **Benchmark (`bench`)**, and **Development (`dev`)**. There is no separate "demo" environment; live demonstrations are conducted using the production configuration.

---

## 1. Environment Specifications

| Environment | Purpose | Compose Project | Compose File | Configuration | Host Ports | Docker Volumes | Reset Policy |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`prod`** | Live operational pentesting & demonstrations | `pentesa-prod` | `docker-compose.yml` | `.env.production` (`PENTESA_ENV=production`) | `127.0.0.1:8000` (API)<br>`127.0.0.1:3000` (Web UI) | `pentesa-prod_pentesa-pgdata`<br>`pentesa-prod_pentesa-redisdata`<br>`pentesa-prod_pentesa-reports`<br>`pentesa-prod_pentesa-evidence` | **Strictly Persistent**.<br>`down -v` is prohibited. |
| **`bench`** | Security benchmarks & ground-truth validation | `pentesa-bench` | `benchmark/docker-compose.bench.yml` | Inherent bench stack config | None (0 host ports exposed;<br>`internal: true` network) | `pentesa-bench_crapi-db-data`<br>`pentesa-bench_crapi-mongo-data` | **Automated Reset**.<br>Managed via `benchmark/reset_bench.py` with safety guard. |
| **`dev`** | Local feature development & testing | `pentesa-dev` | `docker-compose.yml` (dev overrides) | `.env` (`PENTESA_ENV=development`) | `127.0.0.1:8000` (API)<br>`127.0.0.1:3000` (Web UI) | `pentesa-dev_*` | Developer managed. |

---

## 2. Environment Details & Command Reference

### A. Production Environment (`prod`)
The production environment runs with fail-closed security enforcement, persistent named storage, and production-grade authentication.

- **Compose Project Name**: `pentesa-prod`
- **Compose File**: `docker-compose.yml`
- **Environment File**: `.env.production` (untracked, excluded from version control via `.gitignore`)
- **Key Settings**:
  - `PENTESA_ENV=production`
  - `PENTESA_DEBUG=false`
  - `PENTESA_BOOTSTRAP_ADMIN=true`
  - `PENTESA_BOOTSTRAP_ADMIN_EMAIL=ahmad.aji@siloamhospitals.com`
  - `PENTESA_BOOTSTRAP_ADMIN_PASSWORD` (strong password set by administrator; never committed)
  - `PENTESA_ENCRYPTION_KEY` (AES-256 master encryption key, 32+ bytes)
  - `PENTESA_SECRET_KEY` (HMAC-SHA256 JWT signature key, 32+ bytes)
- **Commands**:
  ```bash
  # Start production stack
  docker compose --env-file .env.production up -d

  # Check service status
  docker compose --env-file .env.production ps

  # View live logs
  docker compose --env-file .env.production logs -f api

  # Stop production stack (preserves volumes)
  docker compose --env-file .env.production down
  ```
- **Bootstrap Idempotency**:
  On initial startup with bootstrap credentials provided, Pentesa seeds the designated administrator account (`ahmad.aji@siloamhospitals.com`). Subsequent restarts detect the existing user in `database/seeds/seed_data.py` and skip creation without altering existing credentials or password hashes.

### B. Benchmark Environment (`bench`)
The benchmark environment hosts intentionally vulnerable evaluation targets (DVWA, OWASP Juice Shop, WebGoat, crAPI, and the Pentesa Bench App) alongside an isolated canary sensor.

- **Compose Project Name**: `pentesa-bench`
- **Compose File**: `benchmark/docker-compose.bench.yml`
- **Network Isolation**:
  The stack runs on `pentesa-bench-net` marked with `internal: true`. Containers cannot reach the public Internet, and no host ports are exposed. All benchmark traffic is executed within the Docker bridge network, eliminating port collisions with `pentesa-prod`.
- **Reset Safety Guard**:
  Benchmark resets are executed exclusively through `benchmark/reset_bench.py`. The reset script inspects the compose configuration and enforces a runtime safety guard:
  ```python
  if project_name != "pentesa-bench":
      raise RuntimeError(f"Safety Violation: Cannot execute bench down -v on project '{project_name}'")
  ```
  This ensures benchmark cleanup cycles never affect `pentesa-prod` databases or volumes.
- **Commands**:
  ```bash
  # Start benchmark targets
  docker compose -f benchmark/docker-compose.bench.yml -p pentesa-bench up -d

  # Reset benchmark targets and state safely
  python benchmark/reset_bench.py
  ```

### C. Development Environment (`dev`)
The development environment is used for rapid local testing and development.
- **Key Settings**:
  - `PENTESA_ENV=development`
  - `PENTESA_SEED_DEMO_DATA=1` (demo seeds are only populated when explicitly set in development)
- **Demo Data Seeding**:
  Default demo data is never seeded unconditionally. In `prod` or `staging`, `PENTESA_SEED_DEMO_DATA` is ignored by `database/seeds/seed_data.py` to prevent unauthorized mock accounts.

---

## 3. How to Run a Live Demonstration

To demonstrate Pentesa:

### 1. Start the Production Stack
Ensure Docker is running and `.env.production` has been populated with local secret keys and administrative passwords (copied from `.env.production.example`):
```bash
docker compose --env-file .env.production up -d
```

### 2. Verify System Health
Verify that all core services report healthy:
- **API Health Endpoint**: [http://127.0.0.1:8000/healthz](http://127.0.0.1:8000/healthz)
- **API Interactive Swagger Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Web UI**: [http://127.0.0.1:3000](http://127.0.0.1:3000)

### 3. Log In to the Platform
- Navigate to [http://127.0.0.1:3000](http://127.0.0.1:3000) (or authenticate via `/api/v1/auth/login`).
- **Login Email**: `ahmad.aji@siloamhospitals.com`
- **Password**: The password defined in your local `.env.production`.
- The system issues a signed JWT with `ADMIN` privileges upon authentication.

### 4. What Is Audited vs. Not Yet Audited
When demonstrating the platform, clearly communicate the audit boundaries:
- **Audited & Verified (Phases 1, 2, and 3A)**:
  - Fail-closed security initialization (rejection of default keys, weak passwords, and insecure database strings).
  - Scope and egress enforcement (strict CIDR/IP validation, loopback restriction, canary hit detection).
  - OWASP WSTG-v4.2 test catalog seeding and mapping.
  - Multi-agent architecture and workflow lifecycle state machines (recovery on restart).
  - Benchmark ground-truth verification (63 verified cases across 5 targets).
- **In Progress / Not Yet Audited (Phases 3B - 10)**:
  - Benchmark scanning runs (Juice Shop, DVWA, WebGoat, crAPI, Pentesa Bench App).
  - Full end-to-end autonomous penetration testing workflows against live production targets (Phase 4).
  - Advanced agent reasoning evaluation and LLM decision scoring (Phases 5-8).
  - Post-audit remediation improvements (Phase 9).
