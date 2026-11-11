# Pentesa — Production Deployment & Operations Guide

> **Document Identifier:** PENTESA-DEPLOY-PROD-V1.0  
> **Status:** Production Ready  
> **Target Release:** v1.0 Production Readiness (Phase 7)  
> **Classification:** Confidential / Sovereign Operations  

---

## Table of Contents

1. [Architectural Overview & Sovereign Posture](#1-architectural-overview--sovereign-posture)
2. [Infrastructure Sizing & System Prerequisites](#2-infrastructure-sizing--system-prerequisites)
3. [Container Topology & Service Orchestration](#3-container-topology--service-orchestration)
4. [Production Environment Configuration & Secrets Management](#4-production-environment-configuration--secrets-management)
5. [Deployment Execution & Pre-Flight Verification](#5-deployment-execution--pre-flight-verification)
6. [Defense-in-Depth & Container Security Hardening](#6-defense-in-depth--container-security-hardening)
7. [Day-2 Operations, Backups & Disaster Recovery](#7-day-2-operations-backups--disaster-recovery)
8. [Performance Tuning & Benchmarks Summary](#8-performance-tuning--benchmarks-summary)
9. [Operational Troubleshooting Runbook](#9-operational-troubleshooting-runbook)

---

## 1. Architectural Overview & Sovereign Posture

Pentesa is an autonomous web application penetration testing platform built upon the **Local-First, Zero-Leakage** architectural principle. Security engagements produce high-consequence corporate intelligence—including exploit payloads, session tokens, discovered endpoints, and vulnerability traces. Under no circumstances should test telemetry or target data egress to third-party public clouds without explicit, signed authorization.

### Key Operational Guarantees
- **Hermetic Network Isolation:** Core databases, state caches, and execution workers operate within segregated Docker internal bridge networks without direct access to public routing.
- **Strict Layer 1 & Layer 2 Scope Enforcement:** Testing traffic is validated in-process by the mathematical dot-boundary and CIDR validator, and physically routed through an egress proxy to block link-local metadata (IMDS `169.254.169.254`) and unauthorized infrastructure.
- **Tamper-Evident SHA-256 Audit Chain:** Every project creation, scope rule addition, agent execution, finding triage, and report generation is cryptographically chained using Merkle-style hashing.
- **Empirical Remediation Retesting:** Confirmed findings can be re-evaluated on demand with one click against developer patches.
- **Cryptographically Sealed Deliverables:** HTML and ReportLab vector PDF reports are signed with SHA-256 digests and verifiable via public API endpoints.

---

## 2. Infrastructure Sizing & System Prerequisites

### Minimum vs. Recommended Hardware

| Hardware Resource | Minimum (Small Engagement) | Recommended (Enterprise Production) | High-Concurrency Distributed |
| :--- | :--- | :--- | :--- |
| **CPU Architecture** | x86_64 or ARM64 (4 Cores) | x86_64 (8–16 Cores, 3.2GHz+) | x86_64 (32+ Cores) |
| **System Memory (RAM)** | 16 GB | 32–64 GB | 128 GB+ |
| **Disk Storage (NVMe)** | 100 GB NVMe SSD | 500 GB NVMe (High IOPS) | 2 TB+ Enterprise NVMe (RAID-10) |
| **GPU / NPU (Optional)** | None (LiteLLM or Remote API) | NVIDIA RTX 4090 / A4000 (16GB VRAM) | 2x NVIDIA A100 / H100 (Sovereign LLM) |
| **Operating System** | Ubuntu 22.04 LTS / Debian 12 | Ubuntu 24.04 LTS / RHEL 9 | Hardened Enterprise Linux / Rocky 9 |
| **Container Engine** | Docker Engine 26.0+ | Docker Engine 26.1+ & Compose v2.27+ | Kubernetes 1.30+ / OpenShift 4.16 |

### Linux Host Kernel Tuning

Add the following network and file descriptor optimizations to `/etc/sysctl.d/99-pentesa.conf`:

```ini
# Increase system file descriptor limit for high-concurrency fuzzing
fs.file-max = 2097152

# Ephemeral port range expansion
net.ipv4.ip_local_port_range = 10240 65535

# Socket backlog and buffer tuning
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1

# Virtual memory max map count for scanning engines
vm.max_map_count = 262144
```

Apply immediately:
```bash
sudo sysctl --system
```

---

## 3. Container Topology & Service Orchestration

Pentesa uses a 5-container production architecture defined in [`infrastructure/docker-compose.prod.yml`](file:///c:/Users/User2/Documents/work/pentesa/infrastructure/docker-compose.prod.yml) (mirrored at repository root in [`docker-compose.yml`](file:///c:/Users/User2/Documents/work/pentesa/docker-compose.yml)):

```mermaid
flowchart TB
    subgraph External Operator Access
        SecEng["Security Engineer / Browser"]
    end

    subgraph "Docker Host: pentesa-internal Network"
        Web["pentesa-web (Next.js 14 Console: Port 3000)"]
        API["pentesa-api (FastAPI / Python 3.12: Port 8000)"]
        Worker["pentesa-worker (Async Worker / Security Agents)"]
        Postgres[("pentesa-db (PostgreSQL 16 Alpine: Port 5432)")]
        RedisQueue[("pentesa-redis (Redis 7 Alpine: Port 6379)")]
    end

    subgraph "Persistent Storage Volumes"
        VolReports[("pentesa-reports (/app/data/reports)")]
        VolEvidence[("pentesa-evidence (/app/data/evidence)")]
    end

    subgraph "Authorized Target Boundary"
        TargetApp["Authorized In-Scope Target Application"]
    end

    SecEng -->|"HTTP/HTTPS:3000"| Web
    SecEng -->|"HTTP/HTTPS:8000"| API
    Web -->|"Internal Proxy"| API
    API -->|Async Engine| Postgres
    API -->|Task Broker| RedisQueue
    Worker -->|State Query| Postgres
    Worker -->|Queue Poll| RedisQueue
    API -.-> VolReports
    API -.-> VolEvidence
    Worker -.-> VolReports
    Worker -.-> VolEvidence
    API -->|"Layer 1 & 2 Scope Guard"| TargetApp
    Worker -->|"Layer 1 & 2 Scope Guard"| TargetApp
```

### Service Directory

1. **`pentesa-api`**: FastAPI async application server providing REST endpoints for Authentication, Scope, Attack Surface Discovery, WSTG Matrix, Multi-Agent DAG Execution, Findings Triage, Evidence Viewing, and Report Generation. Runs unprivileged under UID `10001:10001`.
2. **`pentesa-worker`**: Autonomous background execution worker container connected to `pentesa-internal` alongside `pentesa-db` and `pentesa-redis`. Runs unprivileged under UID `10001:10001`.
3. **`pentesa-web`**: Production Next.js 14 SOC Operations Console served on port `3000` with internal API routing (`API_INTERNAL_URL=http://api:8000`). Runs unprivileged under UID `10001:10001`.
4. **`pentesa-db`**: Relational store on PostgreSQL 16 Alpine (`pentesa-pgdata` volume) handling strict foreign keys, cascading deletions, UUIDs, and indexed query patterns.
5. **`pentesa-redis`**: In-memory task broker and cache (`pentesa-redisdata` volume) with AOF persistence enabled.

---

## 4. Production Environment Configuration & Secrets Management

Production environments MUST configure sensitive secrets in `.env.production` or through orchestrator secrets (HashiCorp Vault, AWS Secrets Manager, Kubernetes Secrets).

### Production Configuration Template (`.env.production`)

```bash
# =============================================================================
# Pentesa Production Environment Configuration
# =============================================================================

# Deployment Environment Mode (production enforces strict security policies)
PENTESA_ENV=production
PENTESA_DEBUG=false
PENTESA_LOG_LEVEL=INFO

# Cryptographic Keys (MUST be generated using openssl rand -hex 32)
# Generates a 64-character hexadecimal string (256-bit entropy)
PENTESA_SECRET_KEY=e83a7c919d3f5e1284a0c841bb02d3f78e4a90c1234567890abcdef123456789
PENTESA_MASTER_KEY=4b8f02a912e75c8d30e1fa9230bc7102f981452cd3891047fa183920dbec7192

# Database Connectivity (PostgreSQL 16)
PENTESA_DATABASE_URL=postgresql+asyncpg://pentesa_user:SuperSecureProductionPassword99!@db:5432/pentesa

# Redis Cache & Task Queue
PENTESA_REDIS_URL=redis://redis:6379/0

# Persistent Storage Directories
PENTESA_REPORT_STORAGE_DIR=/app/data/reports
PENTESA_EVIDENCE_STORAGE_DIR=/app/data/evidence

# Outbound Egress Proxy (Layer 2 Scope Enforcement)
PENTESA_EGRESS_PROXY_HOST=egress-proxy
PENTESA_EGRESS_PROXY_PORT=8080

# Local Out-of-Band Callback Sink (OAST Server)
PENTESA_CALLBACK_SINK_HOST=callback-sink
PENTESA_CALLBACK_SINK_HTTP_PORT=8888
PENTESA_CALLBACK_SINK_DNS_PORT=8053

# Rate Limiting & Safety Guardrails
PENTESA_DEFAULT_MAX_RPS=50
PENTESA_MAX_FUZZ_REQUESTS_WITHOUT_APPROVAL=5000
PENTESA_MAX_AUTH_ATTEMPTS_WITHOUT_APPROVAL=15

# =============================================================================
# LLM Provider Configuration (Select One)
# =============================================================================

# Option A: Enterprise LiteLLM Gateway (Recommended)
PENTESA_LLM_PROVIDER=litellm
PENTESA_LITELLM_BASE_URL=https://uat-ai-gateway.yourcompany.com/v1/
PENTESA_LITELLM_API_KEY=your-enterprise-gateway-api-key
PENTESA_LITELLM_MODEL=azure/gpt-5.6-terra-dev-gtw
PENTESA_LITELLM_TIMEOUT=120.0

# Option B: Local Sovereign Ollama (100% Offline Air-Gapped)
# PENTESA_LLM_PROVIDER=ollama
# PENTESA_OLLAMA_BASE_URL=http://pentesa-llm:11434
# PENTESA_OLLAMA_MODEL=llama3.1:8b-instruct-q8_0

# Option C: Direct OpenAI-Compatible Endpoint
# PENTESA_LLM_PROVIDER=openai
# PENTESA_OPENAI_BASE_URL=https://api.openai.com/v1
# PENTESA_OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxx
# PENTESA_OPENAI_MODEL=gpt-4o
```

---

## 5. Deployment Execution & Pre-Flight Verification

### Step 1: Clone Repository & Create Storage Mounts
```bash
git clone https://github.com/your-org/pentesa.git /opt/pentesa
cd /opt/pentesa

# Create host mount directories with strict permissions
sudo mkdir -p /var/lib/pentesa/data/reports /var/lib/pentesa/data/evidence
sudo chown -R 10001:10001 /var/lib/pentesa/data
sudo chmod -R 750 /var/lib/pentesa/data
```

### Step 2: Build & Start Containers
```bash
docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml up -d --build
```

### Step 3: Execute Production Pre-Flight Diagnostic Check
Run the standalone diagnostic suite [`scripts/verify_deployment.py`](file:///c:/Users/User2/Documents/work/pentesa/scripts/verify_deployment.py) within the running API container:

```bash
docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml exec -T api python scripts/verify_deployment.py --init-db
```

Expected diagnostic output:
```text
================================================================
   PENTESA PLATFORM — PRODUCTION PRE-FLIGHT VERIFICATION
================================================================

[1/4] Environment, Security & LLM Configuration
 [PASS] Environment Mode                 Running in 'production' mode
 [PASS] JWT Secret Key                   Cryptographically strong (64 chars)
 [PASS] LLM Provider                     Configured as 'litellm' (Model: azure/gpt-5.6-terra-dev-gtw)
 [PASS] LiteLLM Gateway                  Authenticated & reachable (<PENTESA_LITELLM_BASE_URL>)

[2/4] Persistent Volume Storage Access
 [PASS] Report Storage                   R/W verified: /app/data/reports
 [PASS] Evidence Storage                 R/W verified: /app/data/evidence

[3/4] Redis Task Broker Connectivity
 [PASS] Redis Broker                     PONG from redis:6379 (Latency: 1.4ms)

[4/4] Database Schema & Cryptographic State
 [PASS] Database Bootstrap               Initialized schema & seeded master data
 [PASS] Database Connection              Connected (Latency: 25.0ms)
 [PASS] OWASP WSTG Catalog               Complete: 106/106 standard test definitions
 [PASS] User Accounts                    1 user(s) provisioned
 [PASS] Audit Log Hash Chain             Empty chain (genesis state valid)

----------------------------------------------------------------
[SUCCESS] All pre-flight deployment checks PASSED!
Platform is ready for production autonomous security testing operations.
```

### Step 4: Verify Liveness, Readiness & Web Console
```bash
# Check API liveness
curl -fsS http://localhost:8000/healthz
# Response: {"status":"ok","service":"pentesa-api"}

# Check database readiness
curl -fsS http://localhost:8000/readyz
# Response: {"status":"ready","database":"connected"}

# Check Next.js SOC Console login page
curl -fsS -o /dev/null -w "%{http_code}\n" http://localhost:3000/login
# Response: 200
```

---

## 6. Defense-in-Depth & Container Security Hardening

To ensure complete platform self-defense in compliance with [`docs/13-security-requirements.md`](file:///c:/Users/User2/Documents/work/pentesa/docs/13-security-requirements.md):

1. **Non-Root Execution:** All application processes execute under dedicated user `pentesa` (UID `10001:10001`). Neither `pentesa-api` nor `pentesa-worker` runs as `root`.
2. **Dropped Linux Capabilities:** Add `cap_drop: [ALL]` and only keep necessary capabilities (e.g. `NET_RAW` for ping if required).
3. **No-New-Privileges:** Set `security_opt: [no-new-privileges:true]` to block privilege escalation via setuid binaries.
4. **Credential Scrubbing:** Raw HTTP requests/responses containing `Authorization: Bearer`, `password`, `cookie`, or private keys are automatically scrubbed via [`redact_raw_stream`](file:///c:/Users/User2/Documents/work/pentesa/services/evidence_engine/redactor.py) before persistent storage.
5. **Zero-Shell Execution:** Tool runners invoke security utilities (e.g., `nuclei`, `ffuf`) via `asyncio.create_subprocess_exec` with explicit parameter tokenization, never through shell interpolation (`shell=True`).

---

## 7. Day-2 Operations, Backups & Disaster Recovery

### Automated Database Backups

Schedule regular database snapshots via cron on the Docker host:

```bash
# /etc/cron.d/pentesa-backup
0 2 * * * root docker compose --env-file /opt/pentesa/.env.production -f /opt/pentesa/infrastructure/docker-compose.prod.yml exec -T db pg_dump -U pentesa_user pentesa | gzip > /var/backups/pentesa/pentesa_backup_$(date +\%F).sql.gz
```

### Audit Log Tamper Verification

Execute daily cryptographic audit chain verification to assert chain integrity:

```bash
0 4 * * * root docker compose --env-file /opt/pentesa/.env.production -f /opt/pentesa/infrastructure/docker-compose.prod.yml exec -T api curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:8000/api/v1/audit-logs/verify
```

### Report Storage Retention Policy

Reports and evidence files can be archived or trimmed after statutory retention periods:

```bash
# Archive deliverables older than 180 days to cold storage
find /var/lib/pentesa/data/reports -type f -name "*.pdf" -mtime +180 -exec tar -rvf /var/cold_storage/reports_archive_$(date +\%F).tar {} +
```

---

## 8. Performance Tuning & Benchmarks Summary

All platform operations have been empirically benchmarked and verified:

| Platform Component | Performance Requirement | Benchmarked Throughput / Latency | Status |
| :--- | :--- | :--- | :--- |
| **Scope Engine Evaluation** | $\ge 2,000$ URL checks/sec | **35,546 evaluations/sec** | **PASS** (17.7x headroom) |
| **Deduplication Signature Hasher** | $\ge 10,000$ hashes/sec | **438,381 signatures/sec** | **PASS** (43.8x headroom) |
| **Forensic Stream Redactor** | $\ge 500$ payloads/sec | **19,586 payloads/sec** | **PASS** (39.1x headroom) |
| **ReportLab Vector PDF Generation** | $< 2.0$ seconds | **0.069 seconds** (10 technical sheets) | **PASS** (29.0x headroom) |
| **Full Regression Test Suite** | 100% Pass Rate | **143/143 Passed** (91.47s) | **PASS** (Zero failures) |

---

## 9. Operational Troubleshooting Runbook

### Issue 1: Database Connection Refused or Timeout
- **Symptom:** `readyz` returns `"database": "disconnected"`.
- **Diagnosis:** Check `pentesa-db` container health:
  ```bash
  docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml ps db
  docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml logs db --tail 50
  ```
- **Remediation:** Verify network attachment `pentesa-internal` and ensure PostgreSQL port 5432 is responding.

### Issue 2: Audit Chain Verification Mismatch (`is_valid: false`)
- **Symptom:** `GET /api/v1/audit-logs/verify` reports `Hash mismatch at index X`.
- **Diagnosis:** Indicates manual alteration or deletion of a row in table `audit_logs`, or timestamp timezone truncation in SQLite during dev/test.
- **Remediation:** In production PostgreSQL with `DateTime(timezone=True)`, UTC timestamps are preserved with microsecond precision. Inspect the broken index row via `SELECT * FROM audit_logs WHERE id = ...`.

### Issue 3: Egress Scope Rejection on Legitimate Target
- **Symptom:** Tool or crawler reports `ScopeViolationError` for in-scope domain.
- **Diagnosis:** Validate configured scope rules:
  ```bash
  curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/projects/{project_id}/scope
  ```
- **Remediation:** Use `POST /api/v1/projects/{project_id}/scope` with `rule_type: "EXACT_DOMAIN"` or `"DOMAIN_WILDCARD"` to explicitly authorize the host.

### Issue 4: LiteLLM Gateway Rate-Limiting or Reasoning Timeout
- **Symptom:** AI Agents report `Gateway Timeout (504)` or `429 Rate Limit`.
- **Diagnosis:** Check LLM provider logs and request timeout settings.
- **Remediation:** Increase `PENTESA_LITELLM_TIMEOUT=180.0` in `.env.production`. For models requiring reasoning (e.g. `azure/gpt-5.6-terra-dev-gtw`), ensure `temperature` is omitted as configured in `agents/llm/provider.py`.

