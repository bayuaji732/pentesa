# Pentesa — AI-Powered Autonomous Web Penetration Testing Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Next.js 14](https://img.shields.io/badge/next.js-14.2-black.svg)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/tests-143%2F143%20passed-brightgreen.svg)]()
[![License: Proprietary](https://img.shields.io/badge/license-Proprietary-red.svg)]()

Pentesa is an enterprise-grade, multi-agent autonomous penetration testing platform designed for Security Operations Center (SOC) engineers, red teams, and AppSec auditors. It features dual-layer scope enforcement with DNS anti-rebinding protection, OWASP WSTG 106-item testing coverage, automated exploit reproduction recipes, cryptographic evidence hashing (SHA-256 Merkle chain), and formal PTES report generation.

---

## Architecture & Monorepo Mapping

```
pentesa/
├── apps/
│   ├── api/                      # FastAPI core REST API engine (Port 8000)
│   │   ├── routers/              # Auth, Projects, Scope, Discovery, WSTG, Agents, Findings, Reports, Audit
│   │   └── main.py               # Application entrypoint & middleware lifecycle
│   └── web/                      # Next.js 14 SOC Dark Console (Port 3000)
│       ├── src/app/              # Next.js App Router (Dashboard, Scope, Discovery, WSTG, Agents, Findings, Reports, Audit)
│       ├── src/components/       # TopNav, Sidebar, Forensic HUD widgets
│       └── src/lib/              # Centralized typed API client & ProjectContext state
├── services/
│   ├── scope_engine/             # Dual-layer boundary enforcement & RFC1918/DNS rebinding defense
│   ├── discovery_engine/         # Attack surface enumeration, crawling, & parameter inventory
│   ├── execution_engine/         # Deterministic subprocess sandboxing & rate limiting
│   ├── orchestrator/             # Multi-agent LangGraph workflow orchestrator
│   ├── evidence_engine/          # Forensic evidence collector & SHA-256 artifact hashing
│   └── reporting_engine/         # PTES compliant WeasyPrint PDF/HTML generator
├── database/
│   ├── models/                   # SQLAlchemy 2.0 async models
│   ├── migrations/               # Alembic database schema migrations
│   └── seeds/                    # WSTG master test catalog & seed scripts
├── packages/
│   ├── common/                   # Security primitives, AES-256-GCM, config, & Merkle audit logging
│   ├── schemas/                  # Domain Pydantic V2 models
│   └── tool_sdk/                 # CLI subprocess execution SDK
├── infrastructure/               # Docker Compose & production deployment configs
└── tests/                        # 143 automated unit, integration, and security tests
```

---

## Quick Start (Local Development)

### 1. Prerequisites
- **Python**: 3.11+
- **Node.js**: v18+ (Node v24 supported) & npm
- **SQLite / PostgreSQL**: Local SQLite (`./pentesa.db`) or PostgreSQL 16+

### 2. Backend API Setup
```bash
# 1. Activate Python virtual environment
.venv\Scripts\activate   # Windows
# source .venv/bin/activate # Linux/macOS

# 2. Run database migrations and seed OWASP WSTG catalog
python -m database.seeds.seed_data

# 3. Start FastAPI server (Port 8000)
uvicorn apps.api.main:app --host 127.0.0.1 --port 8000 --reload
```
- Health Check: `http://127.0.0.1:8000/healthz`
- Swagger Documentation: `http://127.0.0.1:8000/docs`

### 3. Frontend Web Console Setup (`apps/web`)
```bash
# 1. Install dependencies
npm install --prefix apps/web

# 2. Start Next.js development server (Port 3000)
npm run dev --prefix apps/web
```
- Web Operations Console: `http://localhost:3000`
- Default Admin Credentials:
  - **Email:** `admin@example.com`
  - **Password:** `Admin123!Secure`

---

## Frontend Web Operations Dashboard (`apps/web`)

The frontend console is built with Next.js 14 App Router, React 18, Tailwind CSS, and Lucide Icons following the high-density forensic dark aesthetic (`#090d16` canvas):

| View | Route | Description |
|---|---|---|
| **Executive Dashboard** | `/` | Real-time severity metrics (Critical/High/Med/Low), WSTG test coverage gauge, multi-agent status, and recent confirmed vulnerabilities. |
| **Scope & Boundaries** | `/scope` | Strict Layer 1 (FQDN regex) & Layer 2 (CIDR/DNS anti-rebinding) rules manager with live real-time URL boundary tester. |
| **Attack Surface** | `/discovery` | Discovered subdomains, crawled URL endpoint inventory, and fingerprinted technology stack badges. |
| **OWASP WSTG Matrix** | `/wstg` | Complete 106-test catalog filterable by category (INFO, CONF, IDNT, AUTH, ATHZ, SESS, INPV, CRYP, BUSL, CLNT) with recalculation trigger. |
| **Multi-Agent Swarm** | `/agents` | Live directed acyclic graph (DAG) pipeline monitoring 7 specialized testing agents, token usage counters, and thought trace feed. |
| **Findings & Retest** | `/findings` | Vulnerability triage with CVSS v3.1 calculator, forensic HTTP request/response viewer, and **one-click empirical patch retest**. |
| **PTES Reports** | `/reports` | One-click PDF & HTML penetration testing report compiler with cryptographic SHA-256 seal verification. |
| **Audit Hash Chain** | `/audit-logs` | Immutable Merkle hash chain viewer (`prev_hash` → `hash`) with one-click cryptographic chain integrity verification and JSON export. |
| **Engagements** | `/projects` | Multi-tenant project catalog, Rules of Engagement (RoE) authorization windows, and target creation wizard. |

---

## Production Deployment (Docker Compose)

For production environments, Pentesa is deployed via a 5-container Docker Compose stack (`pentesa-api`, `pentesa-worker`, `pentesa-web`, PostgreSQL 16 `pentesa-db`, and Redis 7 `pentesa-redis`):

```bash
# 1. Build and launch all production containers
docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml up -d --build

# 2. Initialize PostgreSQL schema/seed data and run pre-flight verification (including LiteLLM check)
docker compose --env-file .env.production -f infrastructure/docker-compose.prod.yml exec -T api python scripts/verify_deployment.py --init-db
```
See [`docs/22-production-deployment-guide.md`](docs/22-production-deployment-guide.md) for full operational hardening and [`docs/23-end-to-end-testing-tutorial.md`](docs/23-end-to-end-testing-tutorial.md) for step-by-step local dev, Docker Option B (`http://testphp.vulnweb.com`), and Docker Option C (`juice-shop` / `dvwa`) walkthroughs.

---

## Test Suite Execution

Run the complete 143-test automated test suite:
```bash
pytest -v
```
All 143 tests (Unit, Scope Engine, Crawler Discovery, Subprocess Isolation, LangGraph Multi-Agent Workflows, ReportLab PDF Reporting, and Cryptographic Merkle Chains) execute in ~91s.
