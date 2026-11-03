# Pentesa — Master Quality Assurance Test Plan

> **Document Identifier:** PENTESA-MTP-V1.0  
> **Status:** Approved for Test Execution  
> **Target Release:** v1.0 GA  
> **Test Execution Framework:** pytest, testcontainers, Playwright, Locust  

---

## 1. Test Objectives & Scope
The objective of this Master Test Plan is to verify that Pentesa satisfies all functional (SRS) and non-functional requirements without introducing regression, out-of-scope packet transmission, or unhandled exceptions.

### Critical Quality Gates:
- **Gate 1 (Scope Defense):** 100% of out-of-scope URLs and private IPs are blocked at both Layer 1 and Layer 2.
- **Gate 2 (Burden of Proof):** 0 confirmed vulnerabilities without working `curl` reproduction commands and SHA-256 evidence hashes.
- **Gate 3 (WSTG Integrity):** 100% of applicable tests mathematically accounted for in coverage calculation.

---

## 2. Test Suites & Execution Strategy

| Test Suite | Framework | Execution Scope | CI Phase |
|---|---|---|---|
| **Unit Test Suite** | `pytest` + `pytest-asyncio` | Scope algorithms, WSTG state machine, tool parsers, Pydantic schemas. | Pre-Commit / PR |
| **Database Integration** | `testcontainers-python` | PostgreSQL 16 schema, Alembic migrations, cascade deletes, JSONB indexes. | Nightly / PR |
| **API Integration** | `httpx.AsyncClient` | REST endpoints, JWT auth, RBAC enforcement, WebSocket event streaming. | Nightly / PR |
| **Proxy Socket Tests** | Python socket harness | DNS pinning, CIDR filtering, redirect interception, anti-rebinding. | Nightly / PR |
| **UI Automation** | `Playwright` | React frontend workflows, wizards, findings diff modal, report downloads. | Pre-Release |
| **Load & Stress Tests** | `Locust` | 10,000 endpoint inventory query performance, 50 concurrent WebSocket users. | Pre-Release |
| **E2E Vulnerable App** | Docker Compose | Autonomous scan against OWASP Juice Shop and DVWA. | Pre-Release |

---

## 3. Test Environment Setup
- Docker Engine 24.0+ and Docker Compose v2.20+.
- Target test applications deployed in isolated local Docker network (`juice-shop:3000`, `dvwa:80`).
- Local Ollama instance running `llama3.1:8b-instruct-q8_0`.

---

## 4. Test Defect Severity Classification

- **Blocker (Severity 1):** Out-of-scope request transmitted; failure to drop connection to unapproved IP; crash of scope proxy.
- **Critical (Severity 2):** False positive confirmed vulnerability; crash of Celery worker without recovery; failure to redact sensitive credentials.
- **Major (Severity 3):** WSTG coverage calculation discrepancy; tool subprocess timeout not trapped cleanly.
- **Minor (Severity 4):** Minor UI styling defect; missing tooltip in coverage heatmap.
