# ADR-006: Documentation Synchronization & Architecture Drift Policy

> **Document Identifier:** `ADR-006-DOCS-SYNC-POLICY`  
> **Status:** PROPOSED  
> **Date:** 2026-11-24  
> **Auditors / Authors:** Principal Systems Architect & Documentation Standards Team  
> **Reference Baseline:** `docs/audit/10-improvement-roadmap.md`

---

## 1. Context & Problem Statement

Throughout Phases 1 to 8, the audit uncovered systematic discrepancies between theoretical documentation written prior to implementation and the actual running code:
- Docs claimed LangGraph DAG $\to$ Implemented as custom DAG in `supervisor.py`.
- Docs claimed Celery worker $\to$ Implemented as in-memory `_ACTIVE_WORKFLOW_TASKS`.
- Docs claimed 15-minute JWT lifetime with refresh $\to$ Implemented as 60-minute access token without refresh tokens.
- PRD claimed 15%/30s circuit breaker $\to$ Architecture claimed 20%/60s circuit breaker.
- Docs claimed 18 tools $\to$ Implemented 5 tools.
- Docs claimed bcrypt cost 14 $\to$ Implemented bcrypt cost 12.

A clear policy is required to prevent "documentation debt" and ensure documents truthfully describe running systems.

---

## 2. Policy Decisions

1. **Code & Empirical Evidence are the Source of Truth:** Documentation exists to accurately explain and operate the system that exists, not to preserve aspirational or theoretical designs.
2. **Mandatory Documentation Synchronization on Remediation:** Whenever a defect is resolved or an architectural change is made, living documentation (`docs/01-prd.md`, `docs/03-system-architecture.md`, `ENVIRONMENTS.md`, etc.) must be updated in the same commit.
3. **Formal Reconciliation Register:**

| Divergence Topic | Documented Spec | Observed Code Implementation | Reconciled Decision | Action Document |
|---|---|---|---|---|
| **Workflow Engine** | LangGraph + PostgresSaver | Custom DAG in `supervisor.py` | Retain Custom DAG + Redis queue (`ADR-001`) | `03-system-architecture.md` |
| **Worker Queue** | Celery distributed broker | In-memory `_ACTIVE_WORKFLOW_TASKS` | Redis consumer in `worker.py` (`ADR-001`) | `03-system-architecture.md` |
| **Circuit Breaker** | PRD 15%/30s vs Arch 20%/60s | Zero implementation | Standardize on 15%/30s (`ADR-003`) | `03-system-architecture.md` |
| **JWT Token Lifetime** | 15 min + refresh token | 60 min single access token | Adopt 15 min + refresh token in Wave 2 | `02-srs.md`, `apps/api/routers/auth.py` |
| **Bcrypt Cost** | Work factor 14 | Work factor 12 | Standardize on factor 12 (OWASP recommended) | `02-srs.md` |
| **Tool Capabilities** | 18 tools in `docs/09` | 5 tools functional | Phased 4-Tier Roadmap (`ADR-002`) | `docs/09-tool-integrations.md` |
