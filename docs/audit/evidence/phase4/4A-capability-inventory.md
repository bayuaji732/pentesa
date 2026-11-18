# Phase 4A: Capability Inventory & Pre-Scan Static Assessment

> **Document Identifier:** PENTESA-AUDIT-EVID-P4-CAPABILITY-INVENTORY  
> **Audit Phase:** Phase 4 — Advanced Pentest Validation (Step 1)  
> **Timestamp (UTC):** 2026-11-18T10:15:00Z  
> **Evaluator:** Independent Principal Software Architect & Senior Penetration Tester  
> **Methodology:** Static Code Analysis & Deterministic Non-LLM Code Probes  
> **Budget / LLM Spend:** $0.00 / 0 tokens (No LLM calls invoked)  

---

## 1. Executive Summary & Core Architectural Questions

Prior to initiating any dynamic scans or committing benchmark budgets, an exhaustive static code audit and deterministic AST/runtime inspection were conducted across the Pentesa codebase. This inventory evaluates the 10 mandated Phase 4 advanced testing capabilities against the actual implementation.

### Key Architectural Findings

1. **Can AGT-07 (Authorization Testing Agent) consume `AuthProfile` entries from the credential vault and send the same request under two identities?**  
   **NO (Not Implemented).**  
   - *Code Evidence:* In `agents/authorization/authz_agent.py` (lines 148–168), `safe_request` is called with `headers=None`. It neither queries the `auth_profiles` table (`database/models/auth_profile.py`) nor decrypts stored AES-256-GCM credentials.  
   - *Token Evidence:* Although lines 212–220 log a tool call named `multi_identity_prober`, the tool does not exist in `services/execution_engine/tools/` and the actual HTTP requests sent to `sample_route` and `sibling_route` are completely unauthenticated.

2. **Can the platform hold two identities in one workflow?**  
   **NO (Not Implemented).**  
   - *Code Evidence:* In `services/orchestrator/state.py` (lines 9–40), `PentestWorkflowState` contains fields for scope, endpoints, WSTG state, and findings, but has **zero** fields for authentication credentials, session tokens, user roles, or multiple identities (`auth_profile`, `identities`, `tokens`, `user_a`, `user_b`).  
   - *Workflow Execution:* Workflows run without any ambient user authentication context; all requests execute unauthenticated.

3. **Does anything flag business-logic cases "for human review" as ground truth demands?**  
   **PARTIAL (Execution Engine Only; Disconnected from Agent Findings).**  
   - *Code Evidence (Catalog & Engine):* In `services/execution_engine/wstg_catalog_data.py` (lines 1104–1206), tests `WSTG-BUSL-01` through `WSTG-BUSL-07` are flagged with `"requires_human_review": True` and `"automation_capability": "Partial"`. In `services/execution_engine/runners.py` (lines 394–406), `GenericProbeRunner` intercepts these tests and immediately returns `ExecutionResult(status="NEEDS_REVIEW")`.  
   - *Defect in Agent Pipeline:* In `agents/validation/validation_agent.py` (lines 164–239), the agent only outputs `Confirmed` findings or `False Positive` (`WAF_BLOCK_PAGE`). `FindingCreate` schema (`packages/schemas/finding.py`) and `database/models/finding.py` lack any `FLAGGED_FOR_HUMAN_REVIEW` status. Business logic flaws cannot be flagged for human review by the multi-agent workflow.

---

## 2. Granular Area-by-Area Capability Matrix

| Area # | Capability Area | Implementation Status | Code References | Summary of Actual System Capability |
|:---:|---|:---:|---|---|
| **1** | **Context-Aware Testing** | **Partial** | `agents/planner/planner_agent.py:37-46`<br>`agents/wstg/wstg_agent.py:100-130` | Heuristic endpoint routing based on URL keyword and WSTG prefix (`login` -> ATHN, `/api` -> APIT, parameters -> INPV). Lacks business context tracking or stateful flow awareness. |
| **2** | **Parameter Relationship Analysis** | **Not Implemented** | `agents/vulnerability/vuln_agent.py:353-384`<br>`services/discovery_engine/service.py:1-150` | Parameters are extracted as isolated scalar strings. Testing probes one parameter at a time. Zero cross-parameter dependency analysis or multi-parameter constraint checking. |
| **3** | **Authentication-Context Comparison** *(admin vs member vs unauthenticated)* | **Not Implemented** | `agents/authorization/authz_agent.py:148-168`<br>`services/orchestrator/state.py:9-40` | No credentials or roles passed during scan execution. The platform cannot compare responses across privilege tiers. Tool call `multi_identity_prober` is an unauthenticated mock stub. |
| **4** | **Cross-User Authorization Testing** | **Not Implemented** | `agents/authorization/authz_agent.py:132-168` | Sibling URL substitution manipulates path integers (`/1` -> `/2`), but requests are made unauthenticated. No cross-user identity swapping (User A token on User B object) exists. |
| **5** | **API Object-Level Authorization (BOLA)** | **Partial** | `agents/authorization/authz_agent.py:73-239` | Detects **unauthenticated** object exposure: regex-replaces path parameters with `1` and `2`, issues GET requests, and triggers candidate finding if sensitive keywords (`api_key`, `password`, `email`) appear in HTTP 200 responses. Authenticated BOLA is Not Implemented. |
| **6** | **Business-Logic Anomaly Detection** | **Partial** | `services/execution_engine/wstg_catalog_data.py:1104-1206`<br>`services/execution_engine/runners.py:394-406` | WSTG catalog identifies `WSTG-BUSL-01..07` as `requires_human_review=True` and runner marks them `NEEDS_REVIEW`. However, zero active automated anomaly detection (e.g. price tampering, race conditions, negative numbers) exists in agents. |
| **7** | **Workflow State Inconsistency** | **Not Implemented** | `agents/vulnerability/vuln_agent.py`<br>`services/orchestrator/supervisor.py:45-56` | Zero capabilities to detect or probe multi-step workflow sequence violations, step-skipping, or state machine anomalies. |
| **8** | **Multi-Step Validation** | **Partial** | `agents/validation/validation_agent.py:81-170` | Performs single-step live HTTP replay against candidate `matched_at` URL and evaluates response via LLM reasoning. Multi-step transaction replay (e.g., login -> fetch nonce -> post) is Not Implemented. |
| **9** | **Chained Findings with Independent Justification** | **Not Implemented** | `database/models/finding.py:1-120`<br>`packages/schemas/finding.py:1-60` | Finding models and database tables are completely flat. Zero relational fields for parent finding, prerequisites, or exploit graph dependencies. |
| **10** | **Expected vs Actual Behavior Comparison** | **Partial** | `agents/authorization/authz_agent.py:170-179`<br>`agents/validation/validation_agent.py:133-170`<br>`services/execution_engine/runners.py:270-320` | Response diffing exists for unauthenticated BOLA (object 1 vs 2 status/body), security headers (expected vs observed set), and LLM validation of raw error text. Lacks formal semantic assertion logic. |

---

## 3. Scope & Budget Gating for Phase 4 Runs

Per the Phase 4 audit governance rules:
> *"Areas that are Not Implemented get NO scan and NO budget; they are recorded as Not Implemented with the code evidence."*

### Excluded from Scanning & Budget Allocation (Not Implemented)
- **Area 2:** Parameter relationship analysis ($0 / 0 runs)
- **Area 3:** Authentication-context comparison ($0 / 0 runs)
- **Area 4:** Cross-user authorization testing ($0 / 0 runs)
- **Area 7:** Workflow state inconsistency ($0 / 0 runs)
- **Area 9:** Chained findings with independent justification ($0 / 0 runs)

### Eligible for Validation Scanning (Implemented / Partial)
- **Area 1:** Context-aware testing (heuristic routing evaluation)
- **Area 5:** API object-level authorization (unauthenticated BOLA evaluation on `pentesa-bench` and `crapi`)
- **Area 6:** Business-logic anomaly detection (WSTG catalog human review flagging evaluation)
- **Area 8:** Multi-step validation (single-step validation engine behavior evaluation)
- **Area 10:** Expected vs actual behavior comparison (response differencing and LLM validation evaluation)
