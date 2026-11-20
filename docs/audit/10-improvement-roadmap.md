# Pentesa Audit: Improvement Roadmap (Phase 9 Backlog)

This document catalogs identified improvements, technical debt, and recommended architectural enhancements across the Pentesa platform, categorized according to the severity classification defined in `docs/audit/00-master-prompt.md`.

---

## Severity Classification
- **P0**: Critical security or scope enforcement issue.
- **P1**: Core functionality broken or major vulnerability.
- **P2**: Important detection, scoring, or reliability improvement.
- **P3**: UX, performance, operational hygiene, and maintainability improvement.

---

## Improvement Backlog

### P3-AUTH-01: Forced Password Change on First Login for Bootstrapped Admin Accounts
- **Category**: Authentication & Credential Governance
- **Severity**: P3 (Operational Security & User Experience)
- **Status**: Identified; Deferred to Phase 9 implementation.
- **Problem Statement**:
  When an initial administrator account is initialized via `PENTESA_BOOTSTRAP_ADMIN_PASSWORD` (or when accounts are provisioned via administrative scripts), the credentials remain active indefinitely without prompting or requiring the user to establish a personal, unshared password upon initial login.
- **Proposed Solution**:
  1. Add a `must_change_password` boolean attribute (defaulting to `True` for bootstrapped or newly provisioned administrative accounts) to `database.models.user.User`.
  2. In `apps.api.routers.auth.login`, if `user.must_change_password` is `True`, issue an access token flagged with a restricted scope (`PASSWORD_RESET_ONLY`) or include `must_change_password: true` in the authentication response payload.
  3. Enforce an API middleware check or frontend guard routing the user directly to a mandatory password change interface (`POST /api/v1/auth/change-password`), rejecting access to operational scanning endpoints until a new password satisfying `SEC-PWD-01` is confirmed.
  4. Reset `must_change_password = False` upon successful completion.

---

### P3-INFRA-01: Deprecation & Consolidation of Stale Compose Configurations
- **Category**: Infrastructure Maintenance
- **Severity**: P3 (Maintainability)
- **Status**: Documented; Cleanup scheduled for Phase 9.
- **Problem Statement**:
  Legacy deployment manifests (`infrastructure/docker-compose.prod.yml`) contained outdated default credential placeholders (`pentesa_password`) and overlapping container names that conflict with the root production manifest (`docker-compose.yml`).
- **Proposed Solution**:
  Consolidate all production compose configurations into the root `docker-compose.yml` (managed under `name: pentesa-prod`), and archive or update `infrastructure/docker-compose.prod.yml` to prevent administrative confusion.


---

### P2-RECON-01: Automated ffuf Wordlist Fallback for Single-Page and Unlinked API Targets
- **Category**: Attack Surface Reconnaissance & Discovery
- **Severity**: P2 (Important Detection Improvement)
- **Status**: Documented; Scheduled for Phase 9 implementation.
- **Problem Statement**:
  When crawling headless APIs, microservices, or SPAs where `GET /` returns HTTP 404 or lacks standard `<a href="...">` hyperlinks (e.g. `pentesa-bench`), the discovery crawler discovers $\le 1$ endpoint. Consequently, active assessment agents (`AGT-07` through `AGT-15`) receive an empty attack surface and cannot probe vulnerable routes.
- **Proposed Solution**:
  1. In `agents.recon.recon_agent.ReconnaissanceAgent`, evaluate the count of endpoints discovered after initial crawling.
  2. If discovered endpoints $\le 3$ or target root returns HTTP 404/403, automatically trigger a secondary path discovery pass using `ffuf` with `/opt/wordlists/common.txt` against the base URL.
  3. Automatically ingest discovered 200/301/302/401 routes into `endpoints_inventory` and persist them via `POST /api/v1/projects/{id}/endpoints`.

---

### P2-FIND-01: Direct Promotion for Passive Security & Configuration Findings
- **Category**: Vulnerability Validation & Finding Promotion
- **Severity**: P2 (Important Detection Improvement)
- **Status**: Documented; Scheduled for Phase 9 implementation.
- **Problem Statement**:
  Defensive configuration issues (e.g. missing security headers `WSTG-CLNT-09`, server banner disclosure `WSTG-INFO-02`) were accurately flagged as `candidate_findings` during passive probing, but the verification agent (`AGT-11`) discarded them because they do not have an active exploit payload. As a result, confirmed findings remained at zero.
- **Proposed Solution**:
  1. In `agents.validation.validation_agent`, introduce a severity/category-specific promotion bypass for passive and informational WSTG checks.
  2. If a candidate finding originates from `wstg_agent` under passive categories (`WSTG-CONF-*`, `WSTG-CLNT-*`, `WSTG-INFO-*`) with definitive response evidence, promote directly to `confirmed_findings` without requiring active exploit roundtrips.

---

### P2-REL-01: Autonomous Gateway Circuit Breaking and Resumable Workflows
- **Category**: Agent Reliability & Fault Tolerance
- **Severity**: P2 (Reliability Improvement)
- **Status**: Documented; Scheduled for Phase 9 implementation.
- **Problem Statement**:
  When the upstream LLM gateway returned transient 503 errors (`no_db_connection`), the orchestrator terminated running workflows with `FAILED` status, and subsequent runs failed immediately on start.
- **Proposed Solution**:
  1. Implement exponential backoff and jitter for upstream LLM gateway calls.
  2. Introduce workflow state pause/resume: transition to `PAUSED_GATEWAY_UNAVAILABLE` rather than immediate termination, retrying when the gateway recovers.

---

### P1-FIND-02: Finding API Model Serialization Omits Root Endpoint and Method Strings
- **Category**: Findings Management & API Schema Integration
- **Severity**: P1 (Core Data Contract Defect — Phase 7 Mandate)
- **Status**: Documented; Scheduled for Phase 9 implementation.
- **Problem Statement**:
  The `FindingResponse` schema in `packages/schemas/finding.py` and API router `GET /api/v1/projects/{project_id}/findings` serialize `endpoint_id: Optional[UUID]`, but omit denormalized `endpoint: Optional[str]`, `target: Optional[str]`, and `method: Optional[str]`. Consequently, standard external tools, benchmark scorers (including the Phase 3 frozen `score.py`), and downstream reporting consumers receive empty endpoint strings when inspecting finding objects directly unless they perform a secondary join across `endpoints` and `evidence`.
- **Proposed Solution**:
  1. Add denormalized or property-backed fields `endpoint: Optional[str] = None`, `target: Optional[str] = None`, and `method: Optional[str] = None` to `FindingResponse`.
  2. In the findings query router, join `Endpoint` table to populate path and method, or extract fallback values from `FindingEvidence.raw_request`.
  3. Alias or mirror `affected_parameter` to `parameter`.

---

### P2-AUTH-01: Session Context & State Management for Authenticated Target Probers
- **Category**: Dynamic Fuzzing & Multi-Step Assessment
- **Severity**: P2 (Detection Improvement)
- **Status**: Documented; Scheduled for Phase 9 implementation.
- **Problem Statement**:
  Active assessment probers on third-party targets requiring multi-step authentication (e.g., DVWA requiring login + CSRF token, crAPI requiring user signup/login token, WebGoat requiring login) probe unauthenticated endpoints or get redirected to login pages, resulting in false negatives on authenticated vulnerability test cases.
- **Proposed Solution**:
  1. Integrate automated session acquisition and cookie/token preservation in `agents/authorization/authz_agent.py` and tool runners using target-specific credentials from `auth_profiles`.
  2. Ensure probers inject authenticated session cookies and Bearer tokens into fuzzing and prober payloads.

---

### P1-AUTH-01: Multi-Identity Session Context & Credential Vault Binding for AGT-07
- **Category**: Authorization & Multi-Tenant Testing
- **Severity**: P1 (Core Functionality Gap — Governs FR-AB-01, FR-AB-02, FR-AB-03)
- **Status**: Documented; Scheduled for Phase 9 implementation.
- **Problem Statement**:
  `AuthorizationAgent` (`AGT-07`) sends requests with empty headers (`headers=None`), failing to consume target credentials from `auth_profiles` or maintain dual-tenant sessions. The orchestrator workflow state (`PentestWorkflowState`) lacks identity attributes, preventing authenticated BOLA, IDOR, and privilege escalation testing across roles.
- **Proposed Solution**:
  1. Add `identities: Dict[str, Dict[str, Any]]` to `PentestWorkflowState` in `services/orchestrator/state.py`.
  2. Implement target credential retrieval and AES-256-GCM decryption in `agents/authorization/authz_agent.py` to acquire active session tokens for User A, User B, and Administrative roles.
  3. Implement cross-user request replay: substitute object IDs discovered under User A with User B's token, asserting whether cross-tenant access is permitted.

---

### P2-BUSL-01: `FLAGGED_FOR_HUMAN_REVIEW` Finding Status and Semantic Anomaly Heuristics
- **Category**: Business Logic Testing & Human Review Governance
- **Severity**: P2 (Important Detection & Governance Improvement — Governs FR-AB-04, FR-AB-05)
- **Status**: Documented; Scheduled for Phase 9 implementation.
- **Problem Statement**:
  Business logic anomalies (e.g. client pricing tampering, workflow step-skipping, race conditions) cannot be safely auto-exploited in production and require human evaluation. However, the finding status enum only supports `CANDIDATE`, `CONFIRMED`, and `FALSE_POSITIVE`. Unconfirmed business logic candidates are discarded by `ValidationAgent`.
- **Proposed Solution**:
  1. Add `FLAGGED_FOR_HUMAN_REVIEW` to `FindingStatusEnum` in `database/models/finding.py` and `packages/schemas/finding.py`.
  2. In `agents/validation/validation_agent.py`, transition candidate findings belonging to `WSTG-BUSL-*` or monetary/workflow anomalies to `FLAGGED_FOR_HUMAN_REVIEW` with evidence attachment.
  3. Introduce semantic parameter inspection in `agents/vulnerability/vuln_agent.py` targeting business-critical parameters (`client_price`, `amount`, `coupon`, `workflow_step`).

---

### P2-CHAIN-01: Finding Graph DAG and Exploit Dependency Chaining
- **Category**: Vulnerability Correlation & Attack Path Reporting
- **Severity**: P2 (Reporting & Modeling Improvement)
- **Status**: Documented; Scheduled for Phase 9 implementation.
- **Problem Statement**:
  Findings are stored as flat, disconnected records. The platform cannot express multi-step attack graphs where one vulnerability enables or escalates another (e.g. Information Disclosure -> Session Hijacking -> Administrative Takeover).
- **Proposed Solution**:
  1. Add `parent_finding_id: Optional[UUID]` and `prerequisites: List[UUID]` to `database/models/finding.py` and `packages/schemas/finding.py`.
  2. Support attack path DAG synthesis in `services/evidence_engine/finding_service.py`.
  3. Render visualized attack chains in PTES executive and technical report sections.

---

### P3-LLM-01: Reasoning Model Adaptive Health Probe Token Limits (Test Harness)
- **Category**: Test Harness & Provider Tooling
- **Severity**: P3 (Test Hygiene)
- **Status**: Documented; Test harness tooling update.
- **Problem Statement**:
  Reasoning models (Azure GPT-5 / OpenAI o-series) reject health check requests with `max_tokens: 1`, returning 400 Bad Request.
- **Proposed Solution**:
  1. In `check_gateway_health.py` and benchmark health probes, detect reasoning models and adjust health check parameter to `max_completion_tokens: 50`.

---

### P1-AGENT-01: Empirical Reproduction Gating & Hallucination Resistance Invariant in ValidationAgent
- **Category**: AI Agent System & Vulnerability Validation
- **Severity**: P1 (Core Functionality & Accuracy Invariant — Governs FR-VV-05, US-04)
- **Status**: Documented; Scheduled for Phase 9 implementation.
- **Problem Statement**:
  In `ValidationAgent.execute()`, candidate findings are validated using an LLM prompt without asserting whether the preceding empirical reproduction probe succeeded. When tested in Phase 5 (`P5-TC-HALLUC-01`), a candidate finding targeting a non-existent endpoint (`/admin/super-exec`) that returned HTTP 404 was hallucinated as `is_valid: true` by the LLM. `ValidationAgent` promoted the finding to `confirmed_findings` without wire proof, resulting in 0.0% hallucination resistance (`DEFECT-AGENT-01`).
- **Proposed Solution**:
  1. In `agents/validation/validation_agent.py`, enforce an empirical wire proof invariant before evaluating LLM assertions:
     - Require `repro_status in (200, 201, 204, 302)` and non-empty `raw_response`.
     - If the reproduction probe returns HTTP 404, 502, or timeout, immediately reject the candidate as `FALSE_POSITIVE` or demote to `UNCONFIRMED_ANOMALY`.
  2. Implement bidirectional validation: both empirical wire evidence AND LLM semantic analysis must agree before promoting a finding to `confirmed_findings`.
  3. Emit structured audit log `HALLUCINATION_SUPPRESSED` when an LLM claims `is_valid: true` on an unverified reproduction.

---

### DEFECT-AUTH-03: Redis-Backed Sliding Window Rate Limiting on User Authentication Endpoint
- **Category**: Authentication & Platform Security
- **Severity**: P2 (Brute-Force & Credential Stuffing Defect — Governs PRD §4.1, ASVS V2)
- **Status**: Documented in Phase 6 Security Assessment; Scheduled for Phase 9 implementation.
- **Problem Statement**:
  `POST /api/v1/auth/login` currently lacks request rate limiting or failure throttling. In Phase 6 and Phase 6b wire testing (`P6-TC-AUTH-04`, `P6B-TC-AUTH-01`), 15 rapid consecutive failed authentication attempts were permitted without delay or IP throttling, returning HTTP 401 repeatedly rather than HTTP 429 Too Many Requests.
- **Proposed Solution**:
  1. Integrate a Redis-backed sliding window rate limiter (or `slowapi` limiter) on `POST /api/v1/auth/login`.
  2. Enforce a threshold of maximum 5 failed attempts per 60-second window per client IP address and per target account email.
  3. When threshold is exceeded, return `HTTP 429 Too Many Requests` with `Retry-After: 60` and record an immutable security audit event `AUTH_LOGIN_THROTTLED`.

---

### P3-API-01: Administrative User Deletion Route in API Router
- **Category**: User Management & Data Hygiene
- **Severity**: P3 (Operational Security & Data Lifecycle)
- **Status**: Documented in Phase 6 Gate Cleanup; Scheduled for Phase 9 implementation.
- **Problem Statement**:
  `apps/api/routers/users.py` lacks a `DELETE /api/v1/users/{id}` endpoint. Throwaway accounts created during automated security evaluations or testing cannot be deleted via the API (HTTP 405 Method Not Allowed), forcing direct database SQL intervention.
- **Proposed Solution**:
  1. Add `DELETE /api/v1/users/{user_id}` route with `require_role(UserRole.ADMIN)`.
  2. Enforce guardrails preventing self-deletion and orphan project memberships.
  3. Return HTTP 204 No Content upon successful deletion.

---

### DEFECT-API-02: Chained Eager Loading for Project Member Users in Project Details Route
- **Category**: API Availability & Core Read Path Serialization
- **Severity**: P1 (Critical — Core Read Path Broken on GET /api/v1/projects/{id})
- **Status**: Documented in Phase 6b Wire Suite; Patch Prepared (`docs/audit/patches/DEFECT-API-02.diff`); Prerequisite for Phase 7 UI/Evidence validation.
- **Problem Statement**:
  `GET /api/v1/projects/{project_id}` crashes with HTTP 500 (`MissingGreenlet` inside `ResponseValidationError`) when called by authorized members because `verify_project_access` loads `Project.members` without eager-loading `ProjectMember.user`.
- **Proposed Solution**:
  In `apps/api/dependencies.py:verify_project_access`, update the query statement to:
  ```python
  stmt = (
      select(Project)
      .options(
          selectinload(Project.members).selectinload(ProjectMember.user),
          selectinload(Project.scope_rules)
      )
      .where(Project.id == project_id)
  )
  ```




