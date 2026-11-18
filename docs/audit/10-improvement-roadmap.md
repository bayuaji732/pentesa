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
