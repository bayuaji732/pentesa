# Pentesa — REST & WebSocket API Specification

> **Document Identifier:** PENTESA-API-SPEC-V1.0  
> **Status:** Approved for Implementation  
> **Protocol:** RESTful JSON (HTTP/1.1 & HTTP/2) + WebSockets (RFC 6455)  
> **Base Path:** `/api/v1`  
> **Target Release:** v1.0  

---

## Table of Contents

1. [API Architecture & Design Principles](#1-api-architecture--design-principles)
2. [Authentication, Authorization & Headers](#2-authentication-authorization--headers)
3. [Standard Envelopes: Errors, Pagination & Timestamps](#3-standard-envelopes-errors-pagination--timestamps)
4. [Module Endpoint Specifications](#4-module-endpoint-specifications)
   - [4.1 Module 1: Authentication & User Management (Auth)](#41-module-1-authentication--user-management-auth)
   - [4.2 Module 2: Project Management (Projects)](#42-module-2-project-management-projects)
   - [4.3 Module 3: Scope Enforcement & Governance (Scope)](#43-module-3-scope-enforcement--governance-scope)
   - [4.4 Module 4: Attack Surface & Discovery (Discovery)](#44-module-4-attack-surface--discovery-discovery)
   - [4.5 Module 5: OWASP WSTG Test Plan & Coverage (WSTG)](#45-module-5-owasp-wstg-test-plan--coverage-wstg)
   - [4.6 Module 6: Deterministic Tool Integrations (Tools)](#46-module-6-deterministic-tool-integrations-tools)
   - [4.7 Module 7: Findings, Evidence & Validation (Findings)](#47-module-7-findings-evidence--validation-findings)
   - [4.8 Module 8: AI Multi-Agent Observability (Agents)](#48-module-8-ai-multi-agent-observability-agents)
   - [4.9 Module 9: PTES Report Generation (Reports)](#49-module-9-ptes-report-generation-reports)
   - [4.10 Module 10: Audit Trail & Compliance (Audit)](#410-module-10-audit-trail--compliance-audit)
   - [4.11 Module 11: Scan Jobs & Scheduling (Scans)](#411-module-11-scan-jobs--scheduling-scans)
5. [Real-Time WebSocket Protocol](#5-real-time-websocket-protocol)
6. [API Error Codes Catalog](#6-api-error-codes-catalog)

---

## 1. API Architecture & Design Principles

The Pentesa API provides the programmatic interface between the React frontend, external CI/CD runners, and internal background workers.

### Core Guidelines
- **Strict REST Conventions:** Standard HTTP verbs (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`) with semantically correct status codes (`200 OK`, `201 Created`, `204 No Content`, `400 Bad Request`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found`, `422 Unprocessable Entity`).
- **Pydantic Validation:** Inbound and outbound payloads are validated against Pydantic v2 schemas.
- **Explicit Versioning:** Prefixed with `/api/v1`. Breaking changes require a version bump.
- **Standardized Error Envelope:** Every failure response returns a structured JSON payload with machine-readable error codes.
- **WebSocket Streaming:** Long-running execution logs, agent thoughts, and finding alerts stream over WebSockets to avoid expensive client polling.

---

## 2. Authentication, Authorization & Headers

### Security Headers
- `Authorization: Bearer <jwt_access_token>`
- `Content-Type: application/json`
- `X-Request-ID: <uuid>` (propagated through Celery and database logs)

### Role-Based Access Control (RBAC) Matrix
- `Admin`: Full read/write across all platform resources and user management.
- `Lead_Tester`: Full project, scope, scan, and reporting control.
- `Tester`: Launch authorized scans, view findings, add manual review notes.
- `Viewer`: Read-only access to projects, dashboards, and generated reports.

---

## 3. Standard Envelopes: Errors, Pagination & Timestamps

### Standard Error Response Envelope
```json
{
  "success": false,
  "error": {
    "code": "SCOPE_VALIDATION_FAILED",
    "message": "Target domain 'analytics.thirdparty.com' is not in project approved scope.",
    "details": {
      "candidate_url": "https://analytics.thirdparty.com/collect",
      "project_id": "8a1e4c3b-7f2a-4b11-9a3b-2f1d8c7e9b01"
    },
    "request_id": "c1f7b8a2-9d3e-4b22-8c11-9f2e3a4b5c6d",
    "timestamp": "2026-11-03T16:10:00Z"
  }
}
```

### Standard Cursor-Based Pagination Schema
For large datasets (`endpoints`, `findings`, `audit_logs`):
```json
{
  "success": true,
  "data": [...],
  "pagination": {
    "cursor": "ZXlKaGJHY2lPaUpTVXpVe...",
    "has_next": true,
    "limit": 50,
    "total_count": 1420
  }
}
```

---

## 4. Module Endpoint Specifications

---

### 4.1 Module 1: Authentication & User Management (Auth)

#### 1. `POST /api/v1/auth/login`
- **Description:** Authenticate platform user and issue JWT token pair.
- **Auth:** None.
- **Request Body:**
  ```json
  { "email": "tester@pentesa.local", "password": "SuperSecretPassword123!" }
  ```
- **Response (200 OK):**
  ```json
  {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "def50200...",
    "token_type": "bearer",
    "expires_in": 900,
    "user": { "id": "UUID", "email": "tester@pentesa.local", "role": "Lead_Tester" }
  }
  ```

#### 2. `POST /api/v1/auth/refresh`
- **Description:** Exchange refresh token for fresh 15-minute access token.
- **Auth:** Refresh Token.

#### 3. `POST /api/v1/auth/logout`
- **Description:** Invalidate active refresh token in Redis blocklist.
- **Auth:** Bearer Token.

#### 4. `GET /api/v1/auth/me`
- **Description:** Fetch current authenticated user profile and permissions.
- **Auth:** Bearer Token.

---

### 4.2 Module 2: Project Management (Projects)

#### 5. `POST /api/v1/projects`
- **Description:** Create a new penetration test engagement with RoE parameters.
- **Auth:** Lead_Tester, Admin.
- **Request Body:**
  ```json
  {
    "name": "Staging Assessment Q4",
    "client_name": "Acme Corp",
    "description": "Pre-release pentest of Acme portal",
    "auth_signer_name": "Jane Doe (CISO)",
    "auth_signer_email": "jane@acme.com",
    "auth_start_date": "2026-11-03T00:00:00Z",
    "auth_end_date": "2026-11-10T23:59:59Z",
    "max_rps": 20
  }
  ```
- **Response (201 Created):** Full project object with assigned UUID.

#### 6. `GET /api/v1/projects`
- **Description:** List projects with optional status filter and pagination.

#### 7. `GET /api/v1/projects/{project_id}`
- **Description:** Retrieve detailed project summary, statistics, and health metrics.

#### 8. `PATCH /api/v1/projects/{project_id}`
- **Description:** Update project details or rate limits (Lead_Tester, Admin).

#### 9. `POST /api/v1/projects/{project_id}/archive`
- **Description:** Lock project as read-only upon completion.

#### 10. `DELETE /api/v1/projects/{project_id}`
- **Description:** Permanently purge project and all child records (Admin only).

#### 11. `POST /api/v1/projects/{project_id}/members`
- **Description:** Assign user to project team.

#### 12. `DELETE /api/v1/projects/{project_id}/members/{user_id}`
- **Description:** Remove user from project team.

---

### 4.3 Module 3: Scope Enforcement & Governance (Scope)

#### 13. `POST /api/v1/projects/{project_id}/scope/targets`
- **Description:** Add in-scope target (Domain, Wildcard, IP, or CIDR).
- **Request Body:**
  ```json
  {
    "target_type": "WILDCARD",
    "value": "*.acme-staging.com",
    "protocol": "BOTH"
  }
  ```

#### 14. `GET /api/v1/projects/{project_id}/scope/targets`
- **Description:** List all approved targets for project.

#### 15. `DELETE /api/v1/projects/{project_id}/scope/targets/{target_id}`
- **Description:** Remove in-scope target and invalidate cached target list.

#### 16. `POST /api/v1/projects/{project_id}/scope/exclusions`
- **Description:** Add excluded endpoint path regex or host.
- **Request Body:**
  ```json
  {
    "exclusion_type": "PATH_REGEX",
    "pattern": "^/admin/purge.*",
    "description": "Prevent database wipe endpoint from crawling"
  }
  ```

#### 17. `GET /api/v1/projects/{project_id}/scope/exclusions`
- **Description:** List all configured exclusions.

#### 18. `DELETE /api/v1/projects/{project_id}/scope/exclusions/{exclusion_id}`
- **Description:** Remove exclusion rule.

#### 19. `POST /api/v1/projects/{project_id}/scope/validate`
- **Description:** Test an arbitrary URL against the scope engine without executing a probe.
- **Request Body:** `{ "url": "https://app.acme-staging.com/api/test" }`
- **Response (200 OK):** `{ "allowed": true, "resolved_ip": "192.168.1.10", "reason": "Matches *.acme-staging.com" }`

#### 20. `GET /api/v1/projects/{project_id}/scope/history`
- **Description:** Fetch complete audit trail of scope revisions.

---

### 4.4 Module 4: Attack Surface & Discovery (Discovery)

#### 21. `POST /api/v1/projects/{project_id}/discovery/start`
- **Description:** Launch passive reconnaissance and active web crawling.
- **Request Body:** `{ "crawl_depth": 3, "use_headless": false, "rate_limit": 15 }`

#### 22. `GET /api/v1/projects/{project_id}/discovery/status`
- **Description:** Query status of ongoing discovery task.

#### 23. `GET /api/v1/projects/{project_id}/endpoints`
- **Description:** Query centralized endpoint inventory with filtering (method, auth, status).

#### 24. `POST /api/v1/projects/{project_id}/endpoints`
- **Description:** Manually insert endpoint discovered out-of-band.

#### 25. `GET /api/v1/projects/{project_id}/domains`
- **Description:** List discovered subdomains and resolved IPs.

#### 26. `GET /api/v1/projects/{project_id}/technologies`
- **Description:** List fingerprinted server frameworks, languages, and client libraries.

---

### 4.5 Module 5: OWASP WSTG Test Plan & Coverage (WSTG)

#### 27. `GET /api/v1/wstg/catalog`
- **Description:** Retrieve master catalog of all 12 WSTG v4.2 categories and tests.

#### 28. `GET /api/v1/projects/{project_id}/wstg/plan`
- **Description:** Retrieve project-specific test plan and status matrix.

#### 29. `PATCH /api/v1/projects/{project_id}/wstg/tests/{test_instance_id}`
- **Description:** Manually update test status (e.g. mark `Not Applicable` with reason).

#### 30. `GET /api/v1/projects/{project_id}/wstg/coverage`
- **Description:** Fetch mathematical coverage breakdown by category.
- **Response (200 OK):**
  ```json
  {
    "overall_coverage_pct": 78.4,
    "total_tests": 102,
    "passed_count": 62,
    "failed_count": 8,
    "needs_review_count": 4,
    "not_applicable_count": 6,
    "not_started_count": 22,
    "categories": {
      "WSTG-INPV": { "coverage_pct": 92.0, "total": 19, "passed": 15, "failed": 3, "na": 1 }
    }
  }
  ```

#### 31. `POST /api/v1/projects/{project_id}/wstg/execute/{wstg_id}`
- **Description:** Trigger execution of a specific WSTG test case across applicable endpoints.

#### 32. `GET /api/v1/projects/{project_id}/wstg/executions/{execution_id}`
- **Description:** Retrieve detailed execution record and timing.

#### 33. `GET /api/v1/projects/{project_id}/wstg/executions/{execution_id}/logs`
- **Description:** Fetch stdout/stderr streaming logs for execution.

#### 34. `POST /api/v1/projects/{project_id}/wstg/recalculate`
- **Description:** Recalculate applicability and coverage after inventory updates.

---

### 4.6 Module 6: Deterministic Tool Integrations (Tools)

#### 35. `GET /api/v1/tools`
- **Description:** List available integrated security binaries and versions (`nuclei`, `katana`, `ffuf`, etc.).

#### 36. `POST /api/v1/projects/{project_id}/tools/execute`
- **Description:** Directly trigger a scoped tool run with typed parameters.

#### 37. `GET /api/v1/projects/{project_id}/tools/executions`
- **Description:** List historical tool runs with exit codes and execution durations.

#### 38. `GET /api/v1/projects/{project_id}/tools/executions/{execution_id}`
- **Description:** Retrieve parsed output and raw artifacts of tool run.

#### 39. `POST /api/v1/projects/{project_id}/tools/executions/{execution_id}/cancel`
- **Description:** Send `SIGTERM` / `SIGKILL` to running tool subprocess.

#### 40. `PUT /api/v1/projects/{project_id}/tools/config`
- **Description:** Set default rate limits and template tags for project tools.

---

### 4.7 Module 7: Findings, Evidence & Validation (Findings)

#### 41. `GET /api/v1/projects/{project_id}/findings`
- **Description:** Query findings with multi-dimensional filtering (severity, status, CWE, WSTG).

#### 42. `POST /api/v1/projects/{project_id}/findings`
- **Description:** Manually create a finding (for manual pentest activities).

#### 43. `GET /api/v1/findings/{finding_id}`
- **Description:** Retrieve finding details, CVSS v3.1 vector, and linked endpoint.

#### 44. `PATCH /api/v1/findings/{finding_id}`
- **Description:** Update finding severity, status, or remediation recommendation.

#### 45. `GET /api/v1/findings/{finding_id}/evidence`
- **Description:** Fetch raw HTTP request/response bytes and SHA-256 hashes.

#### 46. `POST /api/v1/findings/{finding_id}/validate`
- **Description:** Trigger AGT-11 to attempt automated safe reproduction.

#### 47. `POST /api/v1/findings/{finding_id}/false-positive`
- **Description:** Mark finding as False Positive with mandatory classification and justification.

#### 48. `POST /api/v1/findings/{finding_id}/retest`
- **Description:** Re-execute reproduction recipe to confirm developer patch.

#### 49. `GET /api/v1/projects/{project_id}/false-positives`
- **Description:** List all suppressed false positives for audit review.

#### 50. `DELETE /api/v1/findings/{finding_id}`
- **Description:** Delete finding record (Admin/Lead only).

---

### 4.8 Module 8: AI Multi-Agent Observability (Agents)

#### 51. `GET /api/v1/projects/{project_id}/agents/status`
- **Description:** Query state of all 15 agents in the LangGraph supervisor.

#### 52. `POST /api/v1/projects/{project_id}/agents/workflow/start`
- **Description:** Initiate autonomous multi-agent pentest workflow DAG.

#### 53. `POST /api/v1/projects/{project_id}/agents/workflow/pause`
- **Description:** Pause execution at current graph checkpoint.

#### 54. `POST /api/v1/projects/{project_id}/agents/workflow/resume`
- **Description:** Resume paused execution graph.

#### 55. `GET /api/v1/projects/{project_id}/agents/decisions`
- **Description:** Stream agent reasoning traces, intent, and prompts.

#### 56. `POST /api/v1/projects/{project_id}/agents/approvals/{approval_id}`
- **Description:** Operator response (Approve / Reject) to suspended high-risk action.

---

### 4.9 Module 9: PTES Report Generation (Reports)

#### 57. `POST /api/v1/projects/{project_id}/reports/generate`
- **Description:** Compile and render formal PTES report in PDF or HTML.
- **Request Body:**
  ```json
  { "format": "PDF", "template_name": "ptes_standard", "include_raw_evidence": true }
  ```

#### 58. `GET /api/v1/projects/{project_id}/reports`
- **Description:** List generated reports with cryptographic hashes.

#### 59. `GET /api/v1/reports/{report_id}/download`
- **Description:** Stream raw PDF/HTML report file to client.

#### 60. `GET /api/v1/reports/templates`
- **Description:** List available report templates and CSS themes.

#### 61. `DELETE /api/v1/reports/{report_id}`
- **Description:** Remove historical report record.

---

### 4.10 Module 10: Audit Trail & Compliance (Audit)

#### 62. `GET /api/v1/projects/{project_id}/audit`
- **Description:** Query append-only audit trail with date and user filters.

#### 63. `GET /api/v1/audit/system`
- **Description:** Global system audit trail (logins, configuration changes).

#### 64. `POST /api/v1/projects/{project_id}/audit/export`
- **Description:** Export cryptographic audit ledger as signed CSV or JSON.

---

### 4.11 Module 11: Scan Jobs & Scheduling (Scans)

#### 65. `POST /api/v1/projects/{project_id}/scans/schedules`
- **Description:** Set up recurring cron-based scan schedule.

#### 66. `GET /api/v1/projects/{project_id}/scans/schedules`
- **Description:** List recurring scan schedules.

#### 67. `DELETE /api/v1/projects/{project_id}/scans/schedules/{schedule_id}`
- **Description:** Delete scheduled scan.

#### 68. `GET /api/v1/projects/{project_id}/scans/jobs`
- **Description:** List historical scan job runs and statuses.

#### 69. `POST /api/v1/scans/jobs/{job_id}/cancel`
- **Description:** Cancel executing scan job and terminate worker tasks.

---

### 4.12 Module 12: Target Authentication Profiles & Credential Vault (Auth Profiles)

#### 70. `POST /api/v1/projects/{project_id}/auth-profiles`
- **Description:** Create target authentication profile (Bearer Token, Session Cookie, Multi-Role credential pair) with automatic AES-256-GCM encryption of secrets.
- **Auth:** Lead_Tester, Admin.
- **Request Body:**
  ```json
  {
    "name": "Tenant-A Standard User",
    "auth_type": "BEARER_TOKEN",
    "login_url": "https://app.example.com/api/v1/login",
    "credentials": { "token": "eyJhbGciOi..." }
  }
  ```
- **Response (201 Created):** Auth profile object (secrets omitted/redacted).

#### 71. `GET /api/v1/projects/{project_id}/auth-profiles`
- **Description:** List all configured authentication profiles for project (masked secrets).

#### 72. `GET /api/v1/projects/{project_id}/auth-profiles/{profile_id}`
- **Description:** Retrieve specific auth profile metadata.

#### 73. `PUT /api/v1/projects/{project_id}/auth-profiles/{profile_id}`
- **Description:** Update authentication credentials or rotate token.

#### 74. `DELETE /api/v1/projects/{project_id}/auth-profiles/{profile_id}`
- **Description:** Remove authentication profile and securely wipe vaulted secrets.

---

### 4.13 Module 13: Advanced Evidence & Emergency Controls

#### 75. `GET /api/v1/findings/{finding_id}/evidence/screenshot`
- **Description:** Stream captured DOM screenshot image file (PNG) for client-side findings.

#### 76. `POST /api/v1/projects/{project_id}/findings/batch-update`
- **Description:** Perform bulk status transitions (e.g. bulk mark False Positive or Confirmed) with recorded justification.

#### 77. `POST /api/v1/projects/{project_id}/agents/workflow/stop`
- **Description:** Hard emergency stop: sends `SIGKILL` to all active tool subprocesses, aborts Celery task graphs, and invalidates temporary credentials.

#### 78. `GET /api/v1/projects/{project_id}/callbacks`
- **Description:** Query local out-of-band interaction callbacks recorded by `pentesa-callback-sink` for blind SSRF and blind injection correlation.

---

## 5. Real-Time WebSocket Protocol

### Connection URL:
`wss://pentesa.local/ws/v1/projects/{project_id}?token=<jwt_access_token>`

### Message Types Emitted by Server:

1. **Scan Log Line:**
   ```json
   {
     "event": "SCAN_LOG",
     "data": {
       "execution_id": "UUID",
       "tool": "nuclei",
       "level": "INFO",
       "message": "[CVE-2023-XXXX] Matched on https://app.example.com",
       "timestamp": "2026-11-03T16:12:00Z"
     }
   }
   ```

2. **Agent Thought Trace:**
   ```json
   {
     "event": "AGENT_THOUGHT",
     "data": {
       "agent_id": "AGT-08",
       "agent_name": "Input Validation Agent",
       "thought": "Observed reflection of parameter 'q' in HTML response. Planning benign XSS verification probe.",
       "timestamp": "2026-11-03T16:12:05Z"
     }
   }
   ```

3. **Finding Confirmed Alert:**
   ```json
   {
     "event": "FINDING_CONFIRMED",
     "data": {
       "finding_id": "UUID",
       "title": "Reflected Cross-Site Scripting (XSS)",
       "severity": "High",
       "endpoint": "/search?q=",
       "cvss_score": 7.5
     }
   }
   ```

4. **Human Approval Required:**
   ```json
   {
     "event": "APPROVAL_REQUIRED",
     "data": {
       "approval_id": "UUID",
       "agent_id": "AGT-10",
       "action": "Execute directory fuzzing with wordlist size 10,000",
       "target": "https://app.example.com/",
       "risk_assessment": "High request volume; potential server load"
     }
   }
   ```

---

## 6. API Error Codes Catalog

| Error Code | HTTP Status | Meaning & Troubleshooting |
|---|---|---|
| `AUTH_INVALID_CREDENTIALS` | 401 | Email or password incorrect. |
| `AUTH_TOKEN_EXPIRED` | 401 | Access token expired; invoke `/auth/refresh`. |
| `AUTH_FORBIDDEN` | 403 | User role lacks permission for this action. |
| `ROE_WINDOW_EXPIRED` | 403 | Current time is outside authorized project testing window. |
| `SCOPE_VALIDATION_FAILED` | 400 | Destination host, IP, or path violates project scope rules. |
| `SCOPE_DNS_REBINDING_DETECTED`| 400 | Host resolved to unauthorized internal or private IP. |
| `TOOL_EXECUTION_TIMEOUT` | 504 | Security tool exceeded maximum allowed runtime. |
| `CIRCUIT_BREAKER_TRIGGERED`| 429 | Target server error rate exceeded 15%; scans paused. |
| `REPRODUCTION_FAILED` | 422 | Vulnerability reproduction probe did not replicate defect. |

