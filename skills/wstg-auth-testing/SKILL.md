---
name: wstg-auth-testing
version: 1.0.0
description: Tests authentication mechanisms covering credentials over encrypted channels, default credentials, lockout, and password reset (WSTG-ATHN-01 to 10).
category: testing
requires_scope_validation: true
requires_human_approval: true
risk_tier: medium
tool_dependencies: [http_client]
agent_compatibility: [AGT-06]
---

# WSTG Authentication Testing Skill

## 1. Purpose & Objective
Evaluates application authentication security according to OWASP WSTG Category 4:
- WSTG-ATHN-01: Credentials transported over encrypted channels.
- WSTG-ATHN-02: Default credentials.
- WSTG-ATHN-03: Weak lockout mechanism / credential stuffing resistance.
- WSTG-ATHN-07: Weak password policy.
- WSTG-ATHN-09: Weak password reset functionality.

## 2. Execution Prerequisites
- Discovered authentication endpoints (`/login`, `/reset-password`).
- Optional designated test account credentials provided by client.

## 3. Authorized Scope Requirements
Testing strictly limited to project auth profiles; outbound requests route through Egress Proxy.

## 4. Input & Output Contract
### Input Schema:
```json
{
  "project_id": "UUID",
  "login_url": "https://app.example.com/api/v1/auth/login",
  "max_failed_attempts": 10,
  "test_account": "pentesa_test_user@example.com"
}
```
### Output Schema:
```json
{
  "lockout_observed": false,
  "rate_limiting_active": false,
  "wstg_status": "Failed",
  "anomaly": "No account lockout or IP throttling triggered after 10 consecutive failed logins."
}
```

## 5. Step-by-Step Execution Instructions
1. Inspect login endpoint protocol scheme: ensure strictly HTTPS (WSTG-ATHN-01).
2. Check for common administrative default credentials (e.g. `admin:admin`, `test:test`) with max 3 attempts.
3. Test lockout threshold: send sequential invalid password attempts (max 10), checking for HTTP 429 status or lockout messages.
4. If $> 15$ attempts are planned, pause and request human operator approval.
5. Record anomalies and pass to validation agent.

## 6. Safety Constraints & Rate Limiting
- Capped at max 10 attempts unless operator explicitly approves higher threshold.
- Stops testing immediately if account locked status (`HTTP 423 Locked`) is detected.

## 7. Evidence Requirements
- Raw HTTP request/response traces demonstrating lack of lockout or rate limiting.

## 8. Error Handling & Fallbacks
- Halts execution on target 500-level error responses.

## 9. Validation Criteria
- Accurately determines account lockout policy and cryptographic transport posture.
