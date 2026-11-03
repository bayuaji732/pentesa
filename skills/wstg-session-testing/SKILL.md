---
name: wstg-session-testing
version: 1.0.0
description: Tests session management, cookie security attributes, session fixation, and CSRF (WSTG-SESS-01 to 09).
category: testing
requires_scope_validation: true
requires_human_approval: false
risk_tier: low
tool_dependencies: [http_client]
agent_compatibility: [AGT-06, AGT-08]
---

# WSTG Session Testing Skill

## 1. Purpose & Objective
Evaluates session token security and state management under OWASP WSTG Category 6:
- WSTG-SESS-01: Session management schema.
- WSTG-SESS-02: Cookie security attributes (`HttpOnly`, `Secure`, `SameSite`).
- WSTG-SESS-03: Session fixation.
- WSTG-SESS-05: Cross-Site Request Forgery (CSRF).
- WSTG-SESS-06: Logout session invalidation.

## 2. Execution Prerequisites
- Authentication profile configured with session cookie or token.

## 3. Authorized Scope Requirements
Targets must be verified in scope. Traffic routes through Egress Proxy.

## 4. Input & Output Contract
### Input Schema:
```json
{
  "project_id": "UUID",
  "base_url": "https://app.example.com",
  "auth_profile_id": "AUTH-01"
}
```
### Output Schema:
```json
{
  "cookie_findings": [
    {
      "cookie_name": "sessionid",
      "missing_attributes": ["HttpOnly", "SameSite"],
      "severity": "Low",
      "wstg_id": "WSTG-SESS-02"
    }
  ],
  "csrf_findings": [
    {
      "endpoint": "/api/v1/user/email",
      "method": "POST",
      "missing_csrf_token": true,
      "severity": "Medium",
      "wstg_id": "WSTG-SESS-05"
    }
  ]
}
```

## 5. Step-by-Step Execution Instructions
1. Inspect all `Set-Cookie` headers returned across authenticated sessions.
2. Flag any sensitive session cookie lacking `Secure` flag on HTTPS or lacking `HttpOnly` flag.
3. Test session fixation: inspect session token before and after login; assert token value rotates.
4. Test CSRF: send state-modifying POST request omitting CSRF header/token; check if request succeeds with standard cookies.
5. Test logout: invoke `/logout`; verify previous session token is rejected on subsequent requests.

## 6. Safety Constraints & Rate Limiting
- Non-intrusive metadata inspection; standard HTTP requests.

## 7. Evidence Requirements
- Raw `Set-Cookie` response headers and CSRF replay request/response pairs.

## 8. Error Handling & Fallbacks
- Distinguishes between tracking cookies (e.g. `_ga`) and sensitive authentication session tokens.

## 9. Validation Criteria
- Accurately identifies cookie attribute omissions and session lifecycle defects.

