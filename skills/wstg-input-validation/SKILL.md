---
name: wstg-input-validation
version: 1.0.0
description: Tests input vectors against SQL Injection, XSS, Command Injection, Template Injection, and SSRF (WSTG-INPV-01 to 19).
category: testing
requires_scope_validation: true
requires_human_approval: false
risk_tier: high
tool_dependencies: [diff_prober, payload_evaluator]
agent_compatibility: [AGT-08]
---

# WSTG Input Validation Skill

## 1. Purpose & Objective
Evaluates application parameters against injection vulnerabilities under OWASP WSTG Category 7:
- WSTG-INPV-01: Reflected Cross-Site Scripting (XSS).
- WSTG-INPV-05: SQL Injection (SQLi) — Error-based, Boolean-based, and Time-based.
- WSTG-INPV-12: Command Injection.
- WSTG-INPV-17: Server-Side Template Injection (SSTI).
- WSTG-INPV-18: Server-Side Request Forgery (SSRF).

## 2. Execution Prerequisites
- Parameterized endpoint registered in `endpoints` inventory.

## 3. Authorized Scope Requirements
Endpoint URL must be verified in scope. Outbound traffic routed through Egress Proxy.

## 4. Input & Output Contract
### Input Schema:
```json
{
  "project_id": "UUID",
  "endpoint_url": "https://app.example.com/api/v1/search",
  "method": "GET",
  "target_parameter": "q",
  "test_classes": ["SQLI", "XSS", "SSTI"]
}
```
### Output Schema:
```json
{
  "anomaly_detected": true,
  "vulnerability_type": "SQL_INJECTION",
  "wstg_id": "WSTG-INPV-05",
  "parameter": "q",
  "triggering_payload": "1' AND (SELECT 1 FROM pg_sleep(5))--",
  "response_delay_ms": 5080
}
```

## 5. Step-by-Step Execution Instructions
1. Record baseline response timing and body hash.
2. For XSS: Send benign alphanumeric canary (e.g. `pentesa99142xss`) to observe reflection context (HTML, attribute, JavaScript block).
3. If unescaped reflection occurs, test minimal benign proof-of-concept (`"><script>alert(1)</script>`).
4. For SQLi: Transmit benign syntax break characters (`'`, `"`, `\`): check for database error reflections.
5. Transmit differential timing payload (`pg_sleep(5)` or `sleep(5)`): assert delay $> 4,500\text{ ms}$.
6. For SSTI: Transmit benign math expressions (`{{7*7}}`, `${7*7}`): check for reflection of `49`.
7. Package anomalous probe traces and pass to `vulnerability-validation` skill.

## 6. Safety Constraints & Rate Limiting
- Destructive SQL payloads (`DROP`, `DELETE`, `TRUNCATE`, `UPDATE`) strictly forbidden.
- Sleep durations capped at 5 seconds; max 3 sleep attempts per parameter.
- Rate limit capped at 15 RPS.

## 7. Evidence Requirements
- Raw request with injected payload and raw response showing reflection or timing proof.

## 8. Error Handling & Fallbacks
- Throttles immediately if target returns continuous HTTP 500 errors.

## 9. Validation Criteria
- Deterministic reproduction of reflection, calculation, or timing differential.
