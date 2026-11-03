---
name: controlled-fuzzing
version: 1.0.0
description: Executes controlled parameter fuzzing with rate limits and circuit breaker monitoring using ffuf.
category: testing
requires_scope_validation: true
requires_human_approval: true
risk_tier: high
tool_dependencies: [ffuf]
agent_compatibility: [AGT-10]
---

# Controlled Fuzzing Skill

## 1. Purpose & Objective
Executes targeted parameter fuzzing using structured boundary-value and exception-trigger wordlists to surface unhandled exceptions, memory dumps, and hidden behaviors.

## 2. Execution Prerequisites
- Discovered endpoint with controllable parameter.

## 3. Authorized Scope Requirements
Endpoint URL must be pre-validated by `scope-validation`. Fuzzing traffic routes via Egress Proxy.

## 4. Input & Output Contract
### Input Schema:
```json
{
  "project_id": "UUID",
  "target_url": "https://app.example.com/api/v1/order?id=FUZZ",
  "wordlist": "numeric_boundaries_1000",
  "rate_limit": 20
}
```
### Output Schema:
```json
{
  "anomalous_responses": [
    {
      "payload": "-1",
      "status_code": 500,
      "response_snippet": "Unhandled IntegerUnderflowException in billing.py line 42"
    }
  ]
}
```

## 5. Step-by-Step Execution Instructions
1. Verify endpoint is in scope and not in exclusion patterns.
2. If total requests planned $> 5,000$, suspend and require human approval.
3. Configure `ffuf` with rate limit (default 20 RPS) and baseline status filters.
4. Execute sandboxed subprocess.
5. Ingest anomalous responses (e.g. 500 Internal Error, unexpected 200 responses) into candidate findings.

## 6. Safety Constraints & Rate Limiting
- Hard cap at 50 RPS under all circumstances.
- Circuit breaker: Halts if target error rate exceeds 10% over 60 seconds.

## 7. Evidence Requirements
- Injected payload, returned status code, and error trace snippet.

## 8. Error Handling & Fallbacks
- Implements exponential backoff on HTTP 429 Too Many Requests.

## 9. Validation Criteria
- Surfaces reproducible error conditions without causing denial-of-service.

