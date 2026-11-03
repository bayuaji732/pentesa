---
name: parameter-discovery
version: 1.0.0
description: Discovers unlinked query parameters and request body keys accepted by web endpoints.
category: discovery
requires_scope_validation: true
requires_human_approval: false
risk_tier: low
tool_dependencies: [ffuf]
agent_compatibility: [AGT-04, AGT-10]
---

# Parameter Discovery Skill

## 1. Purpose & Objective
Identifies hidden, undocumented, or debug query parameters (e.g. `debug=true`, `admin=1`, `redirect_to=...`) accepted by web endpoints to expand the attack surface for injection and authorization testing.

## 2. Execution Prerequisites
- Validated target endpoint in `endpoints` inventory.

## 3. Authorized Scope Requirements
Endpoint URL must be pre-validated by `scope-validation`. Fuzzing traffic routes through Egress Proxy.

## 4. Input & Output Contract
### Input Schema:
```json
{
  "project_id": "UUID",
  "endpoint_url": "https://app.example.com/api/v1/search",
  "method": "GET",
  "wordlist": "params_top1000",
  "rate_limit": 20
}
```
### Output Schema:
```json
{
  "discovered_parameters": [
    { "name": "debug", "location": "query", "differential_behavior": "Enables verbose timing" },
    { "name": "format", "location": "query", "differential_behavior": "Changes response to XML" }
  ]
}
```

## 5. Step-by-Step Execution Instructions
1. Establish baseline response: Send normal GET request to endpoint and record status code, content-length, and word count.
2. Formulate parameterized fuzzing template: `https://app.example.com/api/v1/search?FUZZ=test`.
3. Execute `ffuf` with baseline reflection filtering (`-fs <baseline_size>`, `-fw <baseline_words>`).
4. Analyze anomalous responses that deviate from baseline.
5. Register discovered parameters into the endpoint's `parameter_schema` in the database.

## 6. Safety Constraints & Rate Limiting
- Rate limit capped at 20 RPS. Circuit breaker triggers if error rate exceeds 10%.

## 7. Evidence Requirements
- Differential response lengths and HTTP status codes recorded in tool log.

## 8. Error Handling & Fallbacks
- Automatically calibrates soft-404 and uniform response page size filters.

## 9. Validation Criteria
- Discovered parameters produce verifiable differential server behavior.
