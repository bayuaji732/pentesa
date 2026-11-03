---
name: hidden-path-discovery
version: 1.0.0
description: Discovers unlinked admin routes, backup files, and hidden directories using ffuf.
category: discovery
requires_scope_validation: true
requires_human_approval: false
risk_tier: medium
tool_dependencies: [ffuf]
agent_compatibility: [AGT-10]
---

# Hidden Path Discovery Skill

## 1. Purpose & Objective
Performs controlled, rate-limited directory and file brute-forcing using `ffuf` to discover exposed backup files (`.bak`, `.env`, `.git`), internal admin dashboards, and unreferenced endpoints.

## 2. Execution Prerequisites
- Target base URL verified in scope.
- Pre-compiled wordlist (e.g. `common_paths_5000.txt`).

## 3. Authorized Scope Requirements
The target root URL must be validated by `scope-validation`. Outbound fuzzing traffic routes through Egress Proxy.

## 4. Input & Output Contract
### Input Schema:
```json
{
  "project_id": "UUID",
  "base_url": "https://app.example.com/",
  "wordlist": "common_paths_5000",
  "rate_limit": 20,
  "filter_status": [404]
}
```
### Output Schema:
```json
{
  "discovered_paths_count": 4,
  "discovered_paths": [
    { "path": "/admin/metrics", "status_code": 200, "content_length": 4120 },
    { "path": "/.env", "status_code": 403, "content_length": 154 }
  ]
}
```

## 5. Step-by-Step Execution Instructions
1. Validate `base_url` against scope engine.
2. Probe non-existent random path (e.g. `/random_xyz_404_test`) to evaluate custom 404 page behavior.
3. Build `ffuf` command with calibrated filter flags (`-fc 404`, `-rate 20`).
4. Execute sandboxed subprocess.
5. Ingest HTTP 200, 301, 302, and 403 responses into `endpoints` inventory.

## 6. Safety Constraints & Rate Limiting
- Rate limit capped at 20 RPS. Fuzzing aborts immediately if target returns $> 10\%$ server errors (500/502/503).
- Requires operator approval if wordlist exceeds 5,000 words.

## 7. Evidence Requirements
- Stores discovered path, HTTP response code, content length, and response time.

## 8. Error Handling & Fallbacks
- Automatically throttles if rate limit headers (`Retry-After`) are returned.

## 9. Validation Criteria
- Discovered paths return valid, accessible HTTP responses within scope boundaries.

