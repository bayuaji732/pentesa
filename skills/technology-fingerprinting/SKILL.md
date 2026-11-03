---
name: technology-fingerprinting
version: 1.0.0
description: Identifies web servers, operating systems, frameworks, and client libraries using httpx and signature rules.
category: discovery
requires_scope_validation: true
requires_human_approval: false
risk_tier: low
tool_dependencies: [httpx]
agent_compatibility: [AGT-03, AGT-04]
---

# Technology Fingerprinting Skill

## 1. Purpose & Objective
Probes active web services to identify web servers (Nginx, Apache, Caddy), backend frameworks (Express, Django, Rails, Spring), frontend libraries (React, Angular, Vue), and third-party SaaS services to inform WSTG test planning.

## 2. Execution Prerequisites
- Discovered domains or endpoints in scope.

## 3. Authorized Scope Requirements
Target URLs validated against project scope. Probes route via Egress Proxy.

## 4. Input & Output Contract
### Input Schema:
```json
{
  "project_id": "UUID",
  "targets": ["https://app.example.com", "https://api.example.com"],
  "rate_limit": 25
}
```
### Output Schema:
```json
{
  "fingerprints": [
    {
      "target": "https://app.example.com",
      "web_server": "Nginx/1.24.0",
      "frameworks": ["Express.js", "Node.js"],
      "frontend": ["React", "Tailwind CSS"],
      "waf_detected": false
    }
  ]
}
```

## 5. Step-by-Step Execution Instructions
1. Validate target URLs against scope engine.
2. Build `httpx` command: `httpx -l <targets> -title -tech-detect -status-code -json -proxy http://pentesa-egress-proxy:8080`.
3. Spawn sandboxed subprocess and parse JSON stream.
4. Extract technology tokens and match against WSTG applicability rules.
5. Ingest technologies into `technologies` table.

## 6. Safety Constraints & Rate Limiting
- Minimal network footprint; standard single-request HTTP probing.

## 7. Evidence Requirements
- Stores raw response headers (`Server`, `X-Powered-By`) and matched HTML signatures.

## 8. Error Handling & Fallbacks
- On generic responses with stripped banners, falls back to cookie naming conventions (`connect.sid` $\to$ Express, `csrftoken` $\to$ Django).

## 9. Validation Criteria
- Accurately associates detected technologies with project record.
