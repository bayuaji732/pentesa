---
name: subdomain-discovery
version: 1.0.0
description: Discovers passive subdomains and certificates using subfinder without sending packets to target infrastructure.
category: reconnaissance
requires_scope_validation: true
requires_human_approval: false
risk_tier: low
tool_dependencies: [subfinder]
agent_compatibility: [AGT-03]
---

# Subdomain Discovery Skill

## 1. Purpose & Objective
Performs passive OSINT-based subdomain enumeration for authorized target domains using Certificate Transparency logs, search engine indices, and public DNS datasets via the `subfinder` engine.

## 2. Execution Prerequisites
- Project root domain defined in `scope_targets`.
- Valid network connectivity to public CT log aggregators.

## 3. Authorized Scope Requirements
All discovered subdomains must be verified against `scope-validation` before being registered in the `discovered_domains` database table.

## 4. Input & Output Contract
### Input Schema:
```json
{
  "project_id": "UUID",
  "root_domain": "example.com",
  "timeout_seconds": 120
}
```
### Output Schema:
```json
{
  "total_discovered": 14,
  "subdomains": [
    { "fqdn": "app.example.com", "source": "cert_transparency" },
    { "fqdn": "api.example.com", "source": "subfinder" }
  ]
}
```

## 5. Step-by-Step Execution Instructions
1. Verify `root_domain` is authorized in project scope.
2. Compile typed execution arguments for `subfinder`:
   `subfinder -d <root_domain> -json -silent -timeout 10`
3. Spawn sandboxed subprocess with `asyncio.create_subprocess_exec`.
4. Stream and parse JSON line outputs.
5. For each discovered hostname, invoke `scope-validation`.
6. Batch insert valid in-scope subdomains into `discovered_domains`.

## 6. Safety Constraints & Rate Limiting
- Strictly passive: No direct TCP or DNS packets sent to target infrastructure.

## 7. Evidence Requirements
- Discovered FQDN, discovery source, and timestamp recorded in database.

## 8. Error Handling & Fallbacks
- If external passive APIs time out, proceed with already discovered subdomains without crashing the workflow.

## 9. Validation Criteria
- At least the root domain or verified subdomains are cataloged.

