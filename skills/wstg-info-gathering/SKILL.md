---
name: wstg-info-gathering
version: 1.0.0
description: Executes OWASP WSTG Information Gathering tests (WSTG-INFO-01 through 10).
category: testing
requires_scope_validation: true
requires_human_approval: false
risk_tier: low
tool_dependencies: [httpx, katana]
agent_compatibility: [AGT-03, AGT-05]
---

# WSTG Information Gathering Skill

## 1. Purpose & Objective
Executes standard tests under OWASP WSTG Category 1 (Information Gathering):
- WSTG-INFO-01: Search engine reconnaissance.
- WSTG-INFO-02: Web server fingerprinting.
- WSTG-INFO-03: Review metafiles (`robots.txt`, `sitemap.xml`, `security.txt`).
- WSTG-INFO-05: Review webpage content and HTML comments for information leaks.
- WSTG-INFO-08: Fingerprint web application framework.

## 2. Execution Prerequisites
- Project initialized with target endpoints and scope confirmed.

## 3. Authorized Scope Requirements
All probes must target authorized hostnames via the Scope Egress Proxy.

## 4. Input & Output Contract
### Input Schema:
```json
{
  "project_id": "UUID",
  "base_url": "https://app.example.com",
  "test_ids": ["WSTG-INFO-02", "WSTG-INFO-03", "WSTG-INFO-05"]
}
```
### Output Schema:
```json
{
  "results": [
    {
      "wstg_id": "WSTG-INFO-03",
      "status": "Failed",
      "finding_title": "Sensitive Administrative Routes Disclosed in robots.txt",
      "severity": "Low",
      "evidence": "Disallow: /internal-admin-portal-v2/"
    }
  ]
}
```

## 5. Step-by-Step Execution Instructions
1. Fetch `/robots.txt`, `/sitemap.xml`, and `/.well-known/security.txt`.
2. Inspect entries for disallow rules exposing unlinked sensitive routes; add discovered routes to endpoint queue.
3. Parse HTML responses and JavaScript bundles for developer comments, debug flags, and staging URLs.
4. Update `wstg_test_instances` statuses (`Passed` or `Failed`).

## 6. Safety Constraints & Rate Limiting
- Low volume HTTP GET requests; rate capped at 15 RPS.

## 7. Evidence Requirements
- Raw HTTP request/response text for discovered metafiles and comments.

## 8. Error Handling & Fallbacks
- Missing metafiles (`404 Not Found`) mark tests as `Passed` (secure default).

## 9. Validation Criteria
- All requested WSTG-INFO test instances updated with auditable statuses.

