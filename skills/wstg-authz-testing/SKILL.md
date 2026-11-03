---
name: wstg-authz-testing
version: 1.0.0
description: Tests Broken Object Level Authorization (BOLA/IDOR), vertical privilege escalation, and path traversal (WSTG-ATHZ-01 to 04).
category: testing
requires_scope_validation: true
requires_human_approval: false
risk_tier: medium
tool_dependencies: [multi_identity_prober]
agent_compatibility: [AGT-07]
---

# WSTG Authorization Testing Skill

## 1. Purpose & Objective
Assesses access control boundaries across identities and role tiers according to OWASP WSTG Category 5:
- WSTG-ATHZ-01: Directory traversal / file include.
- WSTG-ATHZ-02: Bypassing authorization schema.
- WSTG-ATHZ-03: Privilege escalation (vertical).
- WSTG-ATHZ-04: Insecure Direct Object References (IDOR/BOLA).

## 2. Execution Prerequisites
- At least two distinct authenticated user profiles (Identity A and Identity B, e.g. Tenant A User vs Tenant B User).
- Discovered object resource routes (e.g. `/api/v1/orders/{id}`, `/api/v1/documents/{doc_id}`).

## 3. Authorized Scope Requirements
Testing strictly uses client-provided test tenant credentials. Traffic routes through Egress Proxy.

## 4. Input & Output Contract
### Input Schema:
```json
{
  "project_id": "UUID",
  "endpoint": "/api/v1/documents/1042",
  "method": "GET",
  "owner_identity": "Tenant-A",
  "attacker_identity": "Tenant-B"
}
```
### Output Schema:
```json
{
  "is_vulnerable": true,
  "vulnerability_type": "BOLA_IDOR",
  "wstg_id": "WSTG-ATHZ-04",
  "severity": "High",
  "evidence": "Tenant-B received HTTP 200 containing Tenant-A private document body."
}
```

## 5. Step-by-Step Execution Instructions
1. Record resource IDs discovered during Identity A's crawl (e.g. `doc_id=1042`).
2. Replay the exact request replacing Identity A's Authorization token / cookie with Identity B's credentials.
3. Compare response status codes and body lengths.
4. If Identity B receives HTTP 200 with Identity A's object data, flag IDOR anomaly.
5. Replay administrative routes with standard user credentials to test vertical privilege escalation (WSTG-ATHZ-02).

## 6. Safety Constraints & Rate Limiting
- Strictly read-only operations for automated replay. Destructive operations (DELETE / PUT) require operator sign-off.

## 7. Evidence Requirements
- Stacked raw HTTP traces: Request with Token B, Response with 200 OK + private resource.

## 8. Error Handling & Fallbacks
- Detects false positives caused by publicly accessible resources by verifying that an unauthenticated request returns HTTP 401/403.

## 9. Validation Criteria
- Confirmed access to unauthorized objects across tenant boundaries.

