---
name: scope-validation
version: 1.0.0
description: Validates candidate targets, URLs, hostnames, and IP addresses against authorized project scope boundaries.
category: governance
requires_scope_validation: false
requires_human_approval: false
risk_tier: low
tool_dependencies: []
agent_compatibility: [AGT-02, AGT-01, AGT-04, AGT-08, AGT-11]
---

# Scope Validation Skill

## 1. Purpose & Objective
This skill evaluates any destination URL, hostname, or IP address against the project's configured scope targets (domains, wildcards, CIDRs) and exclusion rules (path regexes, excluded hosts) to guarantee that zero out-of-scope packets are transmitted.

## 2. Execution Prerequisites
- An active project record with populated `scope_targets` and `scope_exclusions` tables.
- Validated project authorization window (`auth_start_date` $\le$ `now` $\le$ `auth_end_date`).

## 3. Authorized Scope Requirements
This skill is the authority that computes scope validity. It performs read-only database queries and DNS lookups.

## 4. Input & Output Contract
### Input Schema:
```json
{
  "project_id": "UUID",
  "candidate_url": "https://app.example.com/api/v1/users",
  "check_exclusions": true
}
```
### Output Schema:
```json
{
  "is_allowed": true,
  "resolved_ip": "192.168.1.10",
  "matched_target_id": "UUID",
  "is_excluded": false,
  "reason": "Matches in-scope wildcard *.example.com"
}
```

## 5. Step-by-Step Execution Instructions
1. Parse `candidate_url` into scheme, hostname, port, and path according to RFC 3986.
2. Verify protocol scheme is either `http` or `https`.
3. Test normalized path against compiled `scope_exclusions` regular expressions. If matched, return `is_allowed: false, reason: "Path matches exclusion regex"`.
4. Test hostname against `scope_targets` (exact match and wildcard suffix matching).
5. Resolve hostname to IPv4/IPv6 using isolated resolver.
6. Check resolved IP against loopback (`127.0.0.1`), metadata services (`169.254.169.254`), and private CIDRs. Reject unless project scope explicitly authorizes internal ranges.
7. Return boolean validation decision and log event to `scope_validations`.

## 6. Safety Constraints & Rate Limiting
- Fail-Closed: If DNS resolution times out or returns unparseable records, return `is_allowed: false`.

## 7. Evidence Requirements
- Log evaluated URL, resolved IP, timestamp, and boolean decision to `scope_validations` table.

## 8. Error Handling & Fallbacks
- On DNS lookup failure: Log `DNS_RESOLUTION_ERROR` and return `is_allowed: false`.

## 9. Validation Criteria
- Target is strictly within approved scope and outside all exclusion patterns.

