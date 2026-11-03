---
name: false-positive-analysis
version: 1.0.0
description: Evaluates refuted candidate findings using contextual heuristics to document why an alert was noise and suppress it.
category: validation
requires_scope_validation: false
requires_human_approval: false
risk_tier: low
tool_dependencies: []
agent_compatibility: [AGT-12]
---

# False Positive Analysis Skill

## 1. Purpose & Objective
Performs contextual analysis on scanner or agent alerts that failed empirical reproduction, classifying the cause of the false alert (e.g. static string reflection, WAF blocking page, dynamic page timestamps) and documenting technical justification to suppress noise from final reports.

## 2. Execution Prerequisites
- A candidate finding record with failed reproduction attempt.

## 3. Authorized Scope Requirements
Offline analytical evaluation; zero outbound network packets.

## 4. Input & Output Contract
### Input Schema:
```json
{
  "project_id": "UUID",
  "candidate_finding_id": "UUID",
  "triggering_payload": "' OR 1=1--",
  "failed_reproduction_trace": "HTTP/1.1 200 OK (Identical to baseline)"
}
```
### Output Schema:
```json
{
  "is_false_positive": true,
  "classification": "STATIC_REFLECTION_NO_EXECUTION",
  "justification": "Input is reflected verbatim inside an educational help section; parameter does not reach any database query context.",
  "recommended_action": "Mark as False Positive; suppress from PTES report."
}
```

## 5. Step-by-Step Execution Instructions
1. Ingest candidate finding and failed reproduction traces.
2. Compare baseline response with probe response using diff heuristics.
3. Test for common false positive patterns:
   - Reflection in static text without context escape.
   - Uniform WAF block page returned on all inputs.
   - Dynamic page elements (timestamps, CSRF tokens, random IDs) creating artificial diffs.
4. If false positive confirmed: update finding status to `False Positive`, insert record into `false_positives` table, and suppress from client deliverables.
5. If ambiguous: update finding status to `Needs Manual Review` for operator judgment.

## 6. Safety Constraints & Rate Limiting
- Purely internal computational reasoning; zero risk to target applications.

## 7. Evidence Requirements
- Records classification category, technical justification, and comparator response diffs.

## 8. Error Handling & Fallbacks
- When in doubt, routes to `Needs Manual Review` rather than prematurely closing.

## 9. Validation Criteria
- Accurately classifies and documents scanner noise with auditable reasoning.
