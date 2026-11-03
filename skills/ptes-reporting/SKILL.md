---
name: ptes-reporting
version: 1.0.0
description: Generates formal, publication-ready Penetration Testing Execution Standard (PTES) reports in PDF and standalone HTML formats.
category: reporting
requires_scope_validation: false
requires_human_approval: false
risk_tier: low
tool_dependencies: [weasyprint, jinja2]
agent_compatibility: [AGT-15]
---

# PTES Reporting Skill

## 1. Purpose & Objective
Compiles verified project metadata, scope rules, attack surface summaries, WSTG coverage calculations, approved technical findings, forensic evidence dumps, and remediation guidance into formal, client-ready PTES deliverables in PDF and HTML formats.

## 2. Execution Prerequisites
- An active project with verified findings and completed WSTG test plan.

## 3. Authorized Scope Requirements
Local document compilation and rendering; zero outbound network activity.

## 4. Input & Output Contract
### Input Schema:
```json
{
  "project_id": "UUID",
  "report_format": "PDF | HTML",
  "template_name": "ptes_standard",
  "include_raw_evidence": true,
  "operator_name": "Jane Doe, Lead Tester"
}
```
### Output Schema:
```json
{
  "report_id": "UUID",
  "file_path": "/var/pentesa/reports/Pentesa_Report_ProjectX_20261103.pdf",
  "file_size_bytes": 1845210,
  "file_hash_sha256": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
  "generated_at": "2026-11-03T16:20:00Z"
}
```

## 5. Step-by-Step Execution Instructions
1. Query database for project metadata, scope whitelist, and RoE dates.
2. Calculate final WSTG category coverage percentages.
3. Query all `Confirmed` findings along with sanitized evidence, reproduction `curl` commands, and CVSS v3.1 scores.
4. Synthesize executive summary narrative highlighting business risk posture.
5. Ingest data into Jinja2 template and compile HTML document.
6. If PDF requested: invoke WeasyPrint to compile HTML + CSS Paged Media into pixel-perfect PDF.
7. Compute SHA-256 hash of compiled file, write record to `reports` table, and freeze project snapshot.

## 6. Safety Constraints & Rate Limiting
- HTML auto-escaping enforced across all template variables to prevent template injection or XSS in generated reports.

## 7. Evidence Requirements
- Stores generated document file path, file size, publication timestamp, and SHA-256 hash.

## 8. Error Handling & Fallbacks
- If WeasyPrint encounters complex CSS overflow, falls back to simplified print layout and logs warning.

## 9. Validation Criteria
- Produces complete, visually polished, and cryptographically hashed PTES document.

