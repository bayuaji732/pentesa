---
name: nuclei-scanning
version: 1.0.0
description: Runs curated Nuclei vulnerability templates against scope-validated endpoints.
category: testing
requires_scope_validation: true
requires_human_approval: false
risk_tier: medium
tool_dependencies: [nuclei]
agent_compatibility: [AGT-09]
---

# Nuclei Scanning Skill

## 1. Purpose & Objective
Executes community and custom Nuclei templates targeting known CVEs, outdated components, exposed sensitive panels, and cloud storage misconfigurations across scope-validated endpoints.

## 2. Execution Prerequisites
- Scope-validated endpoints in inventory.
- Pre-installed vetted Nuclei template library.

## 3. Authorized Scope Requirements
Every scanned URL must pass `scope-validation`. Outbound requests route through Egress Proxy.

## 4. Input & Output Contract
### Input Schema:
```json
{
  "project_id": "UUID",
  "target_url": "https://app.example.com",
  "template_tags": ["cve", "misconfig", "exposure"],
  "severity_filter": ["medium", "high", "critical"],
  "rate_limit": 20
}
```
### Output Schema:
```json
{
  "detections_count": 2,
  "detections": [
    {
      "template_id": "CVE-2023-XXXX",
      "name": "Component Outdated Remote Code Execution",
      "severity": "critical",
      "matched_url": "https://app.example.com/vendor/framework/",
      "curl_command": "curl -X GET 'https://app.example.com/vendor/framework/'",
      "raw_request": "GET /vendor/framework/ HTTP/1.1...",
      "raw_response": "HTTP/1.1 200 OK..."
    }
  ]
}
```

## 5. Step-by-Step Execution Instructions
1. Validate `target_url` against scope engine.
2. Build `nuclei` command:
   `nuclei -target <url> -tags <tags> -severity <severity> -rate-limit 20 -jsonl -proxy http://pentesa-egress-proxy:8080 -no-interactsh`
3. Execute sandboxed subprocess.
4. Stream JSONL output, extracting matched templates, raw requests, and curl commands.
5. Ingest detections as candidate findings for validation.

## 6. Safety Constraints & Rate Limiting
- Heavy DoS and fuzzing templates are excluded. Rate limit strictly enforced.

## 7. Evidence Requirements
- Raw request and response bytes captured directly by Nuclei output.

## 8. Error Handling & Fallbacks
- Handles template syntax errors gracefully; continues remaining templates.

## 9. Validation Criteria
- Accurately captures candidate detections with working reproduction details.
