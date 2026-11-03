---
name: evidence-collection
version: 1.0.0
description: Packages verified findings with raw HTTP streams, SHA-256 integrity hashes, PII redaction, and DOM screenshots.
category: validation
requires_scope_validation: true
requires_human_approval: false
risk_tier: low
tool_dependencies: [playwright, sha256_hasher]
agent_compatibility: [AGT-13]
---

# Evidence Collection Skill

## 1. Purpose & Objective
Packages confirmed security vulnerabilities into forensic-grade proof packages. Captures exact raw HTTP request/response bytes, generates SHA-256 verification hashes, masks sensitive credentials, and captures headless browser screenshots for client-side vulnerabilities.

## 2. Execution Prerequisites
- A confirmed finding record with raw transmission data.

## 3. Authorized Scope Requirements
Internal file creation and local Playwright browser execution strictly within container sandbox.

## 4. Input & Output Contract
### Input Schema:
```json
{
  "finding_id": "UUID",
  "raw_request": "POST /api/v1/login HTTP/1.1\r\nAuthorization: Bearer secret_token_xyz...",
  "raw_response": "HTTP/1.1 200 OK\r\n...",
  "reproduction_curl": "curl -X POST ...",
  "capture_screenshot": true,
  "screenshot_url": "https://app.example.com/search?q=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E"
}
```
### Output Schema:
```json
{
  "evidence_id": "UUID",
  "sanitized_request": "POST /api/v1/login HTTP/1.1\r\nAuthorization: Bearer [REDACTED]...",
  "request_hash_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
  "response_hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "screenshot_file_path": "/var/pentesa/evidence/FINDING_UUID.png"
}
```

## 5. Step-by-Step Execution Instructions
1. Ingest raw HTTP request and response strings.
2. Execute automated PII redaction (masking Authorization tokens, passwords, credit card PANs).
3. Compute cryptographic SHA-256 digests over the sanitized byte streams.
4. If client-side finding: launch headless Chromium via Playwright, render proof-of-concept URL, capture viewport screenshot, and save to `/var/pentesa/evidence/`.
5. Persist evidence record into `finding_evidence` table linking to the parent finding.

## 6. Safety Constraints & Rate Limiting
- Playwright browser execution runs in an isolated container without network access except to the validated target.

## 7. Evidence Requirements
- Stores raw strings, SHA-256 hashes, file paths, and capture timestamps.

## 8. Error Handling & Fallbacks
- If screenshot engine times out, stores text evidence and logs non-fatal warning.

## 9. Validation Criteria
- Complete forensic proof package assembled and cryptographically sealed.
