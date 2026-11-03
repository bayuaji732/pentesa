---
name: endpoint-extraction
version: 1.0.0
description: Parses JavaScript ASTs and API specifications (OpenAPI/Swagger) to extract hidden endpoints and parameters.
category: discovery
requires_scope_validation: true
requires_human_approval: false
risk_tier: low
tool_dependencies: []
agent_compatibility: [AGT-04]
---

# Endpoint Extraction Skill

## 1. Purpose & Objective
Performs offline static analysis on discovered client-side JavaScript bundles and parses ingested OpenAPI/Swagger JSON/YAML documents to extract API routes, HTTP methods, and parameter schemas.

## 2. Execution Prerequisites
- Discovered `.js` script URLs or uploaded API specification files in the project.

## 3. Authorized Scope Requirements
Extracts endpoints only from assets originating from verified in-scope domains.

## 4. Input & Output Contract
### Input Schema:
```json
{
  "project_id": "UUID",
  "source_type": "JAVASCRIPT_BUNDLE | OPENAPI_SPEC",
  "source_path_or_url": "https://app.example.com/static/js/main.chunk.js"
}
```
### Output Schema:
```json
{
  "extracted_routes_count": 18,
  "routes": [
    {
      "path": "/api/v2/orders/{order_id}",
      "method": "GET",
      "parameters": [{ "name": "order_id", "in": "path" }]
    }
  ]
}
```

## 5. Step-by-Step Execution Instructions
1. For JavaScript files: Fetch the script body via the scope proxy.
2. Run AST tokenizer and regex scanners targeting API route patterns (`/api/...`, `fetch(...)`, `axios.get(...)`).
3. For OpenAPI specs: Ingest YAML/JSON and iterate through `paths` objects, extracting path keys, parameters, and operation methods.
4. Normalize parameterized path templates (e.g. converting `:id` or `{id}` to `{id}`).
5. Batch insert extracted routes into `endpoints` table.

## 6. Safety Constraints & Rate Limiting
- Purely passive static analysis; zero network packets sent during parsing.

## 7. Evidence Requirements
- Stores source file reference and AST extraction confidence.

## 8. Error Handling & Fallbacks
- On minified or obfuscated JS: Fall back to high-entropy string regex pattern matching.

## 9. Validation Criteria
- Valid routes and parameter signatures registered in `endpoints` inventory.

