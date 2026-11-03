---
name: web-crawling
version: 1.0.0
description: Crawls web applications within scope boundaries using katana to extract endpoints, forms, and assets.
category: discovery
requires_scope_validation: true
requires_human_approval: false
risk_tier: low
tool_dependencies: [katana]
agent_compatibility: [AGT-04]
---

# Web Crawling Skill

## 1. Purpose & Objective
Spiders in-scope web applications to discover hyperlinks, form actions, API routes, and client-side JavaScript bundles, cataloging them into the Central Endpoint Inventory.

## 2. Execution Prerequisites
- Target seed URLs verified in scope.
- Optional authentication profile for authenticated crawling.

## 3. Authorized Scope Requirements
- The crawler must be configured with `HTTP_PROXY` routing through the Scope Egress Proxy.
- Crawl depth strictly constrained (default: 3, max: 5).

## 4. Input & Output Contract
### Input Schema:
```json
{
  "project_id": "UUID",
  "seed_url": "https://app.example.com/",
  "crawl_depth": 3,
  "rate_limit": 15,
  "headless": false
}
```
### Output Schema:
```json
{
  "total_endpoints_found": 52,
  "endpoints": [
    {
      "url_path": "/api/v1/profile",
      "method": "GET",
      "parameters": ["user_id"],
      "content_type": "application/json"
    }
  ]
}
```

## 5. Step-by-Step Execution Instructions
1. Validate `seed_url` against `scope-validation`.
2. Construct safe execution arguments for `katana`:
   `katana -u <seed_url> -depth 3 -rate-limit 15 -jsonl -proxy http://pentesa-egress-proxy:8080`
3. Execute sandboxed subprocess.
4. Stream JSONL output, extracting URL paths, HTTP methods, and query strings.
5. Ingest valid discovered routes into `endpoints` table, deduplicating matching routes.

## 6. Safety Constraints & Rate Limiting
- Rate limit capped at project maximum (default 15 RPS).
- Excluded paths (e.g. `/logout`, `/admin/purge`) filtered out of crawling queue.
- Static media extensions (`.png`, `.jpg`, `.woff2`) ignored to conserve bandwidth.

## 7. Evidence Requirements
- Discovered URLs, methods, and parent referrers stored in `endpoints` table.

## 8. Error Handling & Fallbacks
- If target returns HTTP 429 Too Many Requests, throttle crawler rate by 50%.

## 9. Validation Criteria
- Discovered endpoints written to database with valid HTTP methods and parameter lists.
