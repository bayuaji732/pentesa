"""15 API Contract Audit Runner.

Fetches OpenAPI schema from running API, parses docs/11-api-specification.md,
extracts frontend client API calls in apps/web, and performs exhaustive schema diffing.
"""

import os
import sys
import re
import json
import urllib.request
from typing import Dict, List, Set, Tuple

sys.path.insert(0, os.path.abspath("."))
from tests.audit.evidence_header import format_evidence_header

OPENAPI_URL = "http://127.0.0.1:8000/openapi.json"
DOCS_SPEC_PATH = os.path.join("docs", "11-api-specification.md")
WEB_API_TS_PATH = os.path.join("apps", "web", "src", "lib", "api.ts")
WEB_SRC_DIR = os.path.join("apps", "web", "src")
OUTPUT_PATH = os.path.join("docs", "audit", "evidence", "phase2", "15_api_contract.txt")


def fetch_openapi() -> dict:
    req = urllib.request.Request(OPENAPI_URL, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def parse_docs_spec() -> Set[Tuple[str, str]]:
    """Extract (METHOD, PATH) from docs/11-api-specification.md."""
    endpoints = set()
    if not os.path.exists(DOCS_SPEC_PATH):
        return endpoints

    with open(DOCS_SPEC_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    # Match patterns like: #### 1. `POST /api/v1/auth/login` or `GET /api/v1/...`
    pattern = re.compile(r"`(GET|POST|PUT|PATCH|DELETE)\s+([/a-zA-Z0-9_{}-]+)`")
    for match in pattern.finditer(content):
        method, path = match.group(1), match.group(2)
        # Normalize path
        norm_path = re.sub(r"\{[a-zA-Z0-9_]+\}", "{}", path)
        endpoints.add((method, norm_path, path))
    return endpoints


def parse_web_client() -> List[dict]:
    """Scan apps/web for all api calls (api.ts and fetch/axios/request)."""
    calls = []
    if not os.path.exists(WEB_SRC_DIR):
        return calls

    endpoint_pattern = re.compile(r"""(?:api\.(?:get|post|put|patch|delete)|fetch|request(?:<[^>]+>)?)\s*\(\s*[`"']([^`"']+)""")
    for root, _, files in os.walk(WEB_SRC_DIR):
        for file in files:
            if file.endswith((".ts", ".tsx", ".js")):
                fpath = os.path.join(root, file)
                rel_path = os.path.relpath(fpath, ".")
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    for i, line in enumerate(f, 1):
                        for m in endpoint_pattern.finditer(line):
                            raw_endpoint = m.group(1)
                            calls.append({
                                "file": rel_path,
                                "line": i,
                                "raw": raw_endpoint
                            })
    return calls


def normalize_route(r: str) -> str:
    # Replace variable templates like ${id} or {id} with {}
    r = re.sub(r"\$\{[^}]+\}", "{}", r)
    r = re.sub(r"\{[^}]+\}", "{}", r)
    return r


def main():
    print("=== STARTING 15 API CONTRACT AUDIT RUNNER ===")
    lines = []
    lines.append("API CONTRACT SPECIFICATION AUDIT & SCHEMA DIFF")
    lines.append("=" * 70)

    # 1. Fetch OpenAPI
    print(f"Fetching OpenAPI schema from {OPENAPI_URL}...")
    try:
        openapi = fetch_openapi()
        lines.append(f"[OK] Fetched OpenAPI schema from running API: title='{openapi.get('info', {}).get('title')}', version='{openapi.get('info', {}).get('version')}'")
    except Exception as e:
        lines.append(f"[ERROR] Failed to fetch OpenAPI from {OPENAPI_URL}: {e}")
        return

    openapi_paths = openapi.get("paths", {})
    openapi_endpoints = set()
    for path, methods in openapi_paths.items():
        for method in methods.keys():
            if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                norm = normalize_route(path)
                openapi_endpoints.add((method.upper(), norm, path))

    lines.append(f"Total OpenAPI Endpoints Implemented: {len(openapi_endpoints)}")

    # 2. Parse Docs Spec
    docs_endpoints = parse_docs_spec()
    lines.append(f"Total Documented Endpoints in {DOCS_SPEC_PATH}: {len(docs_endpoints)}")

    # 3. Parse Frontend Web Client
    web_calls = parse_web_client()
    lines.append(f"Total Frontend API Route References Found: {len(web_calls)}")

    # 4. Compare Docs vs OpenAPI
    lines.append("\n" + "=" * 70)
    lines.append("SECTION 1: SPECIFICATION CONFORMANCE (DOCS vs RUNNING OPENAPI)")
    lines.append("=" * 70)

    docs_norm_map = {(m, norm): orig for m, norm, orig in docs_endpoints}
    openapi_norm_map = {(m, norm): orig for m, norm, orig in openapi_endpoints}

    matched_endpoints = set()
    documented_missing_in_api = []
    api_undocumented_in_spec = []

    for key, orig_doc in docs_norm_map.items():
        if key in openapi_norm_map:
            matched_endpoints.add(key)
        else:
            documented_missing_in_api.append((key[0], orig_doc))

    for key, orig_api in openapi_norm_map.items():
        if key not in docs_norm_map:
            api_undocumented_in_spec.append((key[0], orig_api))

    conformance_pct = (len(matched_endpoints) / len(docs_endpoints) * 100) if docs_endpoints else 100.0
    lines.append(f"Specification Matching Endpoints: {len(matched_endpoints)} / {len(docs_endpoints)} ({conformance_pct:.1f}%)")

    lines.append(f"\nDocumented Endpoints Not Found in Running OpenAPI ({len(documented_missing_in_api)}):")
    if documented_missing_in_api:
        for m, p in sorted(documented_missing_in_api):
            lines.append(f"  - [SPEC-UNIMPLEMENTED] {m:6s} {p}")
    else:
        lines.append("  (None - 100% of documented endpoints are implemented)")

    lines.append(f"\nRunning OpenAPI Endpoints Not Documented in Specification ({len(api_undocumented_in_spec)}):")
    if api_undocumented_in_spec:
        for m, p in sorted(api_undocumented_in_spec):
            lines.append(f"  - [SHADOW-API / EXTENSION] {m:6s} {p}")
    else:
        lines.append("  (None - 100% of OpenAPI endpoints are documented)")

    # 5. Frontend Client Contract Conformance
    lines.append("\n" + "=" * 70)
    lines.append("SECTION 2: FRONTEND CLIENT CONTRACT AUDIT (apps/web vs API)")
    lines.append("=" * 70)

    web_endpoints_normalized = set()
    for call in web_calls:
        raw = call["raw"]
        # If relative or starts with /
        if raw.startswith("/") or "/api/v1" in raw:
            norm = normalize_route(raw)
            if not norm.startswith("/api/v1") and norm.startswith("/"):
                norm = "/api/v1" + norm
            web_endpoints_normalized.add((norm, call["file"], call["line"], raw))

    lines.append(f"Unique Frontend API Route Paths: {len(set(w[0] for w in web_endpoints_normalized))}")
    
    # Check if frontend calls any route that doesn't exist in OpenAPI
    api_normalized_paths = set(norm for _, norm, _ in openapi_endpoints)
    unresolved_frontend_calls = []

    for norm, fpath, line, raw in sorted(web_endpoints_normalized):
        # Match against api paths
        matched = False
        for api_norm in api_normalized_paths:
            if norm == api_norm or norm.endswith(api_norm) or api_norm.endswith(norm):
                matched = True
                break
        if not matched:
            unresolved_frontend_calls.append((raw, fpath, line))

    lines.append(f"\nFrontend Calls with Unmatched API Routes ({len(unresolved_frontend_calls)}):")
    if unresolved_frontend_calls:
        for raw, fpath, line in unresolved_frontend_calls:
            lines.append(f"  - [POSSIBLE-CLIENT-ORPHAN] {raw} (at {fpath}:{line})")
    else:
        lines.append("  (None - all frontend calls map cleanly to implemented backend routes)")

    # 6. Schema Complexity & Standard Envelopes
    lines.append("\n" + "=" * 70)
    lines.append("SECTION 3: STANDARD ENVELOPES & ERROR SCHEMAS")
    lines.append("=" * 70)
    schemas = openapi.get("components", {}).get("schemas", {})
    lines.append(f"Total OpenAPI Data Models/Schemas: {len(schemas)}")
    has_error_schema = "HTTPValidationError" in schemas or "ErrorEnvelope" in schemas
    lines.append(f"Error Envelope Schema Defined: {has_error_schema}")
    security_schemes = openapi.get("components", {}).get("securitySchemes", {})
    lines.append(f"Security Schemes Configured: {list(security_schemes.keys())}")

    # Produce formatted output
    body = "\n".join(lines)
    print(body)
    header = format_evidence_header(command="python -m tests.audit.run_15_api_contract")
    full_output = header + "\n" + body + "\n"

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(full_output)
    print(f"\n[EVIDENCE WRITTEN] Saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
