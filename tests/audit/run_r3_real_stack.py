"""R3 Real Stack Audit Runner: Juice Shop Crawl + WSTG Plan & Coverage."""

import os
import sys
sys.path.insert(0, os.path.abspath("."))

import json
import httpx
from datetime import datetime, timezone, timedelta
from tests.audit.evidence_header import format_evidence_header

API_BASE = "http://127.0.0.1:8000"
ADMIN_EMAIL = "security-lead@phase2.lab"
ADMIN_PASS = "CyberSecOps_2026!Str0ng#Auth"


def main():
    print("=== STARTING R3 AUDIT RUNNER ===")
    lines = []
    
    # 1. Authenticate
    client = httpx.Client(base_url=API_BASE, timeout=60.0)
    login_resp = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASS})
    assert login_resp.status_code == 200, f"Login failed: {login_resp.status_code} {login_resp.text}"
    tokens = login_resp.json()
    access_token = tokens["access_token"]
    auth_headers = {"Authorization": f"Bearer {access_token}"}
    lines.append(f"[AUTH] Successfully logged in as {ADMIN_EMAIL}")

    # 2. Create Project
    now = datetime.now(timezone.utc)
    proj_payload = {
        "name": f"Phase2-R3-JuiceShop-Crawl-{int(now.timestamp())}",
        "description": "R3 Juice Shop attack surface discovery and WSTG coverage test project",
        "target_domains": ["target-juiceshop"],
        "allow_internal_networks": True,
        "authorization_start": (now - timedelta(hours=1)).isoformat(),
        "authorization_end": (now + timedelta(days=1)).isoformat()
    }
    proj_resp = client.post("/api/v1/projects", json=proj_payload, headers=auth_headers)
    assert proj_resp.status_code == 201, f"Project creation failed: {proj_resp.status_code} {proj_resp.text}"
    project = proj_resp.json()
    project_id = project["id"]
    lines.append(f"[PROJECT] Created project ID: {project_id}")

    # 3. Add Scope Rule with port 3000
    scope_payload = {
        "rule_type": "EXACT_DOMAIN",
        "target_type": "IN_SCOPE",
        "pattern": "target-juiceshop",
        "port_range": "3000",
        "notes": "Authorized Juice Shop container target on port 3000"
    }
    scope_resp = client.post(f"/api/v1/projects/{project_id}/scope", json=scope_payload, headers=auth_headers)
    assert scope_resp.status_code == 201, f"Scope rule failed: {scope_resp.status_code} {scope_resp.text}"
    lines.append(f"[SCOPE] Added in-scope rule for target-juiceshop:3000")

    # 4. Trigger Crawl
    lines.append("\n--- ATTACK SURFACE CRAWL EXECUTION ---")
    crawl_payload = {
        "seed_urls": ["http://target-juiceshop:3000/"],
        "max_depth": 2,
        "max_pages": 30,
        "respect_robots_txt": True,
        "parse_sitemap": True,
        "extract_js_routes": True,
        "detect_technologies": True
    }
    crawl_resp = client.post(f"/api/v1/projects/{project_id}/discovery/crawl", json=crawl_payload, headers=auth_headers)
    assert crawl_resp.status_code == 200, f"Crawl failed: {crawl_resp.status_code} {crawl_resp.text}"
    crawl_summary = crawl_resp.json()
    lines.append(f"Crawl Status:               {crawl_summary.get('status')}")
    lines.append(f"Total URLs Visited:         {crawl_summary.get('total_urls_visited')}")
    lines.append(f"Endpoints Discovered:       {crawl_summary.get('endpoints_discovered')}")
    lines.append(f"Technologies Detected:      {crawl_summary.get('technologies_detected')}")
    lines.append(f"Domains Discovered:         {crawl_summary.get('domains_discovered')}")
    if crawl_summary.get("errors"):
        lines.append(f"Crawl Errors:               {crawl_summary.get('errors')}")

    # 5. List Discovered Endpoints
    lines.append("\n--- DISCOVERED ENDPOINTS INVENTORY ---")
    ep_resp = client.get(f"/api/v1/projects/{project_id}/endpoints?limit=100", headers=auth_headers)
    assert ep_resp.status_code == 200, f"Endpoints listing failed: {ep_resp.status_code}"
    ep_data = ep_resp.json()
    discovered_endpoints = ep_data.get("items", [])
    lines.append(f"Total Discovered Endpoints in DB: {ep_data.get('total')}")
    for idx, ep in enumerate(discovered_endpoints, 1):
        lines.append(f"  [{idx:02d}] {ep.get('http_method')} {ep.get('fqdn')}{ep.get('url_path')} (auth_req={ep.get('auth_required')}, status={ep.get('testing_status')})")

    # 6. Recalculate WSTG Test Plan
    lines.append("\n--- WSTG TEST PLAN RECALCULATION ---")
    recalc_resp = client.post(f"/api/v1/projects/{project_id}/wstg/recalculate", headers=auth_headers)
    assert recalc_resp.status_code == 200, f"Recalculate failed: {recalc_resp.status_code} {recalc_resp.text}"
    recalc = recalc_resp.json()
    lines.append(f"Total Instances:            {recalc.get('total_instances')}")
    lines.append(f"Planned Count (Applicable): {recalc.get('planned_count')}")
    lines.append(f"Not Applicable Count:       {recalc.get('not_applicable_count')}")
    lines.append(f"Endpoints Analyzed:         {recalc.get('endpoints_analyzed')}")
    lines.append(f"Summary:                    {recalc.get('summary')}")

    # 7. Get Empirical WSTG Coverage Report
    lines.append("\n--- EMPIRICAL MATHEMATICAL COVERAGE REPORT ---")
    cov_resp = client.get(f"/api/v1/projects/{project_id}/wstg/coverage", headers=auth_headers)
    assert cov_resp.status_code == 200, f"Coverage report failed: {cov_resp.status_code} {cov_resp.text}"
    cov = cov_resp.json()
    
    total = cov.get("total_catalog_tests", 106)
    passed = cov.get("passed_count", 0)
    failed = cov.get("failed_count", 0)
    needs_review = cov.get("needs_review_count", 0)
    not_applicable = cov.get("not_applicable_count", 0)
    planned = cov.get("planned_count", 0)
    running = cov.get("running_count", 0)
    not_started = cov.get("not_started_count", 0)

    # Formulas verification:
    # Coverage % = ((Passed + Failed + Needs Review + Not Applicable) / Total) * 100
    # Executed Coverage % = ((Passed + Failed + Needs Review) / (Total - Not Applicable)) * 100
    calc_covered = passed + failed + needs_review + not_applicable
    calc_cov_pct = round((calc_covered / total) * 100.0, 1) if total > 0 else 0.0
    
    calc_executed = passed + failed + needs_review
    calc_applicable = total - not_applicable
    calc_exec_cov_pct = round((calc_executed / calc_applicable) * 100.0, 1) if calc_applicable > 0 else 0.0

    lines.append(f"Total Catalog Tests:        {total}")
    lines.append(f"Planned Tests:              {planned}")
    lines.append(f"Not Applicable Tests:       {not_applicable}")
    lines.append(f"Passed Tests:               {passed}")
    lines.append(f"Failed Tests:               {failed}")
    lines.append(f"Needs Review Tests:         {needs_review}")
    lines.append(f"Running / Not Started:      {running} / {not_started}")
    lines.append("")
    lines.append(f"API overall_coverage_pct:   {cov.get('overall_coverage_pct')}%")
    lines.append(f"Formula Calculated Coverage: {calc_cov_pct}% (Formula: ({passed} + {failed} + {needs_review} + {not_applicable}) / {total} * 100)")
    lines.append(f"API executed_coverage_pct:  {cov.get('executed_coverage_pct')}%")
    lines.append(f"Formula Executed Coverage:  {calc_exec_cov_pct}% (Formula: ({passed} + {failed} + {needs_review}) / ({total} - {not_applicable}) * 100)")
    lines.append(f"API testing_health_score:   {cov.get('testing_health_score')}%")

    lines.append("\nCategory Breakdown:")
    for cat_code, metrics in sorted(cov.get("categories", {}).items()):
        lines.append(f"  {cat_code:12s}: Total={metrics.get('total_tests'):2d}, Planned={metrics.get('planned_count'):2d}, N/A={metrics.get('not_applicable_count'):2d}, Passed={metrics.get('passed_count'):2d}, Failed={metrics.get('failed_count'):2d}, Cov={metrics.get('coverage_pct'):5.1f}%, ExecCov={metrics.get('executed_coverage_pct'):5.1f}%")

    # Format full evidence output
    body = "\n".join(lines)
    print(body)
    header = format_evidence_header(command="python -m tests.audit.run_r3_real_stack")
    evidence_content = header + "\n" + body + "\n"

    out_path = os.path.join("docs", "audit", "evidence", "phase2", "r3_wstg_plan_counts.txt")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(evidence_content)
    print(f"\n[EVIDENCE WRITTEN] Saved to {out_path}")


if __name__ == "__main__":
    main()
