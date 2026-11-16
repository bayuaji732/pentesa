"""12 UI Playwright Automation Test Runner.

Walks critical user journey and verifies all frontend routes with screenshots,
console error logging, and network failure accounting.
"""

import os
import sys
sys.path.insert(0, os.path.abspath("."))

import json
import time
from playwright.sync_api import sync_playwright
from tests.audit.evidence_header import format_evidence_header

BASE_URL = "http://127.0.0.1:3000"
ADMIN_EMAIL = "security-lead@phase2.lab"
ADMIN_PASS = "CyberSecOps_2026!Str0ng#Auth"
SCREENSHOT_DIR = os.path.join("docs", "audit", "evidence", "phase2", "ui_screenshots")


def main():
    print("=== STARTING 12 UI PLAYWRIGHT AUTOMATION RUNNER ===")
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    lines = []

    console_errors = []
    failed_requests = []

    def on_console(msg):
        if msg.type in ("error", "warning"):
            console_errors.append(f"[{msg.type.upper()}] {msg.text}")

    def on_request_failed(request):
        failed_requests.append(f"FAILED {request.method} {request.url} - {request.failure}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()

        page.on("console", on_console)
        page.on("requestfailed", on_request_failed)

        # ---------------------------------------------------------------------
        # STEP 1: Login Page
        # ---------------------------------------------------------------------
        lines.append("\n--- STEP 1: LOGIN PAGE ---")
        page.goto(f"{BASE_URL}/login", wait_until="networkidle")
        page.wait_for_timeout(1000)
        shot_path = os.path.join(SCREENSHOT_DIR, "01_login_page.png")
        page.screenshot(path=shot_path)
        lines.append(f"Navigated to /login. Title: '{page.title()}'")
        lines.append(f"Saved screenshot: {shot_path}")

        # Fill credentials
        page.fill("input[type='email']", ADMIN_EMAIL)
        page.fill("input[type='password']", ADMIN_PASS)
        page.click("button[type='submit']")
        page.wait_for_timeout(2000)
        page.wait_for_load_state("networkidle")
        lines.append(f"Submitted login form. Current URL: {page.url}")

        # ---------------------------------------------------------------------
        # STEP 2: Projects Dashboard & Selection / Creation
        # ---------------------------------------------------------------------
        lines.append("\n--- STEP 2: PROJECTS DASHBOARD & SELECTION ---")
        page.goto(f"{BASE_URL}/projects", wait_until="networkidle")
        page.wait_for_timeout(1500)
        shot_path = os.path.join(SCREENSHOT_DIR, "02_projects_dashboard.png")
        page.screenshot(path=shot_path)
        lines.append(f"Saved screenshot: {shot_path}")

        # Set active project in localStorage to ensure findings are loaded
        page.evaluate("() => localStorage.setItem('pentesa_active_project_id', '95836573-27db-47d2-a2c4-ac948c1f86db')")

        # Search for project with existing findings (e.g. Phase2-R6-PTES-Report)
        page.fill("input[placeholder*='Search engagement']", "Phase2-R6-PTES-Report")
        page.wait_for_timeout(1000)

        open_btns = page.query_selector_all("button:has-text('Open')")
        if open_btns:
            lines.append(f"Found engagement with findings. Opening engagement...")
            open_btns[0].click()
            page.wait_for_timeout(2000)
            page.wait_for_load_state("networkidle")
            lines.append(f"Opened engagement. Current URL: {page.url}")
        else:
            # Open New Project Modal
            lines.append("No existing engagements found. Creating new engagement...")
            page.click("button:has-text('New Engagement')")
            page.wait_for_timeout(1000)
            shot_path = os.path.join(SCREENSHOT_DIR, "03_create_project_modal.png")
            page.screenshot(path=shot_path)
            lines.append(f"Opened create project modal. Saved screenshot: {shot_path}")

            # Fill Project Form
            proj_name = f"Playwright-Audit-Project-{int(time.time())}"
            page.fill("input[placeholder*='e.g. Q4 Web Application']", proj_name)
            page.fill("input[placeholder*='example.com']", "target-juiceshop")
            page.fill("input[placeholder*='ROE-']", "ROE-2026-PLAYWRIGHT-001")
            
            checkbox = page.query_selector("input[type='checkbox']")
            if checkbox and not checkbox.is_checked():
                checkbox.check()

            # Submit modal form
            page.click("button[type='submit']:has-text('Authorize Engagement')")
            page.wait_for_timeout(2000)
            page.wait_for_load_state("networkidle")
            lines.append(f"Created project: {proj_name}. Current URL: {page.url}")

        # ---------------------------------------------------------------------
        # STEP 3: Configure Scope
        # ---------------------------------------------------------------------
        lines.append("\n--- STEP 3: CONFIGURE SCOPE ---")
        page.goto(f"{BASE_URL}/scope", wait_until="networkidle")
        page.wait_for_timeout(1500)
        shot_path = os.path.join(SCREENSHOT_DIR, "04_scope_configuration.png")
        page.screenshot(path=shot_path)
        lines.append(f"Navigated to /scope. Saved screenshot: {shot_path}")

        # ---------------------------------------------------------------------
        # STEP 4: Attack Surface Discovery
        # ---------------------------------------------------------------------
        lines.append("\n--- STEP 4: ATTACK SURFACE DISCOVERY ---")
        page.goto(f"{BASE_URL}/discovery", wait_until="networkidle")
        page.wait_for_timeout(1500)
        shot_path = os.path.join(SCREENSHOT_DIR, "05_attack_surface_discovery.png")
        page.screenshot(path=shot_path)
        lines.append(f"Navigated to /discovery. Saved screenshot: {shot_path}")

        # ---------------------------------------------------------------------
        # STEP 5: WSTG Coverage Matrix
        # ---------------------------------------------------------------------
        lines.append("\n--- STEP 5: WSTG COVERAGE MATRIX ---")
        page.goto(f"{BASE_URL}/wstg", wait_until="networkidle")
        page.wait_for_timeout(1500)
        shot_path = os.path.join(SCREENSHOT_DIR, "06_wstg_coverage_matrix.png")
        page.screenshot(path=shot_path)
        lines.append(f"Navigated to /wstg. Saved screenshot: {shot_path}")

        # ---------------------------------------------------------------------
        # STEP 6: Multi-Agent Workflow Live Monitor
        # ---------------------------------------------------------------------
        lines.append("\n--- STEP 6: MULTI-AGENT WORKFLOW LIVE MONITOR ---")
        page.goto(f"{BASE_URL}/agents", wait_until="networkidle")
        page.wait_for_timeout(1500)
        shot_path = os.path.join(SCREENSHOT_DIR, "07_agent_live_monitor.png")
        page.screenshot(path=shot_path)
        lines.append(f"Navigated to /agents. Saved screenshot: {shot_path}")

        # ---------------------------------------------------------------------
        # STEP 7: Inspect Findings, False Positive & Retest
        # ---------------------------------------------------------------------
        lines.append("\n--- STEP 7: FINDINGS INVENTORY, FALSE POSITIVE & RETEST ---")
        page.goto(f"{BASE_URL}/findings", wait_until="networkidle")
        page.wait_for_timeout(2000)
        shot_path = os.path.join(SCREENSHOT_DIR, "08_findings_inventory.png")
        page.screenshot(path=shot_path)
        lines.append(f"Navigated to /findings. Saved screenshot: {shot_path}")

        # Select first finding card if items exist
        finding_card = page.query_selector("div.cursor-pointer:has-text('CVSS'), div.cursor-pointer:has-text('WSTG-')")
        if finding_card:
            lines.append("Found finding card in inventory. Clicking to open evidence drawer...")
            finding_card.click()
            page.wait_for_timeout(1500)
            shot_path = os.path.join(SCREENSHOT_DIR, "09_finding_retest_and_fp.png")
            page.screenshot(path=shot_path)
            lines.append(f"Selected finding card and opened evidence drawer. Saved screenshot: {shot_path}")

            # Switch evidence tabs
            curl_tab = page.query_selector("button:has-text('Reproduction cURL'), button:has-text('cURL')")
            if curl_tab:
                curl_tab.click()
                page.wait_for_timeout(500)
                lines.append("Switched to 'Reproduction cURL' evidence tab")

            # Test Retest button
            retest_btn = page.query_selector("button:has-text('Verify Fix'), button:has-text('Retest')")
            if retest_btn:
                lines.append("Found Retest button ('Verify Fix'). Triggering retest...")
                retest_btn.click()
                page.wait_for_timeout(3000)
                lines.append("Triggered automated vulnerability retest verification")
        else:
            lines.append("No finding cards found on page (empty findings list).")

        # ---------------------------------------------------------------------
        # STEP 8: Reports Center & Download
        # ---------------------------------------------------------------------
        lines.append("\n--- STEP 8: REPORTS CENTER & DOWNLOAD ---")
        page.goto(f"{BASE_URL}/reports", wait_until="networkidle")
        page.wait_for_timeout(2000)
        shot_path = os.path.join(SCREENSHOT_DIR, "10_reports_center.png")
        page.screenshot(path=shot_path)
        lines.append(f"Navigated to /reports. Saved screenshot: {shot_path}")

        # ---------------------------------------------------------------------
        # STEP 9: Audit Logs Ledger
        # ---------------------------------------------------------------------
        lines.append("\n--- STEP 9: AUDIT LOGS LEDGER ---")
        page.goto(f"{BASE_URL}/audit-logs", wait_until="networkidle")
        page.wait_for_timeout(1500)
        shot_path = os.path.join(SCREENSHOT_DIR, "11_audit_log_ledger.png")
        page.screenshot(path=shot_path)
        lines.append(f"Navigated to /audit-logs. Saved screenshot: {shot_path}")

        # ---------------------------------------------------------------------
        # STEP 10: Full Routing Table Verification (Empty States, Error Boundaries)
        # ---------------------------------------------------------------------
        lines.append("\n" + "=" * 70)
        lines.append("FULL ROUTING TABLE VERIFICATION")
        lines.append("=" * 70)
        routes = [
            "/",
            "/login",
            "/projects",
            "/scope",
            "/discovery",
            "/wstg",
            "/agents",
            "/findings",
            "/reports",
            "/audit-logs"
        ]
        route_results = []
        for r in routes:
            resp = page.goto(f"{BASE_URL}{r}", wait_until="networkidle")
            page.wait_for_timeout(800)
            status_code = resp.status if resp else "unknown"
            has_error_boundary = "Application error" in page.content() or "Internal Server Error" in page.content()
            has_skeleton = "skeleton" in page.content().lower() or "animate-pulse" in page.content().lower()
            lines.append(f"Route: {r:15s} | HTTP Status: {status_code} | Error Boundary: {has_error_boundary} | Skeleton/Loading Handled: {has_skeleton}")
            assert not has_error_boundary, f"Error boundary triggered on route {r}"
            route_results.append((r, status_code))

        # ---------------------------------------------------------------------
        # Summary & Diagnostics
        # ---------------------------------------------------------------------
        lines.append("\n" + "=" * 70)
        lines.append("PLAYWRIGHT DIAGNOSTIC LOG")
        lines.append("=" * 70)
        lines.append(f"Total Console Warnings/Errors: {len(console_errors)}")
        for ce in console_errors[:15]:
            lines.append(f"  {ce}")
        lines.append(f"Total Failed Network Requests: {len(failed_requests)}")
        for fr in failed_requests[:15]:
            lines.append(f"  {fr}")

        browser.close()

    # Format full evidence output
    body = "\n".join(lines)
    print(body)
    header = format_evidence_header(command="python -m tests.audit.run_12_ui_playwright")
    evidence_content = header + "\n" + body + "\n"

    out_path = os.path.join("docs", "audit", "evidence", "phase2", "12_ui_playwright.txt")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(evidence_content)
    print(f"\n[EVIDENCE WRITTEN] Saved to {out_path}")


if __name__ == "__main__":
    main()
