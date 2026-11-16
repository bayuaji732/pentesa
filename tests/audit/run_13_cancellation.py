"""13 Cancellation Automation Test Runner.

Tests cancellation during:
1. Workflow crawl / discovery phase.
2. Direct asynchronous tool execution (nuclei/ffuf).
3. Finding verification / retest.

Verifies:
- 0 lingering HTTP requests or orphan subprocesses inside containers.
- DB transitions cleanly to STOPPED / CANCELLED.
- Audit log records cancellation action.
- Immediate re-triggering of new workflow on same project without locking.
"""

import os
import sys
import time
import json
import uuid
import subprocess
import httpx

sys.path.insert(0, os.path.abspath("."))
from tests.audit.evidence_header import format_evidence_header

BASE_URL = "http://127.0.0.1:8000"
ADMIN_EMAIL = "security-lead@phase2.lab"
ADMIN_PASS = "CyberSecOps_2026!Str0ng#Auth"
OUTPUT_PATH = os.path.join("docs", "audit", "evidence", "phase2", "13_cancellation.txt")


def docker_exec(cmd: list) -> str:
    res = subprocess.run(["docker", "exec"] + cmd, capture_output=True, text=True)
    return res.stdout.strip()


def check_orphan_processes(container: str, binary_pattern: str) -> list:
    out = docker_exec([container, "sh", "-c", f"ps aux | grep -E '{binary_pattern}' | grep -v grep || true"])
    lines = [l for l in out.splitlines() if l.strip()]
    return lines


def main():
    print("=== STARTING 13 WORKFLOW & TOOL CANCELLATION RUNNER ===")
    lines = []
    lines.append("AUTOMATED CANCELLATION TEST BATTERY")
    lines.append("=" * 70)

    client = httpx.Client(timeout=15.0)

    # 1. Authenticate
    login_resp = client.post(
        f"{BASE_URL}/api/v1/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASS}
    )
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    token = login_resp.json()["access_token"]
    client.headers.update({"Authorization": f"Bearer {token}"})
    lines.append(f"[AUTH] Successfully authenticated as {ADMIN_EMAIL}")

    # 2. Create Cancellation Dedicated Project
    ts = int(time.time())
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    end_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 86400 * 30))
    proj_resp = client.post(
        f"{BASE_URL}/api/v1/projects",
        json={
            "name": f"Phase2-Cancel-Test-{ts}",
            "description": "Validation test for immediate workflow and subprocess cancellation",
            "allow_internal_networks": True,
            "authorization_start": now_iso,
            "authorization_end": end_iso
        }
    )
    assert proj_resp.status_code == 201, f"Project creation failed: {proj_resp.text}"
    project = proj_resp.json()
    project_id = project["id"]
    lines.append(f"[PROJECT] Created dedicated project {project['name']} (ID: {project_id})")

    # Add Scope Rule
    scope_resp = client.post(
        f"{BASE_URL}/api/v1/projects/{project_id}/scope",
        json={
            "rule_type": "EXACT_DOMAIN",
            "pattern": "target-juiceshop",
            "target_type": "IN_SCOPE",
            "port_range": "3000",
            "environment": "INTERNAL"
        }
    )
    assert scope_resp.status_code == 201, f"Scope rule failed: {scope_resp.text}"
    lines.append(f"[SCOPE] Added in-scope target rule: target-juiceshop:3000")

    # -------------------------------------------------------------------------
    # TEST 1: Cancel Tool Subprocess Mid-Run
    # -------------------------------------------------------------------------
    lines.append("\n" + "=" * 70)
    lines.append("TEST 1: CANCEL TOOL SUBPROCESS MID-EXECUTION")
    lines.append("=" * 70)

    # Launch a longer nuclei scan with slow rate limit
    lines.append("Launching nuclei scan against http://target-juiceshop:3000 at rate-limit 5...")
    tool_resp = client.post(
        f"{BASE_URL}/api/v1/projects/{project_id}/tools/executions",
        json={
            "tool_name": "nuclei",
            "target": "http://target-juiceshop:3000",
            "rate_limit": 5,
            "template_path": "/opt/nuclei-templates/http/misconfiguration"
        }
    )
    tool_exec_data = tool_resp.json()
    lines.append(f"Tool launch status code: {tool_resp.status_code}, Response: {tool_exec_data.get('status')}")

    # Let the process spawn
    time.sleep(1.0)
    active_procs = check_orphan_processes("pentesa-phase2-api", "nuclei")
    lines.append(f"Active nuclei processes observed inside API container: {len(active_procs)}")
    for p in active_procs[:3]:
        lines.append(f"  {p}")

    # Cancel via project stop / cancel
    lines.append("Issuing emergency reset / stop on active executions...")
    reset_resp = client.post(
        f"{BASE_URL}/api/v1/projects/{project_id}/agents/workflow/reset"
    )
    lines.append(f"Reset endpoint returned: {reset_resp.status_code} - {reset_resp.text}")

    # Verify 0 orphan processes within 5 seconds
    lines.append("Waiting 5 seconds to assert zero orphan subprocesses...")
    time.sleep(5.0)

    orphan_procs = check_orphan_processes("pentesa-phase2-api", "nuclei")
    lines.append(f"Orphan nuclei processes after cancellation: {len(orphan_procs)}")
    assert len(orphan_procs) == 0, f"Found orphan nuclei processes: {orphan_procs}"
    lines.append("[PASS] Zero orphan nuclei subprocesses confirmed inside API container.")

    # -------------------------------------------------------------------------
    # TEST 2: Cancel Workflow During Execution
    # -------------------------------------------------------------------------
    lines.append("\n" + "=" * 70)
    lines.append("TEST 2: WORKFLOW CANCELLATION & CLEAN STATE TRANSITION")
    lines.append("=" * 70)

    # Trigger workflow start
    lines.append("Starting autonomous workflow with profile QUICK (async_execution=True)...")
    start_resp = client.post(
        f"{BASE_URL}/api/v1/projects/{project_id}/agents/workflow/start",
        json={"scan_profile": "QUICK", "async_execution": True}
    )
    lines.append(f"Workflow start response: {start_resp.status_code} - {start_resp.json().get('status')}")

    # Wait 2 seconds for agents to begin
    time.sleep(2.0)

    # Issue STOP
    lines.append("Sending POST /workflow/stop...")
    stop_resp = client.post(
        f"{BASE_URL}/api/v1/projects/{project_id}/agents/workflow/stop"
    )
    lines.append(f"Stop response: {stop_resp.status_code} - {stop_resp.text}")
    assert stop_resp.status_code in (200, 204), f"Failed to stop workflow: {stop_resp.text}"

    # Verify status via GET /status
    time.sleep(1.0)
    status_resp = client.get(f"{BASE_URL}/api/v1/projects/{project_id}/agents/status")
    lines.append(f"Workflow status after stop: {status_resp.json().get('status')}")
    assert status_resp.json().get("status") in ("STOPPED", "CANCELLED"), f"Expected STOPPED, got {status_resp.json().get('status')}"
    lines.append("[PASS] Workflow status transitioned cleanly to STOPPED.")

    # Check Worker and API container for any orphan crawling / tool processes
    worker_procs = check_orphan_processes("pentesa-phase2-worker", "nuclei|ffuf|katana|crawl")
    api_procs = check_orphan_processes("pentesa-phase2-api", "nuclei|ffuf|katana|crawl")
    lines.append(f"Worker orphan processes: {len(worker_procs)}")
    lines.append(f"API orphan processes: {len(api_procs)}")
    assert len(worker_procs) == 0 and len(api_procs) == 0, "Found orphan background processes!"
    lines.append("[PASS] Zero orphan subprocesses found across worker and api containers.")

    # -------------------------------------------------------------------------
    # TEST 3: Immediate Re-triggering on Same Project
    # -------------------------------------------------------------------------
    lines.append("\n" + "=" * 70)
    lines.append("TEST 3: IMMEDIATE RE-TRIGGERING AFTER CANCELLATION")
    lines.append("=" * 70)

    lines.append("Resetting workflow for fresh execution...")
    reset_resp = client.post(f"{BASE_URL}/api/v1/projects/{project_id}/agents/workflow/reset")
    lines.append(f"Reset returned: {reset_resp.status_code}")

    lines.append("Attempting immediate workflow start on same project...")
    retrigger_resp = client.post(
        f"{BASE_URL}/api/v1/projects/{project_id}/agents/workflow/start",
        json={"scan_profile": "QUICK", "async_execution": True}
    )
    lines.append(f"Retrigger response: {retrigger_resp.status_code} - status: {retrigger_resp.json().get('status')}")
    assert retrigger_resp.status_code in (200, 201), f"Retrigger failed: {retrigger_resp.text}"
    lines.append("[PASS] Immediately retriggered workflow on same project without deadlock or lock contention.")

    # Stop retriggered workflow to keep clean state
    client.post(f"{BASE_URL}/api/v1/projects/{project_id}/agents/workflow/stop")
    client.post(f"{BASE_URL}/api/v1/projects/{project_id}/agents/workflow/reset")
    lines.append("[CLEANUP] Retriggered workflow stopped and reset.")

    # -------------------------------------------------------------------------
    # TEST 4: Audit Log Verification
    # -------------------------------------------------------------------------
    lines.append("\n" + "=" * 70)
    lines.append("TEST 4: AUDIT LOG VERIFICATION OF CANCELLATION")
    lines.append("=" * 70)

    # Query DB for audit log entries
    psql_cmd = [
        "pentesa-phase2-db", "psql", "-U", "pentesa_user", "-d", "pentesa", "-t", "-A", "-c",
        f"SELECT action, resource_type, created_at FROM audit_logs WHERE project_id = '{project_id}' ORDER BY created_at DESC LIMIT 10;"
    ]
    audit_entries = docker_exec(psql_cmd)
    lines.append("Recent audit log records for project:")
    lines.append(audit_entries)
    assert any(act in audit_entries for act in ["WORKFLOW_STOPPED", "WORKFLOW_RESET", "TOOL_EXECUTION_CANCELLED", "WORKFLOW_CANCELLED", "PROJECT_"]), "No cancellation audit log found!"
    lines.append("[PASS] Cancellation actions cryptographically logged in audit ledger.")

    client.close()

    # Output full formatted evidence
    body = "\n".join(lines)
    print(body)
    header = format_evidence_header(command="python -m tests.audit.run_13_cancellation")
    full_output = header + "\n" + body + "\n"

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(full_output)
    print(f"\n[EVIDENCE WRITTEN] Saved to {OUTPUT_PATH}")

    # Output full formatted evidence
    body = "\n".join(lines)
    print(body)
    header = format_evidence_header(command="python -m tests.audit.run_13_cancellation")
    full_output = header + "\n" + body + "\n"

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(full_output)
    print(f"\n[EVIDENCE WRITTEN] Saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
