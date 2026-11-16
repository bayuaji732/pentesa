"""Single Workflow Test Probe.

Runs 1 workflow against Juice Shop with live Swedish gateway (azure/gpt-5.6-terra-dev-gtw)
and prints real-time agent progression, token usage, cost, and WSTG metrics.
"""

import os
import sys
import time
import uuid
import httpx

sys.path.insert(0, os.path.abspath("."))

BASE_URL = "http://127.0.0.1:8000"
ADMIN_EMAIL = "security-lead@phase2.lab"
ADMIN_PASS = "CyberSecOps_2026!Str0ng#Auth"


def main():
    print("=== STARTING SINGLE WORKFLOW RUN TEST PROBE ===")
    client = httpx.Client(timeout=60.0)

    # 1. Login
    login_resp = client.post(
        f"{BASE_URL}/api/v1/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASS}
    )
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    token = login_resp.json()["access_token"]
    client.headers.update({"Authorization": f"Bearer {token}"})
    print("[AUTH] Successfully authenticated as admin.")

    # 2. Create project
    ts = int(time.time())
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    end_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 86400 * 30))
    proj_resp = client.post(
        f"{BASE_URL}/api/v1/projects",
        json={
            "name": f"L1-Test-JuiceShop-{ts}",
            "description": "Validation run for 8.1b multi-agent assessment against Juice Shop",
            "allow_internal_networks": True,
            "authorization_start": now_iso,
            "authorization_end": end_iso
        }
    )
    assert proj_resp.status_code == 201, f"Project creation failed: {proj_resp.text}"
    project_id = proj_resp.json()["id"]
    print(f"[PROJECT] Created test project ID: {project_id}")

    # 3. Add scope
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
    print("[SCOPE] Scope rule added for target-juiceshop:3000.")

    # 4. Start workflow
    start_time = time.time()
    start_resp = client.post(
        f"{BASE_URL}/api/v1/projects/{project_id}/agents/workflow/start",
        json={
            "scan_profile": "QUICK",
            "async_execution": True,
            "auto_approve_medium": True
        }
    )
    print(f"[START] Workflow start response: {start_resp.status_code} - {start_resp.text}")

    # 5. Poll until completed or failed
    max_wait = 180  # up to 3 minutes
    print(f"[MONITOR] Polling workflow status (up to {max_wait}s)...")
    last_phase = None
    completed = False
    status_data = {}

    for i in range(max_wait // 2):
        time.sleep(2.0)
        st_resp = client.get(f"{BASE_URL}/api/v1/projects/{project_id}/agents/status")
        if st_resp.status_code == 200:
            data = st_resp.json()
            curr_status = data.get("status")
            curr_phase = data.get("current_phase")
            if curr_phase != last_phase:
                print(f"  [{int(time.time() - start_time)}s] Phase: {curr_phase} | Status: {curr_status}")
                last_phase = curr_phase

            if curr_status in ("COMPLETED", "FAILED", "STOPPED"):
                status_data = data
                completed = True
                break

    duration = round(time.time() - start_time, 2)
    print(f"\n[RESULT] Workflow finished in {duration}s with status: {status_data.get('status')}")
    print(f"Active Agents Summary:")
    total_prompt_tokens = 0
    total_comp_tokens = 0
    total_cost = 0.0

    for ag in status_data.get("active_agents", []):
        print(f"  - {ag['agent_id']:8s} ({ag['agent_name']:35s}): status={ag['status']:10s} prompt_tokens={ag.get('prompt_tokens',0):5d} comp_tokens={ag.get('completion_tokens',0):5d} cost=${ag.get('total_cost_usd',0.0):.6f}")
        total_prompt_tokens += ag.get("prompt_tokens", 0)
        total_comp_tokens += ag.get("completion_tokens", 0)
        total_cost += ag.get("total_cost_usd", 0.0)

    print(f"\nAggregates: Total Prompt Tokens={total_prompt_tokens}, Total Completion Tokens={total_comp_tokens}, Total Cost=${total_cost:.6f}")


if __name__ == "__main__":
    main()
