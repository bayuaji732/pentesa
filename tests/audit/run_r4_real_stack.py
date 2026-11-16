"""R4 Real Stack Audit Runner: Missing Binary Handling (Nuclei & FFUF)."""

import os
import sys
sys.path.insert(0, os.path.abspath("."))

import json
import subprocess
import httpx
from datetime import datetime, timezone, timedelta
from tests.audit.evidence_header import format_evidence_header

API_BASE = "http://127.0.0.1:8000"
ADMIN_EMAIL = "security-lead@phase2.lab"
ADMIN_PASS = "CyberSecOps_2026!Str0ng#Auth"


def run_docker_cmd(args):
    """Run docker command on host."""
    cmd = ["docker"] + args
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return res.stdout.strip()


def query_db(sql):
    """Query live PostgreSQL database."""
    cmd = [
        "docker", "exec", "pentesa-phase2-db",
        "psql", "-U", "pentesa_user", "-d", "pentesa",
        "-c", sql
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return res.stdout.strip()


def main():
    print("=== STARTING R4 AUDIT RUNNER (MISSING BINARY HANDLING) ===")
    lines = []

    # 1. Authenticate
    client = httpx.Client(base_url=API_BASE, timeout=30.0)
    login_resp = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASS})
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    lines.append(f"[AUTH] Logged in as {ADMIN_EMAIL}")

    # 2. Create Project
    now = datetime.now(timezone.utc)
    proj_payload = {
        "name": f"Phase2-R4-Missing-Binary-{int(now.timestamp())}",
        "description": "R4 Missing binary handling verification project",
        "target_domains": ["target-juiceshop"],
        "allow_internal_networks": True,
        "authorization_start": (now - timedelta(hours=1)).isoformat(),
        "authorization_end": (now + timedelta(days=1)).isoformat()
    }
    proj_resp = client.post("/api/v1/projects", json=proj_payload, headers=headers)
    assert proj_resp.status_code == 201, f"Project creation failed: {proj_resp.text}"
    project = proj_resp.json()
    project_id = project["id"]
    lines.append(f"[PROJECT] Created project ID: {project_id}")

    # Add Scope Rule for port 3000
    scope_resp = client.post(
        f"/api/v1/projects/{project_id}/scope",
        json={
            "rule_type": "EXACT_DOMAIN",
            "target_type": "IN_SCOPE",
            "pattern": "target-juiceshop",
            "port_range": "3000",
            "notes": "Juice Shop port 3000"
        },
        headers=headers
    )
    assert scope_resp.status_code == 201, f"Scope rule failed: {scope_resp.text}"
    lines.append(f"[SCOPE] Added in-scope rule for target-juiceshop:3000")

    # Initialize WSTG instances
    cov_resp = client.get(f"/api/v1/projects/{project_id}/wstg/coverage", headers=headers)
    assert cov_resp.status_code == 200, f"Failed initializing WSTG instances: {cov_resp.text}"
    lines.append("[WSTG] Initialized project WSTG instances")

    # -------------------------------------------------------------------------
    # PART A: Missing Nuclei Binary
    # -------------------------------------------------------------------------
    lines.append("\n" + "=" * 60)
    lines.append("PART A: MISSING NUCLEI BINARY TEST")
    lines.append("=" * 60)

    try:
        # Rename nuclei binary in API container
        run_docker_cmd(["exec", "-u", "0", "pentesa-phase2-api", "mv", "/usr/local/bin/nuclei", "/usr/local/bin/nuclei.bak"])
        lines.append("[DOCKER] Executed: mv /usr/local/bin/nuclei /usr/local/bin/nuclei.bak in pentesa-phase2-api")

        # Execute nuclei tool via API
        tool_payload = {
            "tool_name": "nuclei",
            "target_url": "http://target-juiceshop:3000",
            "rate_limit": 5
        }
        resp = client.post(f"/api/v1/projects/{project_id}/tools/execute", json=tool_payload, headers=headers)
        lines.append(f"HTTP Status Code: {resp.status_code} (Expected: 503)")
        lines.append(f"Response Body:    {resp.text}")
        assert resp.status_code == 503, f"Expected 503, got {resp.status_code}"

        # Verify ToolExecution record in DB
        db_exec = query_db(
            f"SELECT id, tool_name, status, stderr_summary FROM tool_executions "
            f"WHERE project_id = '{project_id}' AND tool_name = 'nuclei' ORDER BY created_at DESC LIMIT 1;"
        )
        lines.append("\nToolExecution DB Record:")
        lines.append(db_exec)
        assert "NOT_EXECUTED" in db_exec, "Expected ToolExecution status NOT_EXECUTED"

        # Verify Audit Log entry in DB
        db_audit = query_db(
            f"SELECT action, resource_type, details FROM audit_logs "
            f"WHERE project_id = '{project_id}' AND action = 'TOOL_EXECUTION_UNAVAILABLE' ORDER BY created_at DESC LIMIT 1;"
        )
        lines.append("\nAuditLog DB Record:")
        lines.append(db_audit)
        assert "TOOL_EXECUTION_UNAVAILABLE" in db_audit, "Expected audit log action TOOL_EXECUTION_UNAVAILABLE"

        # Verify WSTG test instances marked 'Not Executed'
        db_wstg = query_db(
            f"SELECT wstg_id, status, notes FROM wstg_test_instances "
            f"WHERE project_id = '{project_id}' AND status = 'Not Executed' LIMIT 5;"
        )
        lines.append("\nWSTG Test Instances Marked 'Not Executed':")
        lines.append(db_wstg)
        assert "Not Executed" in db_wstg, "Expected WSTG test instances in status 'Not Executed'"

    finally:
        # Restore nuclei binary
        run_docker_cmd(["exec", "-u", "0", "pentesa-phase2-api", "mv", "/usr/local/bin/nuclei.bak", "/usr/local/bin/nuclei"])
        lines.append("[DOCKER] Restored: mv /usr/local/bin/nuclei.bak /usr/local/bin/nuclei in pentesa-phase2-api")

    # -------------------------------------------------------------------------
    # PART B: Missing FFUF Binary
    # -------------------------------------------------------------------------
    lines.append("\n" + "=" * 60)
    lines.append("PART B: MISSING FFUF BINARY TEST")
    lines.append("=" * 60)

    try:
        # Rename ffuf binary in API container
        run_docker_cmd(["exec", "-u", "0", "pentesa-phase2-api", "mv", "/usr/local/bin/ffuf", "/usr/local/bin/ffuf.bak"])
        lines.append("[DOCKER] Executed: mv /usr/local/bin/ffuf /usr/local/bin/ffuf.bak in pentesa-phase2-api")

        # Execute ffuf tool via API
        tool_payload = {
            "tool_name": "ffuf",
            "target_url": "http://target-juiceshop:3000/FUZZ",
            "rate_limit": 5
        }
        resp = client.post(f"/api/v1/projects/{project_id}/tools/execute", json=tool_payload, headers=headers)
        lines.append(f"HTTP Status Code: {resp.status_code} (Expected: 503)")
        lines.append(f"Response Body:    {resp.text}")
        assert resp.status_code == 503, f"Expected 503, got {resp.status_code}"

        # Verify ToolExecution record in DB
        db_exec = query_db(
            f"SELECT id, tool_name, status, stderr_summary FROM tool_executions "
            f"WHERE project_id = '{project_id}' AND tool_name = 'ffuf' ORDER BY created_at DESC LIMIT 1;"
        )
        lines.append("\nToolExecution DB Record:")
        lines.append(db_exec)
        assert "NOT_EXECUTED" in db_exec, "Expected ToolExecution status NOT_EXECUTED"

        # Verify Audit Log entry in DB
        db_audit = query_db(
            f"SELECT action, resource_type, details FROM audit_logs "
            f"WHERE project_id = '{project_id}' AND action = 'TOOL_EXECUTION_UNAVAILABLE' ORDER BY created_at DESC LIMIT 1;"
        )
        lines.append("\nAuditLog DB Record:")
        lines.append(db_audit)
        assert "TOOL_EXECUTION_UNAVAILABLE" in db_audit, "Expected audit log action TOOL_EXECUTION_UNAVAILABLE"

        # Verify WSTG test instances marked 'Not Executed'
        db_wstg = query_db(
            f"SELECT wstg_id, status, notes FROM wstg_test_instances "
            f"WHERE project_id = '{project_id}' AND status = 'Not Executed' AND notes LIKE '%ffuf%' LIMIT 5;"
        )
        lines.append("\nWSTG Test Instances Marked 'Not Executed' (ffuf):")
        lines.append(db_wstg)
        assert "Not Executed" in db_wstg, "Expected WSTG test instances in status 'Not Executed' for ffuf"

    finally:
        # Restore ffuf binary
        run_docker_cmd(["exec", "-u", "0", "pentesa-phase2-api", "mv", "/usr/local/bin/ffuf.bak", "/usr/local/bin/ffuf"])
        lines.append("[DOCKER] Restored: mv /usr/local/bin/ffuf.bak /usr/local/bin/ffuf in pentesa-phase2-api")

    # Format full evidence output
    body = "\n".join(lines)
    print(body)
    header = format_evidence_header(command="python -m tests.audit.run_r4_real_stack")
    evidence_content = header + "\n" + body + "\n"

    out_path = os.path.join("docs", "audit", "evidence", "phase2", "r4_missing_binary.txt")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(evidence_content)
    print(f"\n[EVIDENCE WRITTEN] Saved to {out_path}")


if __name__ == "__main__":
    main()
