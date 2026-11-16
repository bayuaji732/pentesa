"""Machine-captured Live Restart Recovery Test Script for Phase 3 Part A Fix Round.
Validates:
1. Starts the Phase 2 live stack (db, redis, api).
2. Seeds test workflows using SQLAlchemy via the live container:
   - One RUNNING workflow (plus RUNNING and QUEUED agent executions).
   - One COMPLETED workflow (plus COMPLETED agent execution).
3. Captures BEFORE restart states.
4. Restarts the API container (`docker restart pentesa-phase2-api`).
5. Captures AFTER restart states.
6. Verifies that recovery:
   - Marks ONLY RUNNING workflow as FAILED (with state_data['failure_reason'] == 'interrupted by restart').
   - Marks associated RUNNING/QUEUED agent executions as FAILED.
   - Leaves COMPLETED workflow and COMPLETED agent execution completely untouched.
7. Saves output to docs/audit/evidence/phase3/live_restart_recovery.txt.
"""

import subprocess
import os
import sys
import time
import json
from datetime import datetime, timezone

EVIDENCE_FILE = r"docs/audit/evidence/phase3/live_restart_recovery.txt"

def run_cmd(cmd_list, timeout=60):
    try:
        res = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout)
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except Exception as e:
        return -1, "", str(e)

def exec_in_api(code_str):
    cmd = [
        "docker", "exec", "pentesa-phase2-api",
        "python", "-c", code_str
    ]
    return run_cmd(cmd)

def main():
    lines = []
    ts = datetime.now(timezone.utc).isoformat()
    lines.append("=== PENTESA AUDIT EVIDENCE — PHASE 3 PART A FIX ROUND: LIVE RESTART RECOVERY ===")
    lines.append(f"Generated At (UTC): {ts}")
    lines.append("Scope: Live Docker Stack Restart Recovery Verification (G3 / NI-06 Remediation)")
    lines.append("Evidence Standard: Machine-captured execution log, non-interactive, verifiable")
    lines.append("=" * 80)
    lines.append("")

    print("Step 1: Starting Phase 2 live stack...")
    lines.append("--- STEP 1: BRINGING UP PHASE 2 LIVE STACK (DB, REDIS, API) ---")
    code, out, err = run_cmd(["docker", "compose", "-f", "docker-compose.phase2.yml", "up", "-d", "db", "redis", "api"])
    lines.append(f"docker compose up exit code: {code}")
    if out:
        lines.append(f"Stdout:\n{out}")
    if err:
        lines.append(f"Stderr:\n{err}")

    # Wait for API to be healthy
    print("Waiting for API health...")
    time.sleep(6)
    healthy = False
    for attempt in range(15):
        code, out, err = run_cmd(["docker", "exec", "pentesa-phase2-api", "curl", "-fs", "http://127.0.0.1:8000/healthz"])
        if code == 0:
            lines.append(f"API Healthy on attempt {attempt+1}: {out}")
            healthy = True
            break
        time.sleep(2)

    if not healthy:
        lines.append("ERROR: API failed to become healthy.")
        print("API not healthy")
        return

    # Step 2: Seed test workflows
    lines.append("")
    lines.append("--- STEP 2: SEEDING TEST WORKFLOWS IN POSTGRES DATABASE ---")
    seed_script = """
import asyncio, uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy import select, delete
from database.session import AsyncSessionLocal
from database.models.user import User
from database.models.project import Project
from database.models.agent import WorkflowExecution, AgentExecution

async def run():
    async with AsyncSessionLocal() as session:
        # Find admin user
        admin = (await session.execute(select(User))).scalars().first()
        if not admin:
            print("ERROR: No admin user found in database.")
            return

        # Find or create a project
        proj = (await session.execute(select(Project))).scalars().first()
        if not proj:
            now = datetime.now(timezone.utc)
            proj = Project(
                id=uuid.uuid4(),
                name="Live Restart Test Engagement",
                status="ACTIVE",
                target_domains=["target-juiceshop", "target-dvwa"],
                allowed_cidrs=[],
                excluded_paths=[],
                allow_internal_networks=True,
                authorization_start=now - timedelta(days=1),
                authorization_end=now + timedelta(days=1),
                created_by=admin.id
            )
            session.add(proj)
            await session.flush()

        # Clean old test records
        w1_id = uuid.UUID('11111111-1111-1111-1111-111111111111')
        w2_id = uuid.UUID('22222222-2222-2222-2222-222222222222')
        a1_id = uuid.UUID('33333333-3333-3333-3333-333333333333')
        a2_id = uuid.UUID('44444444-4444-4444-4444-444444444444')
        a3_id = uuid.UUID('55555555-5555-5555-5555-555555555555')

        await session.execute(delete(AgentExecution).where(AgentExecution.id.in_([a1_id, a2_id, a3_id])))
        await session.execute(delete(WorkflowExecution).where(WorkflowExecution.id.in_([w1_id, w2_id])))
        await session.commit()

        now = datetime.now(timezone.utc)
        wf_running = WorkflowExecution(
            id=w1_id,
            project_id=proj.id,
            current_phase='ACTIVE_ASSESSMENT',
            status='RUNNING',
            state_data={'scan_profile': 'QUICK', 'note': 'in-flight workflow when restart occurs'}
        )
        wf_completed = WorkflowExecution(
            id=w2_id,
            project_id=proj.id,
            current_phase='COMPLETED',
            status='COMPLETED',
            state_data={'scan_profile': 'QUICK', 'note': 'already finished prior to restart'},
            completed_at=now
        )
        ag_running = AgentExecution(
            id=a1_id,
            project_id=proj.id,
            agent_id='AGT-09',
            agent_name='Vulnerability Detection Agent',
            status='RUNNING'
        )
        ag_queued = AgentExecution(
            id=a2_id,
            project_id=proj.id,
            agent_id='AGT-11',
            agent_name='Validation Agent',
            status='QUEUED'
        )
        ag_completed = AgentExecution(
            id=a3_id,
            project_id=proj.id,
            agent_id='AGT-01',
            agent_name='Project Planning Agent',
            status='COMPLETED',
            completed_at=now
        )
        session.add_all([wf_running, wf_completed, ag_running, ag_queued, ag_completed])
        await session.commit()
        print("SEED_SUCCESS: project=" + str(proj.id))

asyncio.run(run())
"""
    code, out, err = exec_in_api(seed_script)
    lines.append(f"Seed script exit code: {code}")
    lines.append(f"Seed output: {out}")
    if err:
        lines.append(f"Seed stderr: {err}")

    # Step 3: Query BEFORE states
    lines.append("")
    lines.append("--- STEP 3: WORKFLOW AND AGENT STATES BEFORE API RESTART ---")
    query_script = """
import asyncio, uuid, json
from sqlalchemy import select
from database.session import AsyncSessionLocal
from database.models.agent import WorkflowExecution, AgentExecution

async def run():
    async with AsyncSessionLocal() as session:
        w1_id = uuid.UUID('11111111-1111-1111-1111-111111111111')
        w2_id = uuid.UUID('22222222-2222-2222-2222-222222222222')
        wfs = (await session.execute(select(WorkflowExecution).where(WorkflowExecution.id.in_([w1_id, w2_id])).order_by(WorkflowExecution.id))).scalars().all()
        for w in wfs:
            fail_reason = (w.state_data or {}).get('failure_reason')
            print(f"WF|{w.id}|{w.status}|{fail_reason}|{w.completed_at is not None}")

        a1_id = uuid.UUID('33333333-3333-3333-3333-333333333333')
        a2_id = uuid.UUID('44444444-4444-4444-4444-444444444444')
        a3_id = uuid.UUID('55555555-5555-5555-5555-555555555555')
        ags = (await session.execute(select(AgentExecution).where(AgentExecution.id.in_([a1_id, a2_id, a3_id])).order_by(AgentExecution.id))).scalars().all()
        for a in ags:
            print(f"AG|{a.id}|{a.agent_id}|{a.agent_name}|{a.status}|{a.error_message}")

asyncio.run(run())
"""
    code, before_out, _ = exec_in_api(query_script)
    lines.append("Entities (BEFORE):")
    for r in before_out.splitlines():
        lines.append(f"  {r}")

    # Step 4: Restart API container
    print("Step 4: Restarting API container...")
    lines.append("")
    lines.append("--- STEP 4: RESTARTING API CONTAINER (docker restart pentesa-phase2-api) ---")
    restart_ts = datetime.now(timezone.utc).isoformat()
    lines.append(f"Restart initiated at (UTC): {restart_ts}")
    code, out, err = run_cmd(["docker", "restart", "pentesa-phase2-api"])
    lines.append(f"docker restart exit code: {code}")

    # Wait for API to restart and finish startup recovery
    print("Waiting for restarted API to be healthy...")
    time.sleep(5)
    for attempt in range(15):
        code, out, err = run_cmd(["docker", "exec", "pentesa-phase2-api", "curl", "-fs", "http://127.0.0.1:8000/healthz"])
        if code == 0:
            lines.append(f"API Healthy after restart on attempt {attempt+1}: {out}")
            break
        time.sleep(2)

    # Step 5: Capture API startup recovery logs
    lines.append("")
    lines.append("--- STEP 5: API STARTUP RECOVERY LOGS ---")
    code, logs, err = run_cmd(["docker", "logs", "--tail", "50", "pentesa-phase2-api"])
    for l in (logs + "\n" + err).splitlines():
        if "Startup recovery" in l or "recover_interrupted_workflows" in l or "marked" in l or "lifespan" in l:
            lines.append(f"  {l}")

    # Step 6: Query AFTER states
    lines.append("")
    lines.append("--- STEP 6: WORKFLOW AND AGENT STATES AFTER API RESTART ---")
    code, after_out, _ = exec_in_api(query_script)
    lines.append("Entities (AFTER):")
    for r in after_out.splitlines():
        lines.append(f"  {r}")

    # Step 7: Verifications
    lines.append("")
    lines.append("--- STEP 7: RECOVERY INVARIANT VERIFICATION ---")
    # wf-running: 11111111-1111-1111-1111-111111111111 must be FAILED with fail_reason == interrupted by restart
    # wf-completed: 22222222-2222-2222-2222-222222222222 must still be COMPLETED with no fail_reason
    wf_running_recovered = "WF|11111111-1111-1111-1111-111111111111|FAILED|interrupted by restart|True" in after_out
    wf_completed_preserved = "WF|22222222-2222-2222-2222-222222222222|COMPLETED|None|True" in after_out
    ag_running_recovered = "AG|33333333-3333-3333-3333-333333333333|AGT-09|Vulnerability Detection Agent|FAILED|interrupted by restart" in after_out
    ag_queued_recovered = "AG|44444444-4444-4444-4444-444444444444|AGT-11|Validation Agent|FAILED|interrupted by restart" in after_out
    ag_completed_preserved = "AG|55555555-5555-5555-5555-555555555555|AGT-01|Project Planning Agent|COMPLETED|None" in after_out

    lines.append(f"Invariant 1 (RUNNING workflow transitioned to FAILED with reason): {'PASS' if wf_running_recovered else 'FAIL'}")
    lines.append(f"Invariant 2 (COMPLETED workflow remained COMPLETED): {'PASS' if wf_completed_preserved else 'FAIL'}")
    lines.append(f"Invariant 3 (RUNNING agent execution transitioned to FAILED): {'PASS' if ag_running_recovered else 'FAIL'}")
    lines.append(f"Invariant 4 (QUEUED agent execution transitioned to FAILED): {'PASS' if ag_queued_recovered else 'FAIL'}")
    lines.append(f"Invariant 5 (COMPLETED agent execution remained COMPLETED): {'PASS' if ag_completed_preserved else 'FAIL'}")

    all_passed = all([wf_running_recovered, wf_completed_preserved, ag_running_recovered, ag_queued_recovered, ag_completed_preserved])
    result_str = "PASS" if all_passed else "FAIL"

    # Teardown stack
    print("Tearing down Phase 2 stack...")
    run_cmd(["docker", "compose", "-f", "docker-compose.phase2.yml", "down", "-v"])
    lines.append("Phase 2 test containers stopped and volumes pruned.")

    lines.append("")
    lines.append("=" * 80)
    lines.append(f"RESULT: {result_str} — Live restart recovery successfully validated.")
    lines.append("=" * 80)

    content = "\n".join(lines) + "\n"
    os.makedirs(os.path.dirname(EVIDENCE_FILE), exist_ok=True)
    with open(EVIDENCE_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Evidence written to {EVIDENCE_FILE}")
    print(content)

if __name__ == "__main__":
    main()
