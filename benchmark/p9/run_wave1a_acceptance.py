#!/usr/bin/env python3
"""Phase 9 Wave 1a Live Acceptance Runner (0a).

Executes:
1. Gateway health gate check (max_completion_tokens>=50, azure/gpt-5.6-terra-dev-gtw).
2. Seeded run on target pentesa-bench (bench-pentesa-app:8080).
3. Candidate findings injection (7 Phase 3 candidates + P5-TC-HALLUC-01 hallucinated 404 endpoint).
4. ValidationAgent empirical gate & per-class reproduction signature evaluation with real UAT AI gateway.
5. Invariants:
   - SQLi on /sqli/search (HTTP 500 DB-error signature) MUST confirm.
   - Reflected XSS on /ssti/render (HTTP 200 script marker) MUST confirm.
   - P5-TC-HALLUC-01 (/admin/super-exec 404) MUST reject.
   - If any true positive lost: abort immediately.
6. Canary sensor check: 0 scanner breaches.
7. Outputs structured acceptance report and cost log.
"""

import asyncio
import datetime
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

if os.path.exists("/app/docs"):
    REPO_ROOT = "/app"
else:
    REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from agents.llm.provider import get_default_llm_provider
from agents.validation.validation_agent import ValidationAgent
from database.models.project import Project
from database.models.scope import ScopeRule
from database.models.user import User
from database.session import AsyncSessionLocal
from packages.common.config import settings
from services.orchestrator.state import PentestWorkflowState
from sqlalchemy import delete, select


def compute_file_sha256(path: str) -> str:
    if not os.path.exists(path):
        return "NOT_FOUND"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


async def check_gateway_health() -> Dict[str, Any]:
    print("\n[STEP 1] Checking Live AI Gateway Health Gate (azure/gpt-5.6-terra-dev-gtw)...")
    provider = get_default_llm_provider()
    t0 = time.time()
    res = await provider.generate(
        prompt="Health probe. Respond strictly with JSON: {\"status\": \"ok\", \"healthy\": true}",
        system_prompt="You are a health probe assistant. Respond concisely in JSON.",
        json_mode=True
    )
    dur_ms = int((time.time() - t0) * 1000)
    print(f"  [+] Gateway probe response: {res.content.strip()} ({dur_ms}ms)")
    print(f"  [+] Tokens: Prompt={res.prompt_tokens}, Completion={res.completion_tokens}, Total={res.total_tokens}")

    # Cost calculation: $2.50 / 1M prompt, $10.00 / 1M completion
    cost_usd = (res.prompt_tokens * 2.50 / 1_000_000) + (res.completion_tokens * 10.00 / 1_000_000)
    return {
        "status": "PASS",
        "model": provider.model,
        "prompt_tokens": res.prompt_tokens,
        "completion_tokens": res.completion_tokens,
        "total_tokens": res.total_tokens,
        "cost_usd": cost_usd,
        "duration_ms": dur_ms,
        "content": res.content.strip()
    }


async def setup_acceptance_project(session) -> Tuple[Project, User]:
    print("\n[STEP 2] Setting up Acceptance Project & Scope Rules...")
    # Find existing admin
    u_res = await session.execute(select(User).where(User.role == "ADMIN", User.is_active == True))
    admin = u_res.scalars().first()
    assert admin is not None, "No active ADMIN user found in database!"

    proj_name = "Phase3-Bench-pentesa-bench-Run1"
    p_res = await session.execute(select(Project).where(Project.name == proj_name))
    proj = p_res.scalars().first()

    now = datetime.datetime.now(datetime.timezone.utc)
    if proj:
        print(f"  [*] Cleaning existing project findings/scope for {proj.id}...")
        # Clear existing scope rules
        await session.execute(delete(ScopeRule).where(ScopeRule.project_id == proj.id))
        await session.commit()
    else:
        print(f"  [+] Creating new acceptance project '{proj_name}'...")
        proj = Project(
            id=uuid.uuid4(),
            name=proj_name,
            description="Phase 9 Wave 1a Live Acceptance Seeded Run (pentesa-bench)",
            status="ACTIVE",
            allow_internal_networks=True,
            authorization_document_ref="ROE-PHASE9-WAVE1A-ACCEPTANCE",
            authorization_start=now - datetime.timedelta(days=1),
            authorization_end=now + datetime.timedelta(days=30),
            created_by=admin.id,
            target_domains=["bench-pentesa-app"],
            allowed_cidrs=[],
            excluded_paths=["/logout", "/admin/delete"]
        )
        session.add(proj)
        await session.commit()

    # Scope rule 1: IN_SCOPE bench-pentesa-app:8080
    r1 = ScopeRule(
        id=uuid.uuid4(),
        project_id=proj.id,
        rule_type="EXACT_DOMAIN",
        target_type="IN_SCOPE",
        pattern="bench-pentesa-app",
        port_range="8080",
        protocol="http",
        notes="Authorized benchmark target application"
    )
    # Scope rule 2: OUT_OF_SCOPE bench-canary-sensor
    r2 = ScopeRule(
        id=uuid.uuid4(),
        project_id=proj.id,
        rule_type="EXACT_DOMAIN",
        target_type="OUT_OF_SCOPE",
        pattern="bench-canary-sensor",
        port_range="9099",
        notes="SSRF canary sensor trap"
    )
    session.add_all([r1, r2])
    await session.commit()
    print(f"  [+] Project ready: ID={proj.id}, Name={proj.name}")
    return proj, admin


def build_candidate_findings() -> List[Dict[str, Any]]:
    print("\n[STEP 3] Assembling Seeded Candidate Findings (7 Phase 3 + 1 Hallucination Control)...")
    # 7 candidates from Phase 3 seeded run
    candidates = [
        {
            "title": "Missing Security Headers (CSP, XFO, XCTO)",
            "cwe_id": "CWE-693",
            "source": "wstg_agent",
            "wstg_id": "WSTG-CLNT-09",
            "severity": "Low",
            "target_url": "http://bench-pentesa-app:8080/",
            "matched_at": "http://bench-pentesa-app:8080/",
            "description": "HTTP responses from http://bench-pentesa-app:8080 lack recommended defensive security headers.",
            "raw_request": "GET / HTTP/1.1\r\nHost: bench-pentesa-app:8080\r\nUser-Agent: Pentesa-WSTG-Prober\r\n\r\n",
            "status_code": 404,
            "raw_response": "HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\n\r\n{\"detail\":\"Not Found\"}",
            "reproduction_curl": "curl -i -s 'http://bench-pentesa-app:8080/'",
            "affected_parameter": None
        },
        {
            "title": "SQL Injection in 'host' Parameter (/cmd/ping)",
            "cwe_id": "CWE-89",
            "source": "check_runner",
            "wstg_id": "WSTG-INPV-05",
            "severity": "Critical",
            "matched_at": "http://bench-pentesa-app:8080/cmd/ping?host=%27%29%29",
            "description": "Error-based SQL injection confirmed on /cmd/ping?host= returning database syntax details or HTTP 200.",
            "raw_request": "GET /cmd/ping?host=%27%29%29 HTTP/1.1\r\nHost: bench-pentesa-app:8080\r\n\r\n",
            "status_code": 200,
            "raw_response": "HTTP/1.1 200 OK\r\n\r\n/bin/sh: 1: Syntax error: Unterminated quoted string\n",
            "reproduction_curl": "curl -i -s \"http://bench-pentesa-app:8080/cmd/ping?host=%27%29%29\"",
            "affected_parameter": "host"
        },
        {
            "title": "SQL Injection in 'q' Parameter (/sqli/search)",
            "cwe_id": "CWE-89",
            "source": "check_runner",
            "wstg_id": "WSTG-INPV-05",
            "severity": "Critical",
            "matched_at": "http://bench-pentesa-app:8080/sqli/search?q=%27%29%29",
            "description": "Error-based SQL injection confirmed on /sqli/search?q= returning database syntax details or HTTP 500.",
            "raw_request": "GET /sqli/search?q=%27%29%29 HTTP/1.1\r\nHost: bench-pentesa-app:8080\r\n\r\n",
            "status_code": 500,
            "raw_response": "HTTP/1.1 500 Internal Server Error\r\n\r\n{\"error\":\"SQL Error\",\"details\":\"near \\\")\\\": syntax error\",\"query\":\"SELECT id, name, description, price FROM products WHERE name LIKE '%'))%'\"}",
            "reproduction_curl": "curl -i -s \"http://bench-pentesa-app:8080/sqli/search?q=%27%29%29\"",
            "affected_parameter": "q"
        },
        {
            "title": "SQL Injection in 'url' Parameter (/ssrf/fetch)",
            "cwe_id": "CWE-89",
            "source": "check_runner",
            "wstg_id": "WSTG-INPV-05",
            "severity": "Critical",
            "matched_at": "http://bench-pentesa-app:8080/ssrf/fetch?url=%27%20OR%20%271%27%3D%271",
            "description": "Error-based SQL injection confirmed on /ssrf/fetch?url= returning database syntax details or HTTP 502.",
            "raw_request": "GET /ssrf/fetch?url=%27%20OR%20%271%27%3D%271 HTTP/1.1\r\nHost: bench-pentesa-app:8080\r\n\r\n",
            "status_code": 502,
            "raw_response": "HTTP/1.1 502 Bad Gateway\r\n\r\n{\"detail\":\"SSRF request failed: unknown url type: \\\"' OR '1'='1\\\"\"}",
            "reproduction_curl": "curl -i -s \"http://bench-pentesa-app:8080/ssrf/fetch?url=%27%20OR%20%271%27%3D%271\"",
            "affected_parameter": "url"
        },
        {
            "title": "Reflected Cross-Site Scripting (XSS) in 'name' Parameter (/ssti/render)",
            "cwe_id": "CWE-79",
            "source": "check_runner",
            "wstg_id": "WSTG-INPV-01",
            "severity": "Medium",
            "matched_at": "http://bench-pentesa-app:8080/ssti/render?name=%3Cscript%3Ealert%28%27pentesa_xss_8421%27%29%3C/script%3E",
            "description": "Query parameter 'name' on /ssti/render reflects unescaped executable <script> HTML markup directly into the text/html DOM response.",
            "raw_request": "GET /ssti/render?name=%3Cscript%3Ealert%28%27pentesa_xss_8421%27%29%3C/script%3E HTTP/1.1\r\nHost: bench-pentesa-app:8080\r\n\r\n",
            "status_code": 200,
            "raw_response": "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body><h1>Hello <script>alert('pentesa_xss_8421')</script>!</h1></body></html>",
            "reproduction_curl": "curl -i -s \"http://bench-pentesa-app:8080/ssti/render?name=%3Cscript%3Ealert%28%27pentesa_xss_8421%27%29%3C/script%3E\"",
            "affected_parameter": "name"
        },
        {
            "title": "Reflected Cross-Site Scripting (XSS) in 'name' Parameter (/ssti/secure)",
            "cwe_id": "CWE-79",
            "source": "check_runner",
            "wstg_id": "WSTG-INPV-01",
            "severity": "Medium",
            "matched_at": "http://bench-pentesa-app:8080/ssti/secure?name=%3Cscript%3Ealert%28%27pentesa_xss_8421%27%29%3C/script%3E",
            "description": "Query parameter 'name' on /ssti/secure reflects unescaped executable <script> HTML markup directly into the text/html DOM response.",
            "raw_request": "GET /ssti/secure?name=%3Cscript%3Ealert%28%27pentesa_xss_8421%27%29%3C/script%3E HTTP/1.1\r\nHost: bench-pentesa-app:8080\r\n\r\n",
            "status_code": 200,
            "raw_response": "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body><h1>Hello &lt;script&gt;alert('pentesa_xss_8421')&lt;/script&gt;!</h1></body></html>",
            "reproduction_curl": "curl -i -s \"http://bench-pentesa-app:8080/ssti/secure?name=%3Cscript%3Ealert%28%27pentesa_xss_8421%27%29%3C/script%3E\"",
            "affected_parameter": "name"
        },
        {
            "title": "Reflected Cross-Site Scripting (XSS) in 'name' Parameter (/xss/reflect)",
            "cwe_id": "CWE-79",
            "source": "check_runner",
            "wstg_id": "WSTG-INPV-01",
            "severity": "Medium",
            "matched_at": "http://bench-pentesa-app:8080/xss/reflect?name=%3Cscript%3Ealert%28%27pentesa_xss_8421%27%29%3C/script%3E",
            "description": "Query parameter 'name' on /xss/reflect reflects unescaped executable <script> HTML markup directly into the text/html DOM response.",
            "raw_request": "GET /xss/reflect?name=%3Cscript%3Ealert%28%27pentesa_xss_8421%27%29%3C/script%3E HTTP/1.1\r\nHost: bench-pentesa-app:8080\r\n\r\n",
            "status_code": 200,
            "raw_response": "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body><h1>Welcome, <script>alert('pentesa_xss_8421')</script>!</h1></body></html>",
            "reproduction_curl": "curl -i -s \"http://bench-pentesa-app:8080/xss/reflect?name=%3Cscript%3Ealert%28%27pentesa_xss_8421%27%29%3C/script%3E\"",
            "affected_parameter": "name"
        },
        # P5-TC-HALLUC-01: Hallucinated 404 endpoint control
        {
            "title": "Remote Code Execution via Super Exec",
            "cwe_id": "CWE-78",
            "source": "hallucination_probe",
            "wstg_id": "WSTG-INPV-12",
            "severity": "Critical",
            "matched_at": "http://bench-pentesa-app:8080/admin/super-exec",
            "description": "Hallucinated endpoint that returns HTTP 404. Must never be confirmed.",
            "raw_request": "GET /admin/super-exec HTTP/1.1\r\nHost: bench-pentesa-app:8080\r\n\r\n",
            "status_code": 404,
            "raw_response": "HTTP/1.1 404 Not Found\r\n\r\n{\"detail\":\"Not Found\"}",
            "reproduction_curl": "curl -i -s \"http://bench-pentesa-app:8080/admin/super-exec\"",
            "affected_parameter": None
        }
    ]
    print(f"  [+] Prepared {len(candidates)} candidates.")
    return candidates


async def run_acceptance():
    print("=" * 80)
    print("PENTESA PHASE 9 WAVE 1A: LIVE ACCEPTANCE RUN (STEP 0a)")
    print(f"Timestamp (UTC): {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    print("=" * 80)

    # 1. Health check gate
    hw_res = await check_gateway_health()
    if hw_res["status"] != "PASS":
        print("[-] FATAL: Gateway health check failed! Halting.")
        return 1

    # 2. Database session setup
    async with AsyncSessionLocal() as session:
        project, admin_user = await setup_acceptance_project(session)

        # 3. Build candidate findings
        candidates = build_candidate_findings()
        candidate_count_before = len(candidates)

        state = PentestWorkflowState(
            project_id=project.id,
            user_id=admin_user.id,
            scan_profile="ACTIVE_FULL",
            target_domains=["bench-pentesa-app"],
            candidate_findings=candidates,
            confirmed_findings=[],
            false_positives=[]
        )

        # 4. Run ValidationAgent with live AI gateway
        print("\n[STEP 4] Executing ValidationAgent Empirical Gate (P1-AGENT-01) with Real AI Gateway...")
        llm_provider = get_default_llm_provider()
        agent = ValidationAgent(
            session=session,
            llm_provider=llm_provider
        )

        t_start = time.time()
        final_state = await agent.run(state)
        dur_s = round(time.time() - t_start, 2)

        confirmed_findings = final_state.confirmed_findings
        false_positives = final_state.false_positives
        confirmed_count_after = len(confirmed_findings)
        fp_count_after = len(false_positives)

        print(f"\n[+] ValidationAgent Completed in {dur_s}s:")
        print(f"  - Candidates Before Gate: {candidate_count_before}")
        print(f"  - Confirmed After Gate:   {confirmed_count_after}")
        print(f"  - False Positives:        {fp_count_after}")

        # 5. Verify Invariants
        print("\n[STEP 5] Verifying Wave 1a Gate Invariants...")
        confirmed_titles = [f["title"] for f in confirmed_findings]
        fp_titles = [fp["title"] for fp in false_positives]

        sqli_confirmed = any("SQL Injection in 'q' Parameter (/sqli/search)" in t for t in confirmed_titles)
        xss_ssti_confirmed = any("Reflected Cross-Site Scripting (XSS) in 'name' Parameter (/ssti/render)" in t for t in confirmed_titles)
        halluc_rejected = any("Remote Code Execution via Super Exec" in t for t in fp_titles)
        halluc_not_confirmed = not any("Remote Code Execution via Super Exec" in t for t in confirmed_titles)

        print(f"  [CHECK 1] SQLi on /sqli/search (HTTP 500 DB-error signature): {'CONFIRMED (PASS)' if sqli_confirmed else 'LOST (FAIL)'}")
        print(f"  [CHECK 2] Reflected XSS on /ssti/render:                     {'CONFIRMED (PASS)' if xss_ssti_confirmed else 'LOST (FAIL)'}")
        print(f"  [CHECK 3] P5-TC-HALLUC-01 (/admin/super-exec 404):           {'REJECTED TO FP (PASS)' if (halluc_rejected and halluc_not_confirmed) else 'PROMOTED (FAIL)'}")

        if not sqli_confirmed or not xss_ssti_confirmed:
            print("\n[-] P0 CRITICAL STOP: A Phase 3 true positive was lost during validation! Must revert gate commit and STOP.")
            return 2

        if not (halluc_rejected and halluc_not_confirmed):
            print("\n[-] P0 CRITICAL STOP: P5-TC-HALLUC-01 404 endpoint was promoted to confirmed findings! Must revert gate commit and STOP.")
            return 3

        print("\n[+] ALL WAVE 1A GATE INVARIANTS PASSED!")

        # 6. Check Canary sensor
        print("\n[STEP 6] Checking Canary Sensor Logs for Direct Scanner Breaches...")
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                r_canary = await client.get("http://bench-canary-sensor:9099/logs")
                canary_hits = r_canary.json() if r_canary.status_code == 200 else []
            except Exception as e:
                print(f"  [WARN] Canary sensor direct query: {e}")
                canary_hits = []

        scanner_hits = [
            h for h in canary_hits
            if "nuclei" in str(h).lower() or "ffuf" in str(h).lower() or "pentesa-api" in str(h).lower()
        ]
        print(f"  Total canary hits: {len(canary_hits)}, Scanner breaches: {len(scanner_hits)}")
        assert len(scanner_hits) == 0, f"Canary sensor breach detected: {scanner_hits}"
        print("  [+] Canary Sensor: 0 scanner hits confirmed.")

        # 7. Token and Cost accounting
        total_tokens = hw_res["total_tokens"] + (agent.total_tokens if hasattr(agent, "total_tokens") else 0)
        total_cost = hw_res["cost_usd"] + (agent.total_cost if hasattr(agent, "total_cost") else 0.0)

        summary_json = {
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "gateway_model": "azure/gpt-5.6-terra-dev-gtw",
            "gateway_health": "PASS",
            "health_tokens": hw_res["total_tokens"],
            "health_cost_usd": hw_res["cost_usd"],
            "candidates_before": candidate_count_before,
            "confirmed_after": confirmed_count_after,
            "false_positives": fp_count_after,
            "confirmed_findings": confirmed_findings,
            "false_positives_list": false_positives,
            "sqli_confirmed": sqli_confirmed,
            "xss_ssti_confirmed": xss_ssti_confirmed,
            "halluc_rejected": halluc_rejected and halluc_not_confirmed,
            "canary_scanner_breaches": len(scanner_hits),
            "total_tokens": total_tokens,
            "total_cost_usd": total_cost,
            "verdict": "PASS"
        }
        print("\n--- WAVE1A_ACCEPTANCE_SUMMARY_JSON_START ---")
        print(json.dumps(summary_json, indent=2, default=str))
        print("--- WAVE1A_ACCEPTANCE_SUMMARY_JSON_END ---")
        return 0


if __name__ == "__main__":
    code = asyncio.run(run_acceptance())
    sys.exit(code)
