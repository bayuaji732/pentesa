#!/usr/bin/env python3
"""Setup Phase3-Bench Engagement and verify Scope Enforcement Guardrails (B0-4)."""

import asyncio
import datetime
import os
import secrets
import sys
import uuid
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.abspath("."))

from benchmark.run_benchmark import generate_evidence_header
from database.session import AsyncSessionLocal
from database.models.project import Project
from database.models.scope import ScopeRule
from database.models.user import User
from packages.common.security import hash_password
from packages.schemas.scope import ScopeRuleCreate
from services.scope_engine.validator import ScopeValidator
from sqlalchemy import select


# Pinned Benchmark Entry Hosts from ground_truth.yaml
BENCH_IN_SCOPE_TARGETS = [
    ("bench-pentesa-app", "8080", "http", "Pentesa Bench purpose-built target application"),
    ("bench-juiceshop", "3000", "http", "OWASP Juice Shop target application"),
    ("bench-dvwa", "80", "http", "Damn Vulnerable Web Application"),
    ("bench-webgoat", "8080", "http", "OWASP WebGoat target application"),
    ("bench-crapi-web", "80", "http", "OWASP crAPI Web UI"),
    ("bench-crapi-identity", "80", "http", "OWASP crAPI Identity Microservice"),
    ("bench-crapi-community", "80", "http", "OWASP crAPI Community Microservice"),
    ("bench-crapi-workshop", "80", "http", "OWASP crAPI Workshop Microservice"),
]

OUT_OF_SCOPE_PROBES = [
    ("bench-canary-sensor", "9099", "Explicit OUT_OF_SCOPE rule for SSRF canary sensor"),
    ("1.1.1.1", "80", "Public WAN IP address"),
    ("169.254.169.254", "80", "AWS/GCP/Azure Cloud IMDS metadata address"),
    ("192.168.100.50", "80", "Non-bench RFC 1918 private IP address"),
]


async def setup_engagement_and_verify_scope(evidence_path: str = "docs/audit/evidence/phase3/scope_check_proof.txt") -> bool:
    print("\n=== [B0-4] SETTING UP ENGAGEMENT 'Phase3-Bench' & SCOPE GUARD PROOF ===")
    
    async with AsyncSessionLocal() as session:
        # 1. Fetch or create admin/system user
        user_res = await session.execute(select(User).limit(1))
        user = user_res.scalars().first()
        if not user:
            print("[-] No user found in database. Seeding system user...")
            bench_env_file = os.path.join(os.path.abspath("."), ".env.benchmark")
            bench_pwd = os.getenv("PENTESA_BENCHMARK_ADMIN_PASSWORD")
            if not bench_pwd and os.path.exists(bench_env_file):
                from dotenv import dotenv_values
                cfg = dotenv_values(bench_env_file)
                bench_pwd = cfg.get("PENTESA_BENCHMARK_ADMIN_PASSWORD")

            pwd_to_hash = bench_pwd or secrets.token_urlsafe(32)
            user = User(
                id=uuid.uuid4(),
                email="benchmark-admin@pentesa.lab",
                full_name="Benchmark Lead",
                password_hash=hash_password(pwd_to_hash),
                role="ADMIN",
                is_active=False
            )
            session.add(user)
            await session.commit()
        else:
            # Enforce ENV RULES v2: benchmark-admin must remain inactive
            if user.email == "benchmark-admin@pentesa.lab" and user.is_active:
                user.is_active = False
                await session.commit()

        # 2. Look for existing engagement
        proj_res = await session.execute(select(Project).where(Project.name == "Phase3-Bench"))
        project = proj_res.scalars().first()

        now = datetime.datetime.now(datetime.timezone.utc)
        auth_start = now - datetime.timedelta(days=1)
        auth_end = now + datetime.timedelta(days=30)

        if not project:
            print("[+] Creating engagement 'Phase3-Bench' (allow_internal_networks=True)...")
            project = Project(
                id=uuid.uuid4(),
                name="Phase3-Bench",
                description="Phase 3 Isolated Pentest Effectiveness Benchmark Engagement",
                status="ACTIVE",
                allow_internal_networks=True,
                authorization_document_ref="ROE-PHASE3-BENCHMARK-ISOLATED",
                authorization_start=auth_start,
                authorization_end=auth_end,
                created_by=user.id,
                target_domains=[t[0] for t in BENCH_IN_SCOPE_TARGETS],
                allowed_cidrs=[],
                excluded_paths=["/logout", "/admin/delete"]
            )
            session.add(project)
            await session.commit()
            print(f"[+] Created Project: {project.id}")
        else:
            print(f"[+] Found existing engagement: {project.id}")
            project.allow_internal_networks = True
            project.status = "ACTIVE"
            project.authorization_start = auth_start
            project.authorization_end = auth_end
            await session.commit()

        # 3. Clear and re-populate scope rules for exact benchmark alignment
        existing_rules = (await session.execute(
            select(ScopeRule).where(ScopeRule.project_id == project.id)
        )).scalars().all()
        for r in existing_rules:
            await session.delete(r)
        await session.commit()

        # Add IN_SCOPE rules
        scope_rule_objs = []
        for host, port, proto, note in BENCH_IN_SCOPE_TARGETS:
            rule = ScopeRule(
                id=uuid.uuid4(),
                project_id=project.id,
                rule_type="EXACT_DOMAIN",
                target_type="IN_SCOPE",
                pattern=host,
                port_range=port,
                protocol=proto,
                notes=note
            )
            session.add(rule)
            scope_rule_objs.append(rule)

        # Add OUT_OF_SCOPE rules
        for host, port, note in OUT_OF_SCOPE_PROBES:
            rule = ScopeRule(
                id=uuid.uuid4(),
                project_id=project.id,
                rule_type="EXACT_DOMAIN" if not host.replace(".", "").isdigit() else "EXACT_IP",
                target_type="OUT_OF_SCOPE",
                pattern=host,
                port_range=port,
                notes=note
            )
            session.add(rule)
            scope_rule_objs.append(rule)

        await session.commit()
        print(f"[+] Configured {len(BENCH_IN_SCOPE_TARGETS)} IN_SCOPE rules and {len(OUT_OF_SCOPE_PROBES)} OUT_OF_SCOPE rules.")

        # 4. Instantiate ScopeValidator with live rules and run empirical verification
        rule_dicts = [
            ScopeRuleCreate(
                rule_type=r.rule_type,
                target_type=r.target_type,
                pattern=r.pattern,
                port_range=r.port_range,
                protocol=r.protocol
            )
            for r in scope_rule_objs
        ]
        validator = ScopeValidator(rules=rule_dicts, allow_internal=True)

        proof_lines = []
        proof_lines.append("[SECTION 1: IN-SCOPE TARGET VALIDATION (Expected: IN)]")
        all_in_passed = True
        for host, port, proto, note in BENCH_IN_SCOPE_TARGETS:
            test_url = f"{proto}://{host}:{port}/test-probe"
            res = validator.validate_url(test_url)
            status_str = "IN" if res.is_in_scope else "OUT"
            verdict = "PASS" if res.is_in_scope else "FAIL"
            if not res.is_in_scope:
                all_in_passed = False
            proof_lines.append(f"  [{verdict}] URL: {test_url:<45} => Status: {status_str:<4} Reason: {res.reason}")

        proof_lines.append("\n[SECTION 2: PROHIBITED & OUT-OF-SCOPE PROBES (Expected: OUT)]")
        all_out_passed = True
        for host, port, note in OUT_OF_SCOPE_PROBES:
            test_url = f"http://{host}:{port}/probe"
            res = validator.validate_url(test_url)
            status_str = "IN" if res.is_in_scope else "OUT"
            verdict = "PASS" if not res.is_in_scope else "FAIL (BREACH)"
            if res.is_in_scope:
                all_out_passed = False
            proof_lines.append(f"  [{verdict}] URL: {test_url:<45} => Status: {status_str:<4} Reason: {res.reason}")

        overall_verdict = all_in_passed and all_out_passed

        # SECTION 3: Live DNS and HTTP reachability from scanner stack
        proof_lines.append("\n[SECTION 3: DIRECT TARGET REACHABILITY & CANARY ISOLATION PROOF]")
        import socket, urllib.request
        all_reach_passed = True
        reachability_targets = [
            ("bench-pentesa-app", 8080, "/healthz"),
            ("bench-juiceshop", 3000, "/rest/admin/application-version"),
            ("bench-dvwa", 80, "/login.php"),
            ("bench-webgoat", 8080, "/WebGoat/login"),
            ("bench-crapi-web", 80, "/"),
            ("bench-crapi-identity", 8080, "/"),
            ("bench-crapi-community", 8087, "/"),
            ("bench-crapi-workshop", 8000, "/"),
        ]
        for host, port, path in reachability_targets:
            try:
                ip = socket.gethostbyname(host)
                url = f"http://{host}:{port}{path}"
                req = urllib.request.Request(url, headers={"User-Agent": "Pentesa-Audit/1.0"})
                try:
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        code = resp.status
                except urllib.error.HTTPError as e:
                    code = e.code
                proof_lines.append(f"  [PASS] {host:<24} -> IP: {ip:<15} Port: {port:<5} HTTP Status: {code}")
            except Exception as e:
                all_reach_passed = False
                proof_lines.append(f"  [FAIL] {host:<24} -> Resolution/Connection Failed: {e}")

        # Canary sensor isolation check (must NOT resolve / connect)
        try:
            canary_ip = socket.gethostbyname("bench-canary-sensor")
            all_reach_passed = False
            proof_lines.append(f"  [FAIL (BREACH)] bench-canary-sensor resolved to {canary_ip}")
        except Exception as e:
            proof_lines.append(f"  [PASS] bench-canary-sensor -> Isolated / Name not known ({type(e).__name__})")

        overall_verdict = overall_verdict and all_reach_passed
        proof_lines.append(f"\nSCOPE GUARD ENFORCEMENT VERDICT: {'PASS' if overall_verdict else 'FAIL'}")

        # 5. Write to evidence file with standardized header
        header = generate_evidence_header(
            "python benchmark/setup_engagement_and_scope_check.py --verify"
        )
        os.makedirs(os.path.dirname(evidence_path), exist_ok=True)
        with open(evidence_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(header)
            f.write(f"Engagement Name: Phase3-Bench\n")
            f.write(f"Engagement UUID: {project.id}\n")
            f.write(f"Allow Internal Networks: {project.allow_internal_networks}\n\n")
            f.write("\n".join(proof_lines) + "\n")

        print(f"[+] Scope guard evidence saved to {evidence_path} (Verdict: {'PASS' if overall_verdict else 'FAIL'})")
        return overall_verdict


if __name__ == "__main__":
    success = asyncio.run(setup_engagement_and_verify_scope())
    sys.exit(0 if success else 1)
