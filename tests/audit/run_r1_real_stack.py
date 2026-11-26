"""R1 Verification: Default Admin & Bootstrap checks against real Docker stack."""

import os
import subprocess
import sys
import time
import httpx

from tests.audit.evidence_header import format_evidence_header


def run_command_capture(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    """Execute a system command and return exit code and combined output."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        combined = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode, combined.strip()
    except Exception as e:
        return -1, str(e)


def main():
    evidence_path = os.path.join(
        os.path.dirname(__file__), "../../docs/audit/evidence/phase2/r1_default_admin.txt"
    )
    os.makedirs(os.path.dirname(evidence_path), exist_ok=True)

    header = format_evidence_header(
        command="python tests/audit/run_r1_real_stack.py",
        execution_mode="running stack (HTTP http://127.0.0.1:8000 + PostgreSQL 16)"
    )

    out = [header]
    print(header)

    def log(msg: str):
        print(msg)
        out.append(msg)

    log("### R1.1: SCENARIO (A) - PENTESA_ENV=production, NO BOOTSTRAP FLAG")
    log("Resetting environment to fresh volume and starting database...")
    run_command_capture(["docker", "compose", "-f", "docker-compose.phase2.yml", "down", "-v"])
    code, c_out = run_command_capture(["docker", "compose", "-f", "docker-compose.phase2.yml", "up", "-d", "db", "redis"])
    time.sleep(5)

    log("Starting API container with NO bootstrap flags on fresh database...")
    api_cmd_a = [
        "docker", "run", "-d", "--name", "pentesa-r1-api-a",
        "--network", "phase2-internal",
        "-p", "127.0.0.1:8000:8000",
        "-e", "PENTESA_ENV=production",
        "-e", "PENTESA_DEBUG=false",
        "-e", "PENTESA_DATABASE_URL=postgresql+asyncpg://pentesa_user:Phase2_Secure_DB_Pass_2026!@db:5432/pentesa",
        "-e", "PENTESA_REDIS_URL=redis://redis:6379/0",
        "-e", "PENTESA_ENCRYPTION_KEY=phase2_master_vault_encryption_key_32b_hex!",
        "-e", "PENTESA_SECRET_KEY=Phase2_JWT_Secret_Key_32_Bytes_Long_Prod_Ready!",
        "-e", "PENTESA_LLM_PROVIDER=litellm",
        "-e", "PENTESA_LITELLM_BASE_URL=https://uat-ai-gateway.siloamhospitals.com/v1/",
        "-e", "PENTESA_LITELLM_API_KEY=" + os.getenv("PENTESA_LITELLM_API_KEY", "mock-test-key-inert"),
        "-e", "PENTESA_LITELLM_MODEL=azure/gpt-5.6-terra-dev-gtw",
        "pentesa-api:latest"
    ]
    code, c_out = run_command_capture(api_cmd_a)

    # Wait for /healthz
    healthy = False
    for _ in range(25):
        time.sleep(1)
        try:
            r = httpx.get("http://127.0.0.1:8000/healthz", timeout=2.0)
            if r.status_code == 200:
                healthy = True
                break
        except Exception:
            pass

    log(f"API Healthcheck reached: {healthy}")

    # Query DB directly to prove 0 users exist
    code, db_users = run_command_capture([
        "docker", "exec", "pentesa-phase2-db", "psql", "-U", "pentesa_user", "-d", "pentesa",
        "-t", "-c", "SELECT count(*) FROM users;"
    ])
    log(f"SQL Direct Verification: SELECT count(*) FROM users -> {db_users.strip()} users")
    assert db_users.strip() == "0", f"Expected 0 users, found {db_users.strip()}"

    # Real HTTP login attempt for admin@example.com
    log("\n--- Real HTTP Login Attempt (admin@example.com) ---")
    req_body = {"email": "admin@example.com", "password": "Admin123!Secure"}
    log("POST /api/v1/auth/login")
    log(f"Request Body: {req_body}")
    login_resp = httpx.post("http://127.0.0.1:8000/api/v1/auth/login", json=req_body, timeout=5.0)
    log(f"HTTP Status: {login_resp.status_code} (Expected: 401 Unauthorized)")
    log(f"Response Headers: {dict(login_resp.headers)}")
    log(f"Response Body: {login_resp.text}")
    assert login_resp.status_code == 401, f"Expected 401, got {login_resp.status_code}"
    log("Result Scenario (a): PASS (Zero users exist, HTTP login returns 401 Unauthorized)\n")

    # Clean up container A
    run_command_capture(["docker", "rm", "-f", "pentesa-r1-api-a"])

    log("### R1.2: SCENARIO (B) - BOOTSTRAP FLAG WITHOUT CREDENTIALS -> CONTAINER EXITS NON-ZERO")
    api_cmd_b = [
        "docker", "run", "--rm", "--name", "pentesa-r1-api-b",
        "--network", "phase2-internal",
        "-e", "PENTESA_ENV=production",
        "-e", "PENTESA_DATABASE_URL=postgresql+asyncpg://pentesa_user:Phase2_Secure_DB_Pass_2026!@db:5432/pentesa",
        "-e", "PENTESA_ENCRYPTION_KEY=phase2_master_vault_encryption_key_32b_hex!",
        "-e", "PENTESA_SECRET_KEY=Phase2_JWT_Secret_Key_32_Bytes_Long_Prod_Ready!",
        "-e", "PENTESA_LLM_PROVIDER=litellm",
        "-e", "PENTESA_LITELLM_BASE_URL=https://uat-ai-gateway.siloamhospitals.com/v1/",
        "-e", "PENTESA_LITELLM_API_KEY=" + os.getenv("PENTESA_LITELLM_API_KEY", "mock-test-key-inert"),
        "-e", "PENTESA_LITELLM_MODEL=azure/gpt-5.6-terra-dev-gtw",
        "-e", "PENTESA_BOOTSTRAP_ADMIN=true",
        "pentesa-api:latest"
    ]
    code_b, out_b = run_command_capture(api_cmd_b, timeout=20)
    log(f"Container Exit Code: {code_b} (Expected: non-zero)")
    log(f"Container Output:\n{out_b}")
    assert code_b != 0, "Container unexpectedly exited with 0"
    assert "PENTESA_BOOTSTRAP_ADMIN is enabled but PENTESA_BOOTSTRAP_ADMIN_EMAIL or PENTESA_BOOTSTRAP_ADMIN_PASSWORD is missing" in out_b
    log("Result Scenario (b): PASS (Refused startup when credentials missing, exited non-zero)\n")

    log("### R1.3: SCENARIO (C) - WEAK/DEFAULT PASSWORD (Admin123!Secure) -> REFUSED NON-ZERO")
    api_cmd_c = [
        "docker", "run", "--rm", "--name", "pentesa-r1-api-c",
        "--network", "phase2-internal",
        "-e", "PENTESA_ENV=production",
        "-e", "PENTESA_DATABASE_URL=postgresql+asyncpg://pentesa_user:Phase2_Secure_DB_Pass_2026!@db:5432/pentesa",
        "-e", "PENTESA_ENCRYPTION_KEY=phase2_master_vault_encryption_key_32b_hex!",
        "-e", "PENTESA_SECRET_KEY=Phase2_JWT_Secret_Key_32_Bytes_Long_Prod_Ready!",
        "-e", "PENTESA_LLM_PROVIDER=litellm",
        "-e", "PENTESA_LITELLM_BASE_URL=https://uat-ai-gateway.siloamhospitals.com/v1/",
        "-e", "PENTESA_LITELLM_API_KEY=" + os.getenv("PENTESA_LITELLM_API_KEY", "mock-test-key-inert"),
        "-e", "PENTESA_LITELLM_MODEL=azure/gpt-5.6-terra-dev-gtw",
        "-e", "PENTESA_BOOTSTRAP_ADMIN=true",
        "-e", "PENTESA_BOOTSTRAP_ADMIN_EMAIL=admin@pentesa-phase2.lab",
        "-e", "PENTESA_BOOTSTRAP_ADMIN_PASSWORD=Admin123!Secure",
        "pentesa-api:latest"
    ]
    code_c, out_c = run_command_capture(api_cmd_c, timeout=20)
    log(f"Container Exit Code: {code_c} (Expected: non-zero)")
    log(f"Container Output:\n{out_c}")
    assert code_c != 0, "Container unexpectedly accepted weak password"
    assert "Password contains prohibited common phrases" in out_c or "rejected" in out_c
    log("Result Scenario (c): PASS (Weak/default password rejected, exited non-zero)\n")

    log("### R1.4: SCENARIO (D) - STRONG PASSWORD -> ADMIN CREATED & LOGS IN")
    run_command_capture(["docker", "rm", "-f", "pentesa-phase2-api"])
    api_cmd_d = [
        "docker", "run", "-d", "--name", "pentesa-phase2-api",
        "--network", "phase2-internal",
        "-p", "127.0.0.1:8000:8000",
        "-e", "PENTESA_ENV=production",
        "-e", "PENTESA_DEBUG=false",
        "-e", "PENTESA_DATABASE_URL=postgresql+asyncpg://pentesa_user:Phase2_Secure_DB_Pass_2026!@db:5432/pentesa",
        "-e", "PENTESA_REDIS_URL=redis://redis:6379/0",
        "-e", "PENTESA_ENCRYPTION_KEY=phase2_master_vault_encryption_key_32b_hex!",
        "-e", "PENTESA_SECRET_KEY=Phase2_JWT_Secret_Key_32_Bytes_Long_Prod_Ready!",
        "-e", "PENTESA_BOOTSTRAP_ADMIN=true",
        "-e", "PENTESA_BOOTSTRAP_ADMIN_EMAIL=security-lead@phase2.lab",
        "-e", "PENTESA_BOOTSTRAP_ADMIN_PASSWORD=CyberSecOps_2026!Str0ng#Auth",
        "-e", "PENTESA_LLM_PROVIDER=litellm",
        "-e", "PENTESA_LITELLM_BASE_URL=https://uat-ai-gateway.siloamhospitals.com/v1/",
        "-e", "PENTESA_LITELLM_API_KEY=" + os.getenv("PENTESA_LITELLM_API_KEY", "mock-test-key-inert"),
        "-e", "PENTESA_LITELLM_MODEL=azure/gpt-5.6-terra-dev-gtw",
        "pentesa-api:latest"
    ]
    code_d, out_d = run_command_capture(api_cmd_d)

    # Connect to target network
    run_command_capture(["docker", "network", "connect", "phase2-targets", "pentesa-phase2-api"])

    healthy_d = False
    for _ in range(25):
        time.sleep(1)
        try:
            r = httpx.get("http://127.0.0.1:8000/healthz", timeout=2.0)
            if r.status_code == 200:
                healthy_d = True
                break
        except Exception:
            pass

    log(f"API Healthcheck with Bootstrap Admin: {healthy_d}")
    assert healthy_d, "API failed to reach healthy state"

    # Query DB to confirm admin user exists
    code, db_admin = run_command_capture([
        "docker", "exec", "pentesa-phase2-db", "psql", "-U", "pentesa_user", "-d", "pentesa",
        "-t", "-c", "SELECT email, role, is_active FROM users WHERE email='security-lead@phase2.lab';"
    ])
    log(f"SQL Direct Verification: {db_admin.strip()}")
    assert "security-lead@phase2.lab" in db_admin

    # HTTP Login with bootstrap admin credentials
    log("\n--- Real HTTP Login Attempt (security-lead@phase2.lab) ---")
    valid_body = {"email": "security-lead@phase2.lab", "password": "CyberSecOps_2026!Str0ng#Auth"}
    log("POST /api/v1/auth/login")
    log(f"Request Body: {valid_body}")
    login_succ = httpx.post("http://127.0.0.1:8000/api/v1/auth/login", json=valid_body, timeout=5.0)
    log(f"HTTP Status: {login_succ.status_code} (Expected: 200 OK)")
    log(f"Response Body: {login_succ.text}")
    assert login_succ.status_code == 200, f"Expected 200, got {login_succ.status_code}"
    tokens = login_succ.json()
    assert "access_token" in tokens

    # Authenticated /auth/me call
    auth_headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    me_resp = httpx.get("http://127.0.0.1:8000/api/v1/auth/me", headers=auth_headers, timeout=5.0)
    log(f"\nGET /api/v1/auth/me")
    log(f"HTTP Status: {me_resp.status_code} (Expected: 200 OK)")
    log(f"Profile: {me_resp.text}")
    assert me_resp.status_code == 200, f"Expected 200, got {me_resp.status_code}"
    assert me_resp.json()["email"] == "security-lead@phase2.lab"
    log("Result Scenario (d): PASS (Admin created and successfully authenticated via HTTP Bearer token)\n")

    # Write output to file
    with open(evidence_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    print(f"[SUCCESS] Evidence recorded to {evidence_path}")


if __name__ == "__main__":
    main()
