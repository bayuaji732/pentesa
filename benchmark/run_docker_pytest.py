"""Machine-captured Full Docker Pytest Runner for Phase 3 Part A Fix Round.
Runs:
1. docker compose -f docker-compose.test.yml up --build --abort-on-container-exit test-runner
2. Captures full test output, pass count, exit code.
3. Cleans up containers with docker compose -f docker-compose.test.yml down -v
4. Writes output to docs/audit/evidence/phase3/pytest_docker_run.txt
"""

import subprocess
import os
import sys
from datetime import datetime, timezone

EVIDENCE_FILE = r"docs/audit/evidence/phase3/pytest_docker_run.txt"

def main():
    ts = datetime.now(timezone.utc).isoformat()
    lines = []
    lines.append("=== PENTESA AUDIT EVIDENCE — PHASE 3 PART A FIX ROUND: DOCKER PYTEST SUITE ===")
    lines.append(f"Generated At (UTC): {ts}")
    lines.append("Scope: Full automated pytest execution inside isolated docker-compose.test.yml environment")
    lines.append("Command: docker compose -f docker-compose.test.yml up --build --abort-on-container-exit test-runner")
    lines.append("Evidence Standard: Machine-captured execution log, non-interactive, verifiable")
    lines.append("=" * 80)
    lines.append("")

    print("Starting docker compose test suite...")
    # First make sure any old test containers are down
    subprocess.run(["docker", "compose", "-f", "docker-compose.test.yml", "down", "-v"], capture_output=True)

    # Run the test runner
    res = subprocess.run(
        ["docker", "compose", "-f", "docker-compose.test.yml", "up", "--build", "--abort-on-container-exit", "test-runner"],
        capture_output=True,
        text=True,
        timeout=600
    )

    combined_output = res.stdout + "\n" + res.stderr
    lines.append(f"Exit code: {res.returncode}")
    lines.append("--- TEST OUTPUT ---")
    for l in combined_output.splitlines():
        lines.append(l)
    lines.append("--- END TEST OUTPUT ---")
    lines.append("")

    # Teardown
    print("Tearing down test containers...")
    subprocess.run(["docker", "compose", "-f", "docker-compose.test.yml", "down", "-v"], capture_output=True)

    lines.append("=" * 80)
    status_str = "PASS" if res.returncode == 0 else "FAIL"
    lines.append(f"RESULT: {status_str} (Exit code {res.returncode})")
    lines.append("=" * 80)

    content = "\n".join(lines) + "\n"
    os.makedirs(os.path.dirname(EVIDENCE_FILE), exist_ok=True)
    with open(EVIDENCE_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Evidence written to {EVIDENCE_FILE}")

if __name__ == "__main__":
    main()
