#!/usr/bin/env python3
"""Pentesa Bench Environment Reset Script with Safety Guard.

Guarantees that volume purges (down -v) can ONLY ever target the isolated
benchmark project ('pentesa-bench') and NEVER touch production ('pentesa-prod')
or development ('pentesa-dev').
"""

import argparse
import os
import subprocess
import sys
import yaml

BENCH_COMPOSE_FILE = os.path.join(os.path.dirname(__file__), "docker-compose.bench.yml")
AUTHORIZED_BENCH_PROJECT = "pentesa-bench"


def get_compose_project_name(compose_file: str) -> str:
    """Read the top-level 'name:' attribute from the compose file."""
    if not os.path.exists(compose_file):
        raise FileNotFoundError(f"Compose file not found: {compose_file}")
    with open(compose_file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("name", "") if isinstance(data, dict) else ""


def execute_bench_down_v(compose_file: str = BENCH_COMPOSE_FILE) -> bool:
    """Safely teardown and purge volumes for the benchmark stack ONLY."""
    project_name = get_compose_project_name(compose_file)

    # CRITICAL SAFETY GUARD: Refuse down -v unless project is strictly 'pentesa-bench'
    if project_name != AUTHORIZED_BENCH_PROJECT:
        error_msg = (
            f"CRITICAL SAFETY VIOLATION: Refusing to run 'down -v'!\n"
            f"Expected compose project name '{AUTHORIZED_BENCH_PROJECT}', but observed '{project_name}'.\n"
            f"Teardown aborted to protect non-benchmark (prod/dev) volumes."
        )
        print(f"[-] {error_msg}", file=sys.stderr)
        raise RuntimeError(error_msg)

    print(f"[+] Safety Guard Verified: compose project '{project_name}' matches '{AUTHORIZED_BENCH_PROJECT}'.")
    cmd = ["docker", "compose", "-f", compose_file, "-p", AUTHORIZED_BENCH_PROJECT, "down", "-v"]
    print(f"[+] Running: {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        print("[+] Benchmark stack successfully torn down with volumes purged.")
        return True
    else:
        print(f"[-] Docker compose down failed: {res.stderr}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Pentesa Bench Environment Safe Reset")
    parser.add_argument("--compose-file", default=BENCH_COMPOSE_FILE, help="Path to compose file")
    parser.add_argument("--purge-volumes", action="store_true", help="Execute docker compose down -v with safety guard")
    args = parser.parse_args()

    if args.purge_volumes:
        try:
            success = execute_bench_down_v(args.compose_file)
            sys.exit(0 if success else 1)
        except RuntimeError:
            sys.exit(2)
    else:
        # Default non-destructive state reset via API
        print("[*] Default state reset: use benchmark/run_benchmark.py or call /api/reset directly.")
        print("[*] Pass --purge-volumes to execute docker compose down -v under safety guard.")


if __name__ == "__main__":
    main()
