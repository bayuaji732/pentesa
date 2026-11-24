"""Regression test for DEFECT-INFRA-01: Compose container resource bounds audit."""

import os
import yaml
import pytest

COMPOSE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "docker-compose.yml"
)

PROD_SERVICES = ["api", "worker", "web", "db", "redis"]

def test_prod_compose_enforces_resource_limits():
    """Verify docker-compose.yml defines memory, CPU, and PID limits on all 5 production services."""
    assert os.path.exists(COMPOSE_PATH), f"docker-compose.yml not found at {COMPOSE_PATH}"
    with open(COMPOSE_PATH, "r", encoding="utf-8") as f:
        compose_cfg = yaml.safe_load(f)

    services = compose_cfg.get("services", {})
    missing_limits = []

    for s_name in PROD_SERVICES:
        assert s_name in services, f"Service '{s_name}' missing from docker-compose.yml"
        s = services[s_name]

        # Check memory limit
        has_mem = bool(s.get("mem_limit") or s.get("deploy", {}).get("resources", {}).get("limits", {}).get("memory"))
        # Check cpu limit
        has_cpu = bool(s.get("cpus") or s.get("deploy", {}).get("resources", {}).get("limits", {}).get("cpus"))
        # Check pids limit
        has_pids = bool(s.get("pids_limit") or s.get("deploy", {}).get("resources", {}).get("limits", {}).get("pids"))

        if not (has_mem and has_cpu and has_pids):
            missing_limits.append({
                "service": s_name,
                "has_memory": has_mem,
                "has_cpus": has_cpu,
                "has_pids": has_pids
            })

    assert not missing_limits, f"Services missing resource limits: {missing_limits}"
