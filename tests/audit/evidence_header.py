"""Evidence header generator following Phase 2 S3 standard."""

from datetime import datetime, timezone
import subprocess
from typing import Optional


def get_pg_version() -> str:
    """Fetch live PostgreSQL version from docker container."""
    try:
        res = subprocess.check_output(
            ["docker", "exec", "pentesa-phase2-db", "psql", "-U", "pentesa_user", "-d", "pentesa", "-t", "-c", "SELECT version();"],
            text=True,
            timeout=5
        ).strip()
        return res
    except Exception as e:
        return f"PostgreSQL 16 (live container check failed: {e})"


def get_git_info() -> str:
    """Fetch current git commit SHA and dirty flag."""
    try:
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        sha = "unknown"
    try:
        dirty_out = subprocess.check_output(["git", "status", "--porcelain"], text=True).strip()
        dirty = " (dirty)" if dirty_out else " (clean)"
    except Exception:
        dirty = ""
    return f"{sha}{dirty}"


def format_evidence_header(command: str, execution_mode: str = "running stack (HTTP + PostgreSQL 16)") -> str:
    """Produce standardized machine header for all Phase 2 evidence files."""
    utc_now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    git_info = get_git_info()
    db_ver = get_pg_version()

    lines = [
        "=" * 80,
        "PENTESA PHASE 2 AUDIT EVIDENCE RECORD",
        f"Timestamp (UTC): {utc_now}",
        f"Git SHA:         {git_info}",
        f"Command:         {command}",
        f"Database:        {db_ver}",
        f"Execution Mode:  {execution_mode}",
        "=" * 80,
        ""
    ]
    return "\n".join(lines)
