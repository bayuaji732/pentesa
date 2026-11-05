"""Deterministic reproduction cURL command generator.

Transforms HTTP request attributes into fully executable, reproducible cURL commands.
"""

from typing import Dict, Optional
from services.evidence_engine.redactor import mask_sensitive_headers


def escape_shell_arg(arg: str) -> str:
    """Safely quote and escape argument for POSIX and Windows bash execution."""
    if not arg:
        return "''"
    # Replace single quote with '\''
    escaped = arg.replace("'", "'\\''")
    return f"'{escaped}'"


def generate_reproduction_curl(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    redact_auth: bool = True
) -> str:
    """Generate reproducible cURL command for forensic evidence."""
    cmd_parts = ["curl -i -s"]

    # HTTP method
    method_upper = method.upper()
    if method_upper != "GET":
        cmd_parts.append(f"-X {method_upper}")

    # Target URL
    cmd_parts.append(escape_shell_arg(url))

    # Headers
    hdrs = headers or {}
    if redact_auth:
        hdrs = mask_sensitive_headers(hdrs)

    for key, value in sorted(hdrs.items()):
        # Exclude standard connection / length headers from reproduction curl
        if key.lower() in {"content-length", "host", "connection", "accept-encoding"}:
            continue
        header_str = f"{key}: {value}"
        cmd_parts.append(f"-H {escape_shell_arg(header_str)}")

    # Request Body
    if body and method_upper in {"POST", "PUT", "PATCH", "DELETE"}:
        cmd_parts.append(f"--data-raw {escape_shell_arg(body)}")

    return " \\\n  ".join(cmd_parts)

