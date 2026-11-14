"""Deterministic Nuclei vulnerability scanner wrapper."""

import json
import os
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from services.execution_engine.tools.base import BaseToolWrapper, ToolExecutionResult

# Baked pinned nuclei templates path with fallback for local dev/test
DEFAULT_NUCLEI_TEMPLATES = os.getenv("PENTESA_NUCLEI_TEMPLATES_DIR", "/opt/nuclei-templates")
if not os.path.exists(DEFAULT_NUCLEI_TEMPLATES):
    _local_tpl = os.path.join(os.path.dirname(__file__), "templates")
    if os.path.exists(_local_tpl):
        DEFAULT_NUCLEI_TEMPLATES = _local_tpl
    else:
        DEFAULT_NUCLEI_TEMPLATES = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../tests/fixtures/nuclei"))


class NucleiRunner(BaseToolWrapper):
    """Integrates ProjectDiscovery's Nuclei scanner with safe argv and JSONL streaming output."""

    def __init__(self):
        super().__init__(tool_name="nuclei", binary_name="nuclei")

    def build_argv(self, target_url: str, options: Dict[str, Any]) -> List[str]:
        """Compile safe, non-shell argv for Nuclei with baked templates and separated per-probe timeout."""
        argv = [
            "nuclei",
            "-target", target_url,
            "-jsonl",
            "-no-interactsh",
            "-silent",
            "-duc"
        ]

        template_path = options.get("template_path") or options.get("templates") or DEFAULT_NUCLEI_TEMPLATES
        if template_path:
            argv.extend(["-t", str(template_path)])

        tags = options.get("tags")
        if tags:
            argv.extend(["-tags", ",".join(tags)])

        severity = options.get("severity")
        if severity:
            argv.extend(["-severity", ",".join(severity)])

        rate_limit = options.get("rate_limit", 20)
        argv.extend(["-rate-limit", str(rate_limit)])

        # Per-probe HTTP request timeout (TOOL-ASSETS-01): separated from overall subprocess execution timeout
        req_timeout = options.get("request_timeout") or options.get("probe_timeout")
        if req_timeout is None and "timeout" in options:
            raw_t = int(options["timeout"])
            req_timeout = raw_t if raw_t <= 30 else 5
        elif req_timeout is None:
            req_timeout = 5

        clamped_req_timeout = max(1, min(30, int(req_timeout)))
        argv.extend(["-timeout", str(clamped_req_timeout)])

        # NI-03 Interim Hardening: strictly ensure redirect-following flags are never present
        clean_argv = [a for a in argv if a not in ("-follow-redirects", "-fr", "-r")]
        return clean_argv

    def parse_output(self, stdout: str) -> List[Dict[str, Any]]:
        """Parse line-delimited JSON stream into structured finding objects."""
        findings = []
        if not stdout:
            return findings

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                raw_item = json.loads(line)
                info = raw_item.get("info", {})
                classification = info.get("classification", {})
                cwe_list = classification.get("cwe-id", [])
                cwe_id = cwe_list[0] if cwe_list else None

                finding = {
                    "title": info.get("name", raw_item.get("template-id", "Nuclei Finding")),
                    "description": info.get("description", "Vulnerability detected by Nuclei template."),
                    "severity": info.get("severity", "medium").capitalize(),
                    "cwe_id": cwe_id,
                    "wstg_id": raw_item.get("wstg_id", "WSTG-CONF-02"),
                    "matched_at": raw_item.get("matched-at", raw_item.get("host")),
                    "template_id": raw_item.get("template-id"),
                    "reproduction_curl": raw_item.get("curl-command"),
                    "raw_request": raw_item.get("request"),
                    "raw_response": raw_item.get("response"),
                    "detection_source": "nuclei",
                    "confidence": "High"
                }
                findings.append(finding)
            except Exception:
                continue

        return findings

    async def simulate_execution(
        self,
        target_url: str,
        argv: List[str],
        options: Dict[str, Any]
    ) -> ToolExecutionResult:
        """Simulate execution when Nuclei binary is not installed on the system (test mode only)."""
        mock_finding = options.get("simulate_finding", False)
        findings = []
        stdout = "[SIMULATED] Nuclei test engine simulation complete."

        if mock_finding:
            clean_base = target_url.rstrip("/")
            host_hdr = urlparse(target_url).netloc or clean_base
            findings.append({
                "title": "[SIMULATED] Exposed Git Repository Configuration",
                "description": "[SIMULATED TEST DATA] Git repository configuration directory (.git/config) is accessible.",
                "severity": "High",
                "cwe_id": "CWE-538",
                "wstg_id": "WSTG-CONF-04",
                "matched_at": f"{clean_base}/.git/config",
                "template_id": "git-config-exposure",
                "reproduction_curl": f"curl -i -s '{clean_base}/.git/config'",
                "raw_request": f"GET /.git/config HTTP/1.1\r\nHost: {host_hdr}\r\n\r\n",
                "raw_response": "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n[core]\r\nrepositoryformatversion = 0",
                "detection_source": "nuclei_simulated",
                "confidence": "Confirmed",
                "is_simulated": True
            })

        return ToolExecutionResult(
            tool_name="nuclei",
            target_url=target_url,
            argv=argv,
            status="SUCCESS",
            exit_code=0,
            duration_ms=120,
            stdout=stdout,
            findings=findings,
            is_simulated=True
        )

