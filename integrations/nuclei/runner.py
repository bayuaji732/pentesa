"""Deterministic Nuclei vulnerability scanner wrapper."""

import json
from typing import Any, Dict, List, Optional
from services.execution_engine.tools.base import BaseToolWrapper, ToolExecutionResult


class NucleiRunner(BaseToolWrapper):
    """Integrates ProjectDiscovery's Nuclei scanner with safe argv and JSONL streaming output."""

    def __init__(self):
        super().__init__(tool_name="nuclei", binary_name="nuclei")

    def build_argv(self, target_url: str, options: Dict[str, Any]) -> List[str]:
        """Compile safe, non-shell argv for Nuclei."""
        argv = [
            "nuclei",
            "-target", target_url,
            "-jsonl",
            "-no-interactsh",
            "-silent"
        ]

        tags = options.get("tags")
        if tags:
            argv.extend(["-tags", ",".join(tags)])

        severity = options.get("severity")
        if severity:
            argv.extend(["-severity", ",".join(severity)])

        rate_limit = options.get("rate_limit", 20)
        argv.extend(["-rate-limit", str(rate_limit)])

        timeout = options.get("timeout", 5)
        argv.extend(["-timeout", str(timeout)])

        return argv

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
        """Simulate execution when Nuclei binary is not installed on the system."""
        # Check if simulation should trigger a mock finding for test coverage
        mock_finding = options.get("simulate_finding", False)
        findings = []
        stdout = "Nuclei v3.0.0 engine simulation complete."

        if mock_finding:
            findings.append({
                "title": "Exposed Git Repository Configuration",
                "description": "Git repository configuration directory (.git/config) is accessible.",
                "severity": "High",
                "cwe_id": "CWE-538",
                "wstg_id": "WSTG-CONF-04",
                "matched_at": f"{target_url}/.git/config",
                "template_id": "git-config-exposure",
                "reproduction_curl": f"curl -i -s '{target_url}/.git/config'",
                "raw_request": f"GET /.git/config HTTP/1.1\r\nHost: target.com\r\n\r\n",
                "raw_response": "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n[core]\r\nrepositoryformatversion = 0",
                "detection_source": "nuclei",
                "confidence": "Confirmed"
            })

        return ToolExecutionResult(
            tool_name="nuclei",
            target_url=target_url,
            argv=argv,
            status="SUCCESS",
            exit_code=0,
            duration_ms=120,
            stdout=stdout,
            findings=findings
        )

