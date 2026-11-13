"""Controlled web fuzzer wrapper using ffuf."""

import json
from typing import Any, Dict, List, Optional
from services.execution_engine.tools.base import BaseToolWrapper, ToolExecutionResult


class FfufRunner(BaseToolWrapper):
    """Integrates ffuf with rate limiting, scope confinement, and JSON result parsing."""

    def __init__(self):
        super().__init__(tool_name="ffuf", binary_name="ffuf")

    def build_argv(self, target_url: str, options: Dict[str, Any]) -> List[str]:
        """Compile safe, non-shell argv for ffuf."""
        url_template = options.get("url_template")
        if not url_template:
            url_template = f"{target_url.rstrip('/')}/FUZZ"

        wordlist = options.get("wordlist_path") or "common_paths.txt"
        rate_limit = min(options.get("rate_limit", 20), 50)  # Capped at 50 rps max

        argv = [
            "ffuf",
            "-u", url_template,
            "-w", wordlist,
            "-rate", str(rate_limit),
            "-fc", "404",
            "-of", "json",
            "-s"
        ]

        filter_status = options.get("filter_status")
        if filter_status:
            argv.extend(["-fc", ",".join(str(s) for s in filter_status)])

        return argv

    def parse_output(self, stdout: str) -> List[Dict[str, Any]]:
        """Parse ffuf JSON output into standardized finding / match records."""
        matches = []
        if not stdout:
            return matches

        try:
            data = json.loads(stdout)
            results = data.get("results", [])
            for r in results:
                fuzz_val = r.get("input", {}).get("FUZZ", "")
                url = r.get("url", "")
                status_code = r.get("status", 200)

                matches.append({
                    "title": f"Discovered Path: /{fuzz_val}",
                    "description": f"Hidden endpoint or file discovered via controlled fuzzing (HTTP {status_code}).",
                    "severity": "Low" if status_code != 200 else "Medium",
                    "cwe_id": "CWE-538",
                    "wstg_id": "WSTG-CONF-04",
                    "matched_at": url,
                    "status_code": status_code,
                    "length": r.get("length"),
                    "words": r.get("words"),
                    "lines": r.get("lines"),
                    "reproduction_curl": f"curl -i -s '{url}'",
                    "raw_request": f"GET /{fuzz_val} HTTP/1.1\r\n\r\n",
                    "raw_response": f"HTTP/1.1 {status_code}\r\n\r\n",
                    "detection_source": "ffuf",
                    "confidence": "High"
                })
        except Exception:
            pass

        return matches

    async def simulate_execution(
        self,
        target_url: str,
        argv: List[str],
        options: Dict[str, Any]
    ) -> ToolExecutionResult:
        """Simulate ffuf execution when binary is not installed on the system (test mode only)."""
        mock_finding = options.get("simulate_finding", False)
        findings = []

        if mock_finding:
            findings.append({
                "title": "[SIMULATED] Discovered Path: /backup.sql",
                "description": "[SIMULATED TEST DATA] Sensitive database backup file identified via fuzzing.",
                "severity": "High",
                "cwe_id": "CWE-530",
                "wstg_id": "WSTG-CONF-04",
                "matched_at": f"{target_url}/backup.sql",
                "status_code": 200,
                "reproduction_curl": f"curl -i -s '{target_url}/backup.sql'",
                "raw_request": f"GET /backup.sql HTTP/1.1\r\n\r\n",
                "raw_response": "HTTP/1.1 200 OK\r\n\r\n-- Database Dump",
                "detection_source": "ffuf_simulated",
                "confidence": "Confirmed",
                "is_simulated": True
            })

        return ToolExecutionResult(
            tool_name="ffuf",
            target_url=target_url,
            argv=argv,
            status="SUCCESS",
            exit_code=0,
            duration_ms=100,
            stdout="[SIMULATED] ffuf simulation completed cleanly.",
            findings=findings,
            is_simulated=True
        )

