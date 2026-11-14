"""Controlled web fuzzer wrapper using ffuf."""

import json
import os
from typing import Any, Dict, List, Optional
from services.execution_engine.tools.base import BaseToolWrapper, ToolExecutionResult

# Baked pinned ffuf wordlist path with fallback for local dev/test
DEFAULT_FFUF_WORDLIST = os.getenv("PENTESA_FFUF_WORDLIST_PATH", "/opt/wordlists/common_paths.txt")
if not os.path.exists(DEFAULT_FFUF_WORDLIST):
    _local_wl = os.path.join(os.path.dirname(__file__), "wordlists", "common_paths.txt")
    if os.path.exists(_local_wl):
        DEFAULT_FFUF_WORDLIST = _local_wl
    else:
        DEFAULT_FFUF_WORDLIST = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../tests/fixtures/ffuf/wordlist.txt"))


class FfufRunner(BaseToolWrapper):
    """Integrates ffuf with rate limiting, scope confinement, and JSON result parsing."""

    def __init__(self):
        super().__init__(tool_name="ffuf", binary_name="ffuf")

    def build_argv(self, target_url: str, options: Dict[str, Any]) -> List[str]:
        """Compile safe, non-shell argv for ffuf with baked wordlist default."""
        url_template = options.get("url_template")
        if not url_template:
            url_template = f"{target_url.rstrip('/')}/FUZZ"

        wordlist = options.get("wordlist_path") or DEFAULT_FFUF_WORDLIST
        rate_limit = min(options.get("rate_limit", 20), 50)  # Capped at 50 rps max

        argv = [
            "ffuf",
            "-u", url_template,
            "-w", wordlist,
            "-rate", str(rate_limit),
            "-fc", "404",
            "-ac",
            "-json",
            "-of", "json",
            "-s"
        ]

        filter_status = options.get("filter_status")
        if filter_status:
            argv.extend(["-fc", ",".join(str(s) for s in filter_status)])

        # NI-03 Interim Hardening: strictly ensure redirect-following and recursion flags are never present
        clean_argv = [a for a in argv if a not in ("-r", "-recursion")]
        return clean_argv

    def parse_output(self, stdout: str, baseline: Optional[Any] = None) -> List[Dict[str, Any]]:
        """Parse ffuf newline-delimited or array JSON output into standardized finding records."""
        matches = []
        if not stdout:
            return matches

        import base64
        from urllib.parse import urlparse

        # Process each line as newline-delimited JSON or parse full JSON object
        raw_results = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                parsed = json.loads(line)
                if "results" in parsed and isinstance(parsed["results"], list):
                    raw_results.extend(parsed["results"])
                else:
                    raw_results.append(parsed)
            except Exception:
                continue

        for r in raw_results:
            fuzz_val = r.get("input", {}).get("FUZZ", "")
            if fuzz_val:
                try:
                    b_dec = base64.b64decode(fuzz_val).decode("utf-8")
                    if b_dec and all(32 <= ord(c) <= 126 for c in b_dec):
                        fuzz_val = b_dec
                except Exception:
                    pass

            url = r.get("url", "")
            if not fuzz_val and url:
                fuzz_val = urlparse(url).path.lstrip("/")

            status_code = r.get("status", 200)
            length = r.get("length")

            # Filter out soft-404 / SPA catch-all false positives (TOOL-FP-01)
            if baseline and getattr(baseline, "has_soft_404", False):
                if baseline.is_match(status=status_code, length=length):
                    continue

            matches.append({
                "title": f"Discovered Path: /{fuzz_val}",
                "description": f"Hidden endpoint or file discovered via controlled fuzzing (HTTP {status_code}).",
                "severity": "Low" if status_code != 200 else "Medium",
                "cwe_id": "CWE-538",
                "wstg_id": "WSTG-CONF-04",
                "matched_at": url,
                "status_code": status_code,
                "length": length,
                "words": r.get("words"),
                "lines": r.get("lines"),
                "reproduction_curl": f"curl -i -s '{url}'",
                "raw_request": f"GET /{fuzz_val} HTTP/1.1\r\n\r\n",
                "raw_response": f"HTTP/1.1 {status_code}\r\n\r\n",
                "detection_source": "ffuf",
                "confidence": "High"
            })

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

