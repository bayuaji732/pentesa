"""Unit tests for tool wrappers: NucleiRunner and FfufRunner."""

import json
import pytest
from integrations.ffuf.runner import FfufRunner
from integrations.nuclei.runner import NucleiRunner
from packages.common.exceptions import ScopeViolationError


def test_nuclei_build_argv():
    """Verify safe argv compilation for Nuclei."""
    runner = NucleiRunner()
    argv = runner.build_argv(
        target_url="https://target.com",
        options={
            "tags": ["cve", "misconfig"],
            "severity": ["high", "critical"],
            "rate_limit": 25,
            "timeout": 10
        }
    )

    assert argv[0] == "nuclei"
    assert "-target" in argv
    assert argv[argv.index("-target") + 1] == "https://target.com"
    assert "-tags" in argv
    assert argv[argv.index("-tags") + 1] == "cve,misconfig"
    assert "-severity" in argv
    assert argv[argv.index("-severity") + 1] == "high,critical"
    assert "-rate-limit" in argv
    assert argv[argv.index("-rate-limit") + 1] == "25"
    assert "-timeout" in argv
    assert argv[argv.index("-timeout") + 1] == "10"
    assert "-jsonl" in argv
    assert "-no-interactsh" in argv


def test_nuclei_parse_output():
    """Verify JSONL output stream parsing into standardized finding dicts."""
    runner = NucleiRunner()
    raw_jsonl = (
        json.dumps({
            "template-id": "cve-2021-41773",
            "info": {
                "name": "Apache 2.4.49 Path Traversal",
                "severity": "critical",
                "description": "Path traversal flaw in Apache HTTP Server 2.4.49.",
                "classification": {
                    "cwe-id": ["CWE-22"]
                }
            },
            "matched-at": "https://target.com/icons/.%2e/%2e%2e/%2e%2e/etc/passwd",
            "curl-command": "curl -s -X GET 'https://target.com/icons/.%2e/%2e%2e/%2e%2e/etc/passwd'",
            "request": "GET /icons/.%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1\r\nHost: target.com\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\n\r\nroot:x:0:0:root:/root:/bin/bash"
        }) + "\n" +
        "invalid line that is not json\n"
    )

    findings = runner.parse_output(raw_jsonl)
    assert len(findings) == 1
    f = findings[0]
    assert f["title"] == "Apache 2.4.49 Path Traversal"
    assert f["severity"] == "Critical"
    assert f["cwe_id"] == "CWE-22"
    assert f["template_id"] == "cve-2021-41773"
    assert "passwd" in f["matched_at"]
    assert f["detection_source"] == "nuclei"


@pytest.mark.asyncio
async def test_nuclei_simulation():
    """Verify simulated execution when nuclei binary is absent."""
    runner = NucleiRunner()
    res = await runner.simulate_execution(
        target_url="https://target.com",
        argv=["nuclei"],
        options={"simulate_finding": True}
    )
    assert res.status == "SUCCESS"
    assert len(res.findings) == 1
    assert res.findings[0]["title"] == "Exposed Git Repository Configuration"
    assert res.findings[0]["severity"] == "High"


def test_ffuf_build_argv_rate_limit_capping():
    """Verify ffuf argv compilation and rate limit maximum cap enforcement."""
    runner = FfufRunner()
    # Requesting 150 rps should be capped at 50 rps
    argv = runner.build_argv(
        target_url="https://target.com",
        options={
            "wordlist_path": "/wordlists/common.txt",
            "rate_limit": 150
        }
    )

    assert argv[0] == "ffuf"
    assert "-u" in argv
    assert argv[argv.index("-u") + 1] == "https://target.com/FUZZ"
    assert "-w" in argv
    assert argv[argv.index("-w") + 1] == "/wordlists/common.txt"
    assert "-rate" in argv
    assert argv[argv.index("-rate") + 1] == "50"  # Enforced maximum
    assert "-fc" in argv
    assert "-of" in argv
    assert argv[argv.index("-of") + 1] == "json"


def test_ffuf_parse_output():
    """Verify ffuf JSON output parser."""
    runner = FfufRunner()
    raw_json = json.dumps({
        "results": [
            {
                "input": {"FUZZ": "admin"},
                "url": "https://target.com/admin",
                "status": 301,
                "length": 182,
                "words": 10,
                "lines": 5
            },
            {
                "input": {"FUZZ": "config.php"},
                "url": "https://target.com/config.php",
                "status": 200,
                "length": 0,
                "words": 0,
                "lines": 0
            }
        ]
    })

    matches = runner.parse_output(raw_json)
    assert len(matches) == 2
    assert matches[0]["title"] == "Discovered Path: /admin"
    assert matches[0]["status_code"] == 301
    assert matches[1]["title"] == "Discovered Path: /config.php"
    assert matches[1]["severity"] == "Medium"


@pytest.mark.asyncio
async def test_ffuf_simulation():
    """Verify simulated execution when ffuf binary is absent."""
    runner = FfufRunner()
    res = await runner.simulate_execution(
        target_url="https://target.com",
        argv=["ffuf"],
        options={"simulate_finding": True}
    )
    assert res.status == "SUCCESS"
    assert len(res.findings) == 1
    assert res.findings[0]["title"] == "Discovered Path: /backup.sql"


@pytest.mark.asyncio
async def test_runner_validate_scope_enforcement(db_session, test_project):
    """Verify pre-flight scope validation rejects out-of-scope and excluded targets."""
    runner = NucleiRunner()

    # In-scope URL: should not raise
    await runner.validate_scope(db_session, test_project.id, "https://api.target.com/v1/users")

    # Excluded path: should raise ScopeViolationError
    with pytest.raises(ScopeViolationError) as exc_info:
        await runner.validate_scope(db_session, test_project.id, "https://target.com/logout")
    assert "blocked by scope engine" in str(exc_info.value)

    # Completely out-of-scope domain: should raise ScopeViolationError
    with pytest.raises(ScopeViolationError) as exc_info:
        await runner.validate_scope(db_session, test_project.id, "https://malicious-target.org/probe")
    assert "blocked by scope engine" in str(exc_info.value)

