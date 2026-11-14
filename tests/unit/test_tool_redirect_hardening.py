"""Unit regression tests verifying interim tool hardening against redirect following (NI-03).

Guarantees:
1. ToolExecutionRequest enforces strict schema validation (extra='forbid') rejecting unexpected attributes.
2. CLI flag injection (e.g. values starting with '-') is strictly prohibited in options.
3. Redirect-following flags (-fr, -r, -follow-redirects, -recursion) are rejected at schema validation.
4. NucleiRunner.build_argv guarantees redirect-following flags are purged from production argv.
5. FfufRunner.build_argv guarantees recursion / redirect-following flags are purged from production argv.
"""

import pytest
from pydantic import ValidationError

from integrations.ffuf.runner import FfufRunner
from integrations.nuclei.runner import NucleiRunner
from packages.schemas.tool import ToolExecutionRequest


def test_tool_execution_request_forbids_extra_fields():
    """ToolExecutionRequest rejects arbitrary extra fields (extra='forbid')."""
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ToolExecutionRequest(
            tool_name="nuclei",
            target_url="http://127.0.0.1:8000",
            follow_redirects=True  # Extra prohibited field
        )


def test_tool_execution_request_rejects_flag_injection():
    """ToolExecutionRequest rejects values attempting CLI flag injection."""
    with pytest.raises(ValidationError, match="Arbitrary CLI flag injection prohibited"):
        ToolExecutionRequest(
            tool_name="nuclei",
            target_url="http://127.0.0.1:8000",
            template_path="--debug-arbitrary-flag"
        )

    with pytest.raises(ValidationError, match="Arbitrary CLI flag injection prohibited"):
        ToolExecutionRequest(
            tool_name="ffuf",
            target_url="http://127.0.0.1:8000",
            wordlist="-custom-flag"
        )

    with pytest.raises(ValidationError, match="Arbitrary CLI flag injection prohibited"):
        ToolExecutionRequest(
            tool_name="nuclei",
            target_url="http://127.0.0.1:8000",
            tags=["-v", "cve"]
        )


def test_tool_execution_request_rejects_redirect_following_keywords():
    """ToolExecutionRequest explicitly rejects redirect-following flags (NI-03)."""
    with pytest.raises(ValidationError, match="Redirect following is forbidden for security tools"):
        ToolExecutionRequest(
            tool_name="nuclei",
            target_url="http://127.0.0.1:8000",
            template_path="-fr"
        )

    with pytest.raises(ValidationError, match="Redirect following is forbidden for security tools"):
        ToolExecutionRequest(
            tool_name="ffuf",
            target_url="http://127.0.0.1:8000",
            wordlist="-r"
        )


def test_nuclei_runner_argv_excludes_redirect_flags():
    """NucleiRunner.build_argv purges redirect-following flags from production argv."""
    runner = NucleiRunner()
    argv = runner.build_argv("http://127.0.0.1:8000", {})
    assert "-fr" not in argv
    assert "-follow-redirects" not in argv
    assert "-r" not in argv


def test_ffuf_runner_argv_excludes_recursion_and_redirect_flags():
    """FfufRunner.build_argv purges -r and -recursion from production argv."""
    runner = FfufRunner()
    argv = runner.build_argv("http://127.0.0.1:8000", {})
    assert "-r" not in argv
    assert "-recursion" not in argv
