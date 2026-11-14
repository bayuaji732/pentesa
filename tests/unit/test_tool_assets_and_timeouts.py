"""Unit tests verifying tool asset bundling and timeout separation (TOOL-ASSETS-01).

Guarantees:
1. Pinned Nuclei templates default to a valid existing templates directory.
2. Pinned ffuf wordlist defaults to a valid existing wordlist file.
3. In NucleiRunner, -timeout in argv reflects the per-request HTTP timeout (default 5s, clamped 1-30s),
   and does NOT conflate with the overall subprocess timeout_seconds (e.g. 180s or 300s).
4. In FfufRunner, wordlist in argv defaults to the baked common_paths.txt rather than a missing file.
5. Startup checks assert tool asset presence and fail in production if assets are missing.
"""

import os
import pytest
from apps.api.main import validate_tool_assets_startup
from integrations.ffuf.runner import DEFAULT_FFUF_WORDLIST, FfufRunner
from integrations.nuclei.runner import DEFAULT_NUCLEI_TEMPLATES, NucleiRunner
from packages.common.config import settings
from scripts.check_security_tools import verify_assets


def test_nuclei_runner_default_template_path():
    """NucleiRunner defaults to baked/fixture templates directory."""
    runner = NucleiRunner()
    argv = runner.build_argv("http://127.0.0.1:8000", {})

    assert "-t" in argv
    t_idx = argv.index("-t")
    template_path = argv[t_idx + 1]
    assert template_path == DEFAULT_NUCLEI_TEMPLATES
    assert os.path.exists(template_path)
    assert os.path.isdir(template_path)


def test_nuclei_runner_timeout_separation():
    """NucleiRunner separates per-request probe timeout from overall execution timeout."""
    runner = NucleiRunner()

    # Case A: Overall execution timeout is 300s, request_timeout is default
    argv_a = runner.build_argv("http://127.0.0.1:8000", {"timeout_seconds": 300})
    timeout_idx = argv_a.index("-timeout")
    assert argv_a[timeout_idx + 1] == "5"  # Default 5s per-probe, NOT 300!
    assert "300" not in argv_a

    # Case B: Explicit request_timeout of 10s
    argv_b = runner.build_argv("http://127.0.0.1:8000", {"request_timeout": 10, "timeout_seconds": 600})
    timeout_idx_b = argv_b.index("-timeout")
    assert argv_b[timeout_idx_b + 1] == "10"
    assert "600" not in argv_b

    # Case C: Request timeout clamping (must be within 1-30s)
    argv_c = runner.build_argv("http://127.0.0.1:8000", {"request_timeout": 999})
    timeout_idx_c = argv_c.index("-timeout")
    assert argv_c[timeout_idx_c + 1] == "30"  # Clamped to max 30s


def test_ffuf_runner_default_wordlist():
    """FfufRunner defaults to baked common_paths.txt wordlist."""
    runner = FfufRunner()
    argv = runner.build_argv("http://127.0.0.1:8000", {})

    assert "-w" in argv
    w_idx = argv.index("-w")
    wordlist_path = argv[w_idx + 1]
    assert wordlist_path == DEFAULT_FFUF_WORDLIST
    assert os.path.exists(wordlist_path)
    assert os.path.isfile(wordlist_path)
    assert os.path.getsize(wordlist_path) > 0


def test_check_security_tools_verify_assets():
    """CLI pre-flight check asserts assets are valid."""
    assert verify_assets() is True


def test_startup_validation_refuses_missing_assets_in_production(monkeypatch):
    """Production startup refuses to start if nuclei templates or ffuf wordlists are missing."""
    monkeypatch.setattr(settings, "env", "production")

    # Mock non-existent nuclei template path
    import integrations.nuclei.runner
    monkeypatch.setattr(integrations.nuclei.runner, "DEFAULT_NUCLEI_TEMPLATES", "/nonexistent/templates")

    with pytest.raises(RuntimeError, match="CRITICAL TOOL ASSET ERROR.*Nuclei templates"):
        validate_tool_assets_startup()

    # Restore templates, mock non-existent ffuf wordlist
    monkeypatch.setattr(integrations.nuclei.runner, "DEFAULT_NUCLEI_TEMPLATES", DEFAULT_NUCLEI_TEMPLATES)
    import integrations.ffuf.runner
    monkeypatch.setattr(integrations.ffuf.runner, "DEFAULT_FFUF_WORDLIST", "/nonexistent/wordlist.txt")

    with pytest.raises(RuntimeError, match="CRITICAL TOOL ASSET ERROR.*ffuf wordlist"):
        validate_tool_assets_startup()
