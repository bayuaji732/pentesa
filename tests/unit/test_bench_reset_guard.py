"""Unit tests for benchmark environment reset guard."""

import pytest
import tempfile
import os
from benchmark.reset_bench import execute_bench_down_v, get_compose_project_name


def test_guard_refuses_non_bench_project():
    """Verify safety guard refuses down -v on prod or other projects."""
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yml") as f:
        f.write("name: pentesa-prod\nservices:\n  db:\n    image: postgres:16\n")
        temp_path = f.name

    try:
        with pytest.raises(RuntimeError, match="CRITICAL SAFETY VIOLATION: Refusing to run 'down -v'"):
            execute_bench_down_v(temp_path)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_guard_refuses_empty_or_missing_name():
    """Verify safety guard refuses down -v when name attribute is missing."""
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yml") as f:
        f.write("services:\n  db:\n    image: postgres:16\n")
        temp_path = f.name

    try:
        with pytest.raises(RuntimeError, match="CRITICAL SAFETY VIOLATION"):
            execute_bench_down_v(temp_path)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_get_compose_project_name_bench():
    """Verify proper detection of benchmark compose project name."""
    from benchmark.reset_bench import BENCH_COMPOSE_FILE
    name = get_compose_project_name(BENCH_COMPOSE_FILE)
    assert name == "pentesa-bench"
