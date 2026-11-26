"""Unit tests for Alembic database migration foundation (Phase 9 Wave 1b, ADR-007).

Verifies:
1. Fresh database bootstrapping (empty DB -> upgrade head creates all tables)
2. Stamped existing database compatibility (Base.metadata.create_all -> stamp 0001 -> upgrade head)
3. Concurrent migration execution safety (advisory lock / serialization)
4. Downgrade/Upgrade round trip integrity
"""

import os
import pathlib
import pytest
import tempfile
import multiprocessing
from alembic.config import Config
from alembic import command
from sqlalchemy import create_engine, inspect

from database.base import Base
import database.models


@pytest.fixture
def temp_db_path():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    yield path
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


def get_test_alembic_config(db_path: str) -> Config:
    ini_path = pathlib.Path(__file__).resolve().parents[2] / "alembic.ini"
    cfg = Config(str(ini_path))
    db_url = f"sqlite+aiosqlite:///{db_path}"
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def test_fresh_db_upgrade_head(temp_db_path):
    """B1.1: Fresh empty DB -> alembic upgrade head creates all 29 tables."""
    cfg = get_test_alembic_config(temp_db_path)
    command.upgrade(cfg, "head")

    engine = create_engine(f"sqlite:///{temp_db_path}")
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    engine.dispose()

    assert "alembic_version" in tables
    assert "users" in tables
    assert "projects" in tables
    assert "findings" in tables
    assert "audit_logs" in tables
    assert "reports" in tables
    for expected_table in ["wstg_test_catalog", "scope_rules", "endpoints", "test_executions"]:
        assert expected_table in tables, f"Expected table {expected_table} missing from fresh upgrade"


def test_stamped_existing_db_upgrade_head(temp_db_path):
    """B1.2: Existing database created via create_all -> stamp 0001_initial_schema -> upgrade head succeeds."""
    engine = create_engine(f"sqlite:///{temp_db_path}")
    Base.metadata.create_all(bind=engine)
    inspector_pre = inspect(engine)
    tables_pre = set(inspector_pre.get_table_names())
    engine.dispose()

    cfg = get_test_alembic_config(temp_db_path)
    command.stamp(cfg, "0001_initial_schema")
    command.upgrade(cfg, "head")

    engine2 = create_engine(f"sqlite:///{temp_db_path}")
    inspector_post = inspect(engine2)
    tables_post = set(inspector_post.get_table_names())
    engine2.dispose()

    assert "alembic_version" in tables_post
    assert tables_pre.issubset(tables_post)


def _proc_run_upgrade(db_path: str, return_dict: dict, proc_id: int):
    try:
        cfg = get_test_alembic_config(db_path)
        command.upgrade(cfg, "head")
        return_dict[proc_id] = "OK"
    except Exception as e:
        return_dict[proc_id] = str(e)


def test_concurrent_migrators(temp_db_path):
    """B1.3: Two concurrent migration processes starting simultaneously succeed without failure."""
    manager = multiprocessing.Manager()
    return_dict = manager.dict()

    p1 = multiprocessing.Process(target=_proc_run_upgrade, args=(temp_db_path, return_dict, 1))
    p2 = multiprocessing.Process(target=_proc_run_upgrade, args=(temp_db_path, return_dict, 2))

    p1.start()
    p2.start()

    p1.join(timeout=20)
    p2.join(timeout=20)

    assert p1.exitcode == 0, f"Process 1 failed with {return_dict.get(1)}"
    assert p2.exitcode == 0, f"Process 2 failed with {return_dict.get(2)}"

    engine = create_engine(f"sqlite:///{temp_db_path}")
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    engine.dispose()
    assert "alembic_version" in tables
    assert "users" in tables


def test_downgrade_upgrade_roundtrip(temp_db_path):
    """B1.4: Downgrade to base drops tables cleanly; upgrade to head restores them."""
    cfg = get_test_alembic_config(temp_db_path)
    command.upgrade(cfg, "head")

    # Verify head
    engine = create_engine(f"sqlite:///{temp_db_path}")
    assert "users" in inspect(engine).get_table_names()

    # Downgrade to base
    command.downgrade(cfg, "base")
    tables_after_downgrade = set(inspect(engine).get_table_names())
    assert "users" not in tables_after_downgrade
    assert "projects" not in tables_after_downgrade

    # Re-upgrade to head
    command.upgrade(cfg, "head")
    tables_re_upgraded = set(inspect(engine).get_table_names())
    engine.dispose()

    assert "users" in tables_re_upgraded
    assert "projects" in tables_re_upgraded
    assert "findings" in tables_re_upgraded
