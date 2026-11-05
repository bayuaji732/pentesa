"""Unit tests for OWASP WSTG v4.2 master catalog data and database seeding."""

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.wstg import WSTGTestCatalog
from services.execution_engine.planner import seed_wstg_catalog
from services.execution_engine.wstg_catalog_data import WSTG_CATALOG_ITEMS, WSTG_CATEGORIES


def test_catalog_structure_and_completeness():
    """Verify that the static catalog contains all 12 categories and 106 tests."""
    assert len(WSTG_CATEGORIES) == 12
    assert len(WSTG_CATALOG_ITEMS) == 106

    expected_prefixes = {
        "WSTG-INFO": 10,
        "WSTG-CONF": 11,
        "WSTG-IDNT": 5,
        "WSTG-ATHN": 10,
        "WSTG-ATHZ": 4,
        "WSTG-SESS": 9,
        "WSTG-INPV": 19,
        "WSTG-ERRH": 2,
        "WSTG-CRYP": 4,
        "WSTG-BUSL": 9,
        "WSTG-CLNT": 13,
        "WSTG-APIT": 10,
    }

    seen_ids = set()
    category_counts = {}

    for item in WSTG_CATALOG_ITEMS:
        item_id = item["id"]
        assert item_id not in seen_ids, f"Duplicate WSTG ID found: {item_id}"
        seen_ids.add(item_id)

        cat_code = item["category_code"]
        assert cat_code in WSTG_CATEGORIES
        category_counts[cat_code] = category_counts.get(cat_code, 0) + 1

        # Check required fields
        assert item["name"]
        assert item["description"]
        assert item["automation_capability"] in {"Full", "Partial", "Manual"}
        assert item["default_risk"] in {"Critical", "High", "Medium", "Low", "Info"}
        assert isinstance(item["required_tools"], list)
        assert isinstance(item["endpoint_types"], list)

    for prefix, expected_count in expected_prefixes.items():
        assert category_counts[prefix] == expected_count, (
            f"Category {prefix} expected {expected_count} tests, got {category_counts.get(prefix, 0)}"
        )


@pytest.mark.asyncio
async def test_seed_wstg_catalog_idempotency(db_session: AsyncSession):
    """Verify seeding WSTG catalog is idempotent and populates all 106 entries."""
    # First seed
    count1 = await seed_wstg_catalog(db_session)
    assert count1 == 106

    # Verify rows in database
    result = await db_session.execute(select(WSTGTestCatalog))
    rows = result.scalars().all()
    assert len(rows) == 106

    # Check sample item
    sqli = await db_session.get(WSTGTestCatalog, "WSTG-INPV-05")
    assert sqli is not None
    assert sqli.name == "Testing for SQL Injection"
    assert sqli.cwe_id == "CWE-89"
    assert sqli.automation_capability == "Full"
    assert sqli.default_risk == "Critical"

    # Second seed (idempotent update)
    count2 = await seed_wstg_catalog(db_session)
    assert count2 == 106

    result2 = await db_session.execute(select(WSTGTestCatalog))
    assert len(result2.scalars().all()) == 106

