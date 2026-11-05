"""OWASP WSTG Test Planner & Applicability Engine.

Responsible for:
1. Seeding and updating the master WSTG v4.2 test catalog.
2. Initializing project-specific test matrices.
3. Analyzing attack surface inventory to determine test applicability.
4. Validating and enforcing WSTG test state transitions.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.discovery import Cookie, DiscoveredDomain, Endpoint, Technology
from database.models.wstg import WSTGTestCatalog, WSTGTestInstance
from packages.common.exceptions import BadRequestException
from services.execution_engine.wstg_catalog_data import WSTG_CATALOG_ITEMS


# Finite state transition rules for WSTG test cases
VALID_STATE_TRANSITIONS: Dict[str, Set[str]] = {
    "Not Started": {"Planned", "Not Applicable"},
    "Planned": {"Running", "Not Applicable", "Not Started"},
    "Running": {"Passed", "Failed", "Needs Manual Review", "Blocked", "Error", "Planned"},
    "Needs Manual Review": {"Passed", "Failed", "Running"},
    "Blocked": {"Running", "Planned", "Not Applicable"},
    "Error": {"Running", "Planned", "Not Applicable"},
    "Passed": {"Failed", "Needs Manual Review", "Not Applicable", "Planned"},  # Manual override
    "Failed": {"Passed", "Needs Manual Review", "Not Applicable", "Planned"},  # Manual override
    "Not Applicable": {"Planned", "Not Started"},
}


def validate_status_transition(
    current_status: str,
    new_status: str,
    justification: Optional[str] = None
) -> None:
    """Validate that a WSTG test status transition obeys the lifecycle state machine.
    
    Raises:
        BadRequestException: If transition is invalid or lacks mandatory justification.
    """
    if current_status == new_status:
        return

    allowed_targets = VALID_STATE_TRANSITIONS.get(current_status, set())
    if new_status not in allowed_targets:
        raise BadRequestException(
            f"Invalid WSTG status transition from '{current_status}' to '{new_status}'."
        )

    # Transitioning to 'Not Applicable' requires an explicit justification
    if new_status == "Not Applicable" and (not justification or not justification.strip()):
        raise BadRequestException(
            "Marking a WSTG test as 'Not Applicable' requires an explicit justification."
        )

    # Overriding a terminal result ('Passed' or 'Failed') requires justification
    if current_status in {"Passed", "Failed"} and (not justification or not justification.strip()):
        raise BadRequestException(
            f"Overriding a confirmed '{current_status}' test status requires an explicit justification."
        )


async def seed_wstg_catalog(session: AsyncSession) -> int:
    """Seed or update the master WSTG v4.2 test catalog in the database.
    
    Returns:
        Number of catalog items populated or refreshed.
    """
    stmt = select(WSTGTestCatalog)
    result = await session.execute(stmt)
    existing_map = {item.id: item for item in result.scalars().all()}

    count = 0
    for raw in WSTG_CATALOG_ITEMS:
        item_id = raw["id"]
        if item_id in existing_map:
            # Update attributes if needed
            existing = existing_map[item_id]
            existing.category = raw["category"]
            existing.category_code = raw["category_code"]
            existing.name = raw["name"]
            existing.description = raw["description"]
            existing.automation_capability = raw["automation_capability"]
            existing.default_risk = raw["default_risk"]
            existing.cwe_id = raw.get("cwe_id")
            existing.owasp_category = raw.get("owasp_category")
            existing.required_tools = raw.get("required_tools", [])
            existing.requires_human_review = raw.get("requires_human_review", False)
            existing.endpoint_types = raw.get("endpoint_types", [])
        else:
            new_item = WSTGTestCatalog(
                id=item_id,
                category=raw["category"],
                category_code=raw["category_code"],
                name=raw["name"],
                description=raw["description"],
                automation_capability=raw["automation_capability"],
                default_risk=raw["default_risk"],
                cwe_id=raw.get("cwe_id"),
                owasp_category=raw.get("owasp_category"),
                required_tools=raw.get("required_tools", []),
                requires_human_review=raw.get("requires_human_review", False),
                endpoint_types=raw.get("endpoint_types", [])
            )
            session.add(new_item)
        count += 1

    await session.commit()
    return count


async def initialize_project_wstg_instances(
    session: AsyncSession,
    project_id: uuid.UUID
) -> int:
    """Initialize WSTG test case instances for a project from the master catalog.
    
    Creates instances for any catalog test that hasn't yet been instantiated.
    
    Returns:
        Number of new test instances created.
    """
    # Fetch all catalog items
    catalog_stmt = select(WSTGTestCatalog)
    cat_result = await session.execute(catalog_stmt)
    catalog_items = cat_result.scalars().all()

    if not catalog_items:
        # Seed catalog if empty
        await seed_wstg_catalog(session)
        cat_result = await session.execute(catalog_stmt)
        catalog_items = cat_result.scalars().all()

    # Fetch existing instances for this project
    inst_stmt = select(WSTGTestInstance.wstg_id).where(WSTGTestInstance.project_id == project_id)
    inst_result = await session.execute(inst_stmt)
    existing_ids = set(inst_result.scalars().all())

    created = 0
    now = datetime.now(timezone.utc)
    for cat in catalog_items:
        if cat.id not in existing_ids:
            instance = WSTGTestInstance(
                project_id=project_id,
                wstg_id=cat.id,
                status="Not Started",
                notes=None,
                justification=None,
                applicable_endpoints_count=0,
                updated_at=now
            )
            session.add(instance)
            created += 1

    if created > 0:
        await session.commit()

    return created


async def recalculate_project_test_plan(
    session: AsyncSession,
    project_id: uuid.UUID
) -> Dict[str, Any]:
    """Analyze project attack surface and update WSTG test applicability.
    
    Determines whether tests should transition from 'Not Started' to 'Planned'
    or 'Not Applicable' based on empirical surface indicators (parameters,
    authentication endpoints, API routes, file upload controls, etc.).
    
    Returns:
        Summary dict of planned, applicable, and unchanged tests.
    """
    # Ensure instances are initialized
    await initialize_project_wstg_instances(session, project_id)

    # 1. Fetch project attack surface
    endpoints_stmt = select(Endpoint).where(Endpoint.project_id == project_id)
    endpoints = (await session.execute(endpoints_stmt)).scalars().all()

    cookies_stmt = select(Cookie).where(Cookie.project_id == project_id)
    cookies = (await session.execute(cookies_stmt)).scalars().all()

    tech_stmt = select(Technology).where(Technology.project_id == project_id)
    technologies = (await session.execute(tech_stmt)).scalars().all()

    # Surface feature indexing
    has_endpoints = len(endpoints) > 0
    has_cookies = len(cookies) > 0
    has_tech = len(technologies) > 0

    parameterized_endpoints = [
        e for e in endpoints
        if (e.parameter_schema and (
            e.parameter_schema.get("query") or
            e.parameter_schema.get("body") or
            e.parameter_schema.get("json") or
            e.parameter_schema.get("path")
        ))
    ]

    auth_endpoints = [
        e for e in endpoints
        if e.auth_required or any(k in e.url_path.lower() for k in ["login", "signin", "auth", "token", "session"])
    ]

    api_endpoints = [
        e for e in endpoints
        if e.url_path.lower().startswith("/api") or
        (e.content_type and "json" in e.content_type.lower()) or
        (e.parameter_schema and e.parameter_schema.get("json"))
    ]

    upload_endpoints = [
        e for e in endpoints
        if (e.content_type and "multipart" in e.content_type.lower()) or
        any(k in e.url_path.lower() for k in ["upload", "file", "avatar", "attachment"]) or
        (e.parameter_schema and any("file" in p.lower() for p in (e.parameter_schema.get("body") or [])))
    ]

    reset_pwd_endpoints = [
        e for e in endpoints
        if any(k in e.url_path.lower() for k in ["reset-password", "forgot-password", "recover"])
    ]

    # Fetch all project instances with their catalog metadata
    inst_stmt = (
        select(WSTGTestInstance, WSTGTestCatalog)
        .join(WSTGTestCatalog, WSTGTestInstance.wstg_id == WSTGTestCatalog.id)
        .where(WSTGTestInstance.project_id == project_id)
    )
    instances = (await session.execute(inst_stmt)).all()

    planned_count = 0
    na_count = 0
    now = datetime.now(timezone.utc)

    for instance, catalog in instances:
        # Respect manual status decisions (Passed, Failed, Running, Needs Manual Review)
        if instance.status in {"Running", "Passed", "Failed", "Needs Manual Review"}:
            continue

        applicable_count = 0
        is_applicable = False
        is_explicit_na = False
        na_reason = ""

        # Specific rule evaluations
        if catalog.id == "WSTG-CLNT-08":  # Cross-Site Flashing (Flash/SWF)
            # Unless .swf file exists in endpoints
            swf_endpoints = [e for e in endpoints if e.url_path.lower().endswith(".swf")]
            if not swf_endpoints:
                is_explicit_na = True
                na_reason = "No Adobe Flash or ActionScript (.swf) assets detected in discovered attack surface."
            else:
                is_applicable = True
                applicable_count = len(swf_endpoints)

        elif "PARAMETERIZED" in catalog.endpoint_types:
            if parameterized_endpoints:
                is_applicable = True
                applicable_count = len(parameterized_endpoints)
            elif has_endpoints:
                # Target has endpoints but none have params yet
                is_applicable = False
                applicable_count = 0

        elif "LOGIN" in catalog.endpoint_types or "AUTH" in catalog.endpoint_types:
            if auth_endpoints:
                is_applicable = True
                applicable_count = len(auth_endpoints)
            elif has_endpoints:
                is_applicable = False

        elif "API" in catalog.endpoint_types or "JSON" in catalog.endpoint_types:
            if api_endpoints:
                is_applicable = True
                applicable_count = len(api_endpoints)

        elif "UPLOAD" in catalog.endpoint_types:
            if upload_endpoints:
                is_applicable = True
                applicable_count = len(upload_endpoints)
            elif has_endpoints:
                is_explicit_na = True
                na_reason = "No file upload forms, multipart endpoints, or file parameters identified."

        elif "RESET_PASSWORD" in catalog.endpoint_types:
            if reset_pwd_endpoints:
                is_applicable = True
                applicable_count = len(reset_pwd_endpoints)

        elif "COOKIES" in catalog.endpoint_types:
            if has_cookies:
                is_applicable = True
                applicable_count = len(cookies)

        elif catalog.category_code == "WSTG-INFO":
            # Information gathering is universally applicable to web engagements
            is_applicable = True
            applicable_count = len(endpoints) if endpoints else 1

        elif catalog.id in {"WSTG-CONF-01", "WSTG-CONF-02", "WSTG-CONF-06", "WSTG-CONF-07", "WSTG-CRYP-01"}:
            # Core infrastructure, HTTP methods, HSTS, and TLS testing are applicable to all web hosts
            is_applicable = True
            applicable_count = len(endpoints) if endpoints else 1

        elif has_endpoints:
            # Default applicability for generic web tests when endpoints are known
            is_applicable = True
            applicable_count = len(endpoints)

        # Apply state transitions
        if is_explicit_na and instance.status != "Not Applicable":
            instance.status = "Not Applicable"
            instance.justification = na_reason
            instance.applicable_endpoints_count = 0
            instance.updated_at = now
            na_count += 1
        elif is_applicable and instance.status in {"Not Started", "Not Applicable"}:
            instance.status = "Planned"
            instance.applicable_endpoints_count = applicable_count
            instance.updated_at = now
            planned_count += 1
        elif instance.status == "Planned":
            instance.applicable_endpoints_count = applicable_count

    await session.commit()

    return {
        "project_id": str(project_id),
        "total_instances": len(instances),
        "planned_count": planned_count,
        "not_applicable_count": na_count,
        "summary": f"Recalculated test plan: {planned_count} tests planned, {na_count} marked not applicable."
    }
