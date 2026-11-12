"""Unit tests for WSTG test planner, applicability engine, and state transitions."""

import datetime
import uuid
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.discovery import Endpoint
from database.models.project import Project
from database.models.user import User
from database.models.wstg import WSTGTestCatalog, WSTGTestInstance
from packages.common.exceptions import BadRequestException
from services.execution_engine.planner import (
    initialize_project_wstg_instances,
    recalculate_project_test_plan,
    seed_wstg_catalog,
    validate_status_transition
)


def test_wstg_status_transitions():
    """Verify state transition rules adherence and rejection of illegal states."""
    # Valid transitions from Not Started
    validate_status_transition("Not Started", "Planned")
    validate_status_transition("Not Started", "Not Applicable", justification="Out of scope technology")

    # Invalid: Not Started -> Passed without running
    with pytest.raises(BadRequestException, match="Invalid WSTG status transition"):
        validate_status_transition("Not Started", "Passed")

    # Missing justification when setting Not Applicable
    with pytest.raises(BadRequestException, match="requires an explicit justification"):
        validate_status_transition("Planned", "Not Applicable", justification=None)

    # Valid running transitions
    validate_status_transition("Running", "Passed")
    validate_status_transition("Running", "Failed")
    validate_status_transition("Running", "Needs Manual Review")
    validate_status_transition("Running", "Blocked")
    validate_status_transition("Running", "Error")

    # Overriding terminal status requires justification
    validate_status_transition("Passed", "Failed", justification="Secondary inspection confirmed false positive clean")
    with pytest.raises(BadRequestException, match="requires an explicit justification"):
        validate_status_transition("Passed", "Failed", justification="")


@pytest.mark.asyncio
async def test_initialize_project_wstg_instances(db_session: AsyncSession, test_project: Project):
    """Verify that all 106 WSTG tests are initialized for a project in 'Not Started' state."""
    proj = test_project

    # Initialize instances
    created = await initialize_project_wstg_instances(db_session, proj.id)
    assert created == 106

    # Verify instances in DB
    result = await db_session.execute(
        select(WSTGTestInstance).where(WSTGTestInstance.project_id == proj.id)
    )
    instances = result.scalars().all()
    assert len(instances) == 106
    assert all(i.status == "Not Started" for i in instances)

    # Idempotent second call creates 0
    created2 = await initialize_project_wstg_instances(db_session, proj.id)
    assert created2 == 0


@pytest.mark.asyncio
async def test_recalculate_project_applicability(db_session: AsyncSession, test_project: Project):
    """Verify that discovering endpoints dynamically marks tests as Planned or Not Applicable."""
    proj = test_project

    # Add endpoints with parameters, auth, and API paths
    ep1 = Endpoint(
        project_id=proj.id,
        fqdn="app.acme.com",
        url_path="/api/v1/search",
        http_method="GET",
        parameter_schema={"query": ["q", "page"], "body": []},
        content_type="application/json",
        auth_required=False,
        discovery_source="CRAWLER"
    )
    ep2 = Endpoint(
        project_id=proj.id,
        fqdn="app.acme.com",
        url_path="/auth/login",
        http_method="POST",
        parameter_schema={"query": [], "body": ["username", "password"]},
        content_type="application/x-www-form-urlencoded",
        auth_required=False,
        discovery_source="CRAWLER"
    )
    db_session.add_all([ep1, ep2])
    await db_session.commit()

    # Recalculate plan
    summary = await recalculate_project_test_plan(db_session, proj.id)
    assert summary["total_instances"] == 106
    assert summary["planned_count"] > 0
    assert summary["not_applicable_count"] > 0

    # Verify SQL Injection (WSTG-INPV-05) is now Planned due to ep1 having query parameters
    sqli_stmt = select(WSTGTestInstance).where(
        WSTGTestInstance.project_id == proj.id,
        WSTGTestInstance.wstg_id == "WSTG-INPV-05"
    )
    sqli_inst = (await db_session.execute(sqli_stmt)).scalar_one()
    assert sqli_inst.status == "Planned"
    assert sqli_inst.applicable_endpoints_count >= 1

    # Verify Authentication test (WSTG-ATHN-01) is Planned due to ep2 (/auth/login)
    auth_stmt = select(WSTGTestInstance).where(
        WSTGTestInstance.project_id == proj.id,
        WSTGTestInstance.wstg_id == "WSTG-ATHN-01"
    )
    auth_inst = (await db_session.execute(auth_stmt)).scalar_one()
    assert auth_inst.status == "Planned"

    # Verify Legacy Flash (WSTG-CLNT-08) is marked Not Applicable with justification
    flash_stmt = select(WSTGTestInstance).where(
        WSTGTestInstance.project_id == proj.id,
        WSTGTestInstance.wstg_id == "WSTG-CLNT-08"
    )
    flash_inst = (await db_session.execute(flash_stmt)).scalar_one()
    assert flash_inst.status == "Not Applicable"
    assert "Flash" in flash_inst.justification


@pytest.mark.asyncio
async def test_dvwa_dict_parameter_schema_recalculate_no_crash_and_php_profile(
    db_session: AsyncSession,
    admin_user: User,
):
    """Verify DVWA list-of-dict form schemas recalculate cleanly without AttributeError and produce PHP HTTP matrix."""
    from database.models.discovery import Cookie, DiscoveredDomain, Technology
    from database.models.project import Project
    from database.models.scope import ScopeRule

    now = datetime.datetime.now(datetime.timezone.utc)
    dvwa = Project(
        id=uuid.uuid4(),
        name="DVWA Assessment",
        status="ACTIVE",
        target_domains=["dvwa", "localhost"],
        allow_internal_networks=True,
        authorization_start=now - datetime.timedelta(days=1),
        authorization_end=now + datetime.timedelta(days=10),
        created_by=admin_user.id,
    )
    db_session.add(dvwa)
    await db_session.flush()
    db_session.add(
        ScopeRule(
            id=uuid.uuid4(),
            project_id=dvwa.id,
            rule_type="EXACT_DOMAIN",
            target_type="IN_SCOPE",
            pattern="dvwa",
            protocol="http",
            port_range="80",
        )
    )
    db_session.add(
        DiscoveredDomain(
            id=uuid.uuid4(),
            project_id=dvwa.id,
            fqdn="dvwa",
            discovery_source="CRAWLER",
        )
    )
    db_session.add(
        Technology(
            id=uuid.uuid4(),
            project_id=dvwa.id,
            name="PHP",
            category="LANGUAGE",
            detected_on_url="http://dvwa/login.php",
        )
    )
    db_session.add(
        Cookie(
            id=uuid.uuid4(),
            project_id=dvwa.id,
            name="PHPSESSID",
            domain="dvwa",
            path="/",
            is_secure=False,
            is_httponly=False,
        )
    )
    db_session.add_all([
        Endpoint(
            project_id=dvwa.id,
            fqdn="dvwa",
            url_path="/login.php",
            http_method="POST",
            parameter_schema={
                "body": [
                    {"name": "username", "location": "body", "type": "string", "required": False},
                    {"name": "password", "location": "body", "type": "password", "required": False},
                    {"name": "user_token", "location": "body", "type": "hidden", "required": False},
                ]
            },
            content_type="application/x-www-form-urlencoded",
            discovery_source="FORM",
        ),
        Endpoint(
            project_id=dvwa.id,
            fqdn="dvwa",
            url_path="/vulnerabilities/upload/",
            http_method="POST",
            parameter_schema={
                "body": [
                    {"name": "uploaded", "location": "body", "type": "file", "required": False},
                    {"name": "Upload", "location": "body", "type": "submit", "required": False},
                ]
            },
            content_type="multipart/form-data",
            discovery_source="FORM",
        ),
        Endpoint(
            project_id=dvwa.id,
            fqdn="dvwa",
            url_path="/vulnerabilities/sqli/",
            http_method="GET",
            parameter_schema={"query": [{"name": "id", "location": "query", "type": "string"}]},
            content_type="text/html",
            discovery_source="CRAWLER",
        ),
    ])
    await db_session.commit()

    summary = await recalculate_project_test_plan(db_session, dvwa.id)
    assert summary["total_instances"] == 106
    assert summary["endpoints_analyzed"] == 3

    rows = (
        await db_session.execute(select(WSTGTestInstance).where(WSTGTestInstance.project_id == dvwa.id))
    ).scalars().all()
    by_id = {r.wstg_id: r for r in rows}

    assert by_id["WSTG-INPV-19"].status == "Planned"  # PHP LFI/RFI runtime
    assert by_id["WSTG-BUSL-08"].status == "Planned"  # File upload detected
    assert by_id["WSTG-SESS-02"].status == "Planned"  # Cookie PHPSESSID detected
    assert by_id["WSTG-CONF-07"].status == "Not Applicable"  # Plain HTTP only
    assert by_id["WSTG-CRYP-01"].status == "Not Applicable"  # Plain HTTP only
    assert by_id["WSTG-CLNT-10"].status == "Not Applicable"  # No WebSockets
    assert by_id["WSTG-APIT-01"].status == "Not Applicable"  # No JSON/REST API


@pytest.mark.asyncio
async def test_differentiated_wstg_matrices_across_target_archetypes(
    db_session: AsyncSession,
    admin_user: User,
):
    """Verify REST JSON API, WebSocket SPA, and pre-crawl HTTP projects produce genuinely distinct plans."""
    from database.models.discovery import DiscoveredDomain, Technology
    from database.models.project import Project
    from database.models.scope import ScopeRule

    now = datetime.datetime.now(datetime.timezone.utc)
    # Project A: Pure REST JSON API over HTTPS
    api_proj = Project(
        id=uuid.uuid4(),
        name="REST API Target",
        status="ACTIVE",
        target_domains=["api.example.com"],
        authorization_start=now - datetime.timedelta(days=1),
        authorization_end=now + datetime.timedelta(days=10),
        created_by=admin_user.id,
    )
    # Project B: SPA + WebSocket + HTTPS Target
    spa_proj = Project(
        id=uuid.uuid4(),
        name="SPA WebSocket Target",
        status="ACTIVE",
        target_domains=["spa.example.com"],
        authorization_start=now - datetime.timedelta(days=1),
        authorization_end=now + datetime.timedelta(days=10),
        created_by=admin_user.id,
    )
    # Project C: Pre-crawl local HTTP (0 endpoints)
    precrawl_proj = Project(
        id=uuid.uuid4(),
        name="Pre-Crawl HTTP Local",
        status="ACTIVE",
        target_domains=["127.0.0.1"],
        allow_internal_networks=True,
        authorization_start=now - datetime.timedelta(days=1),
        authorization_end=now + datetime.timedelta(days=10),
        created_by=admin_user.id,
    )
    db_session.add_all([api_proj, spa_proj, precrawl_proj])
    await db_session.flush()

    db_session.add_all([
        ScopeRule(id=uuid.uuid4(), project_id=api_proj.id, rule_type="EXACT_DOMAIN", target_type="IN_SCOPE", pattern="api.example.com", protocol="https", port_range="443"),
        ScopeRule(id=uuid.uuid4(), project_id=spa_proj.id, rule_type="EXACT_DOMAIN", target_type="IN_SCOPE", pattern="spa.example.com", protocol="https", port_range="443"),
        ScopeRule(id=uuid.uuid4(), project_id=precrawl_proj.id, rule_type="EXACT_DOMAIN", target_type="IN_SCOPE", pattern="127.0.0.1", protocol="http", port_range="8888"),
        DiscoveredDomain(id=uuid.uuid4(), project_id=api_proj.id, fqdn="api.example.com", discovery_source="CRAWLER"),
        DiscoveredDomain(id=uuid.uuid4(), project_id=spa_proj.id, fqdn="spa.example.com", discovery_source="CRAWLER"),
        Technology(id=uuid.uuid4(), project_id=api_proj.id, name="FastAPI", category="BACKEND_FRAMEWORK", detected_on_url="https://api.example.com/openapi.json"),
        Technology(id=uuid.uuid4(), project_id=spa_proj.id, name="Angular", category="FRONTEND_FRAMEWORK", detected_on_url="https://spa.example.com/"),
        Endpoint(
            project_id=api_proj.id,
            fqdn="api.example.com",
            url_path="/api/v1/orders/{id}",
            http_method="POST",
            parameter_schema={"path": [{"name": "id", "type": "integer"}], "json": [{"name": "quantity", "type": "integer"}]},
            content_type="application/json",
            auth_required=True,
            discovery_source="OPENAPI",
        ),
        Endpoint(
            project_id=spa_proj.id,
            fqdn="spa.example.com",
            url_path="/socket.io/",
            http_method="GET",
            parameter_schema={},
            content_type="application/json",
            discovery_source="JS_ANALYSIS",
        ),
        Endpoint(
            project_id=spa_proj.id,
            fqdn="spa.example.com",
            url_path="/",
            http_method="GET",
            parameter_schema={},
            content_type="text/html",
            discovery_source="CRAWLER",
        ),
    ])
    await db_session.commit()

    res_api = await recalculate_project_test_plan(db_session, api_proj.id)
    res_spa = await recalculate_project_test_plan(db_session, spa_proj.id)
    res_pre = await recalculate_project_test_plan(db_session, precrawl_proj.id)

    assert len({res_api["planned_count"], res_spa["planned_count"], res_pre["planned_count"]}) == 3

    api_map = {
        r.wstg_id: r.status
        for r in (await db_session.execute(select(WSTGTestInstance).where(WSTGTestInstance.project_id == api_proj.id))).scalars().all()
    }
    spa_map = {
        r.wstg_id: r.status
        for r in (await db_session.execute(select(WSTGTestInstance).where(WSTGTestInstance.project_id == spa_proj.id))).scalars().all()
    }
    pre_map = {
        r.wstg_id: r.status
        for r in (await db_session.execute(select(WSTGTestInstance).where(WSTGTestInstance.project_id == precrawl_proj.id))).scalars().all()
    }

    assert api_map["WSTG-APIT-01"] == "Planned"
    assert api_map["WSTG-APIT-07"] == "Planned"
    assert api_map["WSTG-CLNT-09"] == "Not Applicable"
    assert api_map["WSTG-INPV-01"] == "Not Applicable"
    assert api_map["WSTG-INPV-19"] == "Not Applicable"

    assert spa_map["WSTG-CLNT-10"] == "Planned"
    assert spa_map["WSTG-CLNT-09"] == "Planned"
    assert spa_map["WSTG-CONF-07"] == "Planned"

    assert pre_map["WSTG-CONF-07"] == "Not Applicable"
    assert pre_map["WSTG-CRYP-01"] == "Not Applicable"
    assert pre_map["WSTG-INFO-01"] == "Not Applicable"
    assert pre_map["WSTG-INPV-05"] == "Not Started"


@pytest.mark.asyncio
async def test_finding_lifecycle_synchronizes_wstg_instance_status(
    db_session: AsyncSession,
    test_project: Project,
    admin_user: User,
):
    """Verify Finding create/remediate/false-positive transitions update WSTGTestInstance automatically."""
    import httpx
    from packages.schemas.finding import FalsePositiveCreate, FindingCreate, FindingRetestRequest
    from services.evidence_engine.finding_service import FindingService

    await initialize_project_wstg_instances(db_session, test_project.id)
    f_service = FindingService(db_session)

    # 1. Create active SQLi finding -> WSTG-INPV-05 becomes Failed
    created = await f_service.create_finding(
        project_id=test_project.id,
        payload=FindingCreate(
            title="SQLi in Search",
            description="SQL syntax error confirmed",
            severity="Critical",
            cwe_id="CWE-89",
            wstg_id="WSTG-INPV-05",
            raw_request="GET /products?search=' HTTP/1.1\r\nHost: target.com\r\n\r\n",
            raw_response="HTTP/1.1 500 Internal Server Error\r\n\r\nSQLite3 error",
        ),
        user_id=admin_user.id,
    )
    inst = (
        await db_session.execute(
            select(WSTGTestInstance).where(
                WSTGTestInstance.project_id == test_project.id,
                WSTGTestInstance.wstg_id == "WSTG-INPV-05",
            )
        )
    ).scalar_one()
    assert inst.status == "Failed"

    # 2. Retest remediated -> WSTG-INPV-05 becomes Passed
    retest_res = await f_service.retest_finding(
        created.id,
        test_project.id,
        FindingRetestRequest(),
        user_id=admin_user.id,
        http_transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"ok": True})),
    )
    assert retest_res.new_status == "Remediated"
    await db_session.refresh(inst)
    assert inst.status == "Passed"

    # 3. Another finding refuted as False Positive -> reverts Failed to Planned
    fp_finding = await f_service.create_finding(
        project_id=test_project.id,
        payload=FindingCreate(
            title="CORS/Headers Observation",
            description="Checking behavior",
            severity="Low",
            wstg_id="WSTG-CONF-02",
        ),
        user_id=admin_user.id,
    )
    inst2 = (
        await db_session.execute(
            select(WSTGTestInstance).where(
                WSTGTestInstance.project_id == test_project.id,
                WSTGTestInstance.wstg_id == "WSTG-CONF-02",
            )
        )
    ).scalar_one()
    assert inst2.status == "Failed"

    await f_service.register_false_positive(
        fp_finding.id,
        test_project.id,
        FalsePositiveCreate(
            classification="INTENDED_BEHAVIOR",
            justification="Reviewed config and confirmed benign.",
        ),
        user_id=admin_user.id,
    )
    await db_session.refresh(inst2)
    assert inst2.status == "Planned"
