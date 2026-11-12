"""Integration tests for Attack Surface Discovery API endpoints."""

import uuid
import httpx
import pytest
from httpx import AsyncClient

from database.models.discovery import Endpoint, Technology


@pytest.mark.asyncio
async def test_domains_api_crud(
    client: AsyncClient,
    admin_token: str,
    test_project
):
    """Verify listing and creating discovered domains/subdomains."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create new domain
    domain_payload = {
        "fqdn": "sub.target.com",
        "resolved_ips": ["203.0.113.10"],
        "discovery_source": "MANUAL",
        "is_active": True
    }
    create_resp = await client.post(
        f"/api/v1/projects/{test_project.id}/domains",
        json=domain_payload,
        headers=headers
    )
    assert create_resp.status_code == 201
    created = create_resp.json()
    assert created["fqdn"] == "sub.target.com"

    # Duplicate domain should return 409 Conflict
    dup_resp = await client.post(
        f"/api/v1/projects/{test_project.id}/domains",
        json=domain_payload,
        headers=headers
    )
    assert dup_resp.status_code == 409

    # List domains
    list_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/domains",
        headers=headers
    )
    assert list_resp.status_code == 200
    domains = list_resp.json()
    assert any(d["fqdn"] == "sub.target.com" for d in domains)


@pytest.mark.asyncio
async def test_endpoints_api_crud(
    client: AsyncClient,
    admin_token: str,
    test_project
):
    """Verify endpoint inventory CRUD, search, and pagination."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Create Endpoint
    ep_payload = {
        "fqdn": "target.com",
        "url_path": "/api/v1/users/{id}",
        "http_method": "GET",
        "parameter_schema": {
            "path": [{"name": "id", "type": "integer", "required": True}],
            "query": [{"name": "details", "type": "boolean"}]
        },
        "content_type": "application/json",
        "auth_required": True,
        "discovery_source": "MANUAL"
    }
    create_resp = await client.post(
        f"/api/v1/projects/{test_project.id}/endpoints",
        json=ep_payload,
        headers=headers
    )
    assert create_resp.status_code == 201
    created_ep = create_resp.json()
    endpoint_id = created_ep["id"]
    assert created_ep["url_path"] == "/api/v1/users/{id}"
    assert created_ep["auth_required"] is True

    # 2. Get Endpoint by ID
    get_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/endpoints/{endpoint_id}",
        headers=headers
    )
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == endpoint_id

    # 3. List Endpoints with Filter and Search
    list_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/endpoints?search=users&http_method=GET",
        headers=headers
    )
    assert list_resp.status_code == 200
    data = list_resp.json()
    assert data["total"] >= 1
    assert any(e["id"] == endpoint_id for e in data["items"])

    # 4. Update Endpoint Status
    update_resp = await client.put(
        f"/api/v1/projects/{test_project.id}/endpoints/{endpoint_id}",
        json={"testing_status": "Testing", "auth_required": False},
        headers=headers
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["testing_status"] == "Testing"
    assert update_resp.json()["auth_required"] is False

    # 5. Delete Endpoint
    del_resp = await client.delete(
        f"/api/v1/projects/{test_project.id}/endpoints/{endpoint_id}",
        headers=headers
    )
    assert del_resp.status_code == 204

    # Confirm deletion
    get_deleted = await client.get(
        f"/api/v1/projects/{test_project.id}/endpoints/{endpoint_id}",
        headers=headers
    )
    assert get_deleted.status_code == 404


@pytest.mark.asyncio
async def test_technologies_and_attack_surface_graph_api(
    client: AsyncClient,
    admin_token: str,
    test_project,
    db_session
):
    """Verify technologies listing and attack surface topology graph retrieval."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Seed an endpoint and a technology directly into db
    tech = Technology(
        id=uuid.uuid4(),
        project_id=test_project.id,
        name="FastAPI",
        version="0.110.0",
        category="BACKEND_FRAMEWORK",
        confidence=100
    )
    ep = Endpoint(
        id=uuid.uuid4(),
        project_id=test_project.id,
        fqdn="target.com",
        url_path="/healthz",
        http_method="GET",
        parameter_schema={},
        discovery_source="MANUAL",
        testing_status="Discovered"
    )
    db_session.add_all([tech, ep])
    await db_session.commit()

    # List technologies
    tech_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/technologies",
        headers=headers
    )
    assert tech_resp.status_code == 200
    techs = tech_resp.json()
    assert any(t["name"] == "FastAPI" for t in techs)

    # Get attack surface topology graph
    graph_resp = await client.get(
        f"/api/v1/projects/{test_project.id}/attack-surface/graph",
        headers=headers
    )
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()
    assert "nodes" in graph_data
    assert "edges" in graph_data
    assert graph_data["stats"]["endpoints"] >= 1
    assert graph_data["stats"]["technologies"] >= 1


@pytest.mark.asyncio
async def test_discovery_execute_crawl_persists_cookies_and_form_schemas(
    db_session,
    test_project,
):
    """Verify DiscoveryService.execute_crawl persists Cookie records and multipart form schemas cleanly."""
    from sqlalchemy import select
    from database.models.discovery import Cookie
    from packages.schemas.discovery import CrawlRequest
    from services.discovery_engine.service import discovery_service

    await db_session.refresh(test_project, attribute_names=["scope_rules"])

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://target.com/":
            return httpx.Response(
                200,
                headers={
                    "Content-Type": "text/html",
                    "Set-Cookie": "PHPSESSID=abc123; Path=/; HttpOnly; SameSite=Lax",
                },
                text=(
                    '<html><form action="/vulnerabilities/upload/" method="POST" enctype="multipart/form-data">'
                    '<input type="file" name="uploaded">'
                    "</form></html>"
                ),
            )
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as mock_client:
        summary = await discovery_service.execute_crawl(
            db_session,
            test_project,
            CrawlRequest(
                seed_urls=["https://target.com/"],
                max_depth=2,
                max_pages=5,
                respect_robots_txt=False,
                parse_sitemap=False,
                extract_js_routes=False,
            ),
            custom_client=mock_client,
        )

    assert summary.endpoints_discovered >= 2
    cookies = (
        await db_session.execute(select(Cookie).where(Cookie.project_id == test_project.id))
    ).scalars().all()
    assert any(c.name == "PHPSESSID" and c.is_httponly is True and c.samesite == "Lax" for c in cookies)

    ep = (
        await db_session.execute(
            select(Endpoint).where(
                Endpoint.project_id == test_project.id,
                Endpoint.url_path == "/vulnerabilities/upload",
                Endpoint.http_method == "POST",
            )
        )
    ).scalar_one()
    assert ep.content_type == "multipart/form-data"
    assert ep.parameter_schema["body"][0]["type"] == "file"

