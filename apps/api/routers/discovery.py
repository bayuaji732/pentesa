"""Attack surface discovery, endpoint inventory, and technology API router."""

import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.dependencies import get_current_user, record_audit_log, verify_project_access
from database.models.discovery import DiscoveredDomain, Endpoint, Technology
from database.models.user import User
from database.session import get_db
from packages.schemas.discovery import (
    AttackSurfaceGraphResponse,
    CrawlRequest,
    CrawlSummaryResponse,
    DiscoveredDomainCreate,
    DiscoveredDomainResponse,
    EndpointCreate,
    EndpointListResponse,
    EndpointResponse,
    EndpointUpdate,
    TechnologyResponse
)
from services.discovery_engine.service import discovery_service

router = APIRouter(prefix="/api/v1/projects/{project_id}", tags=["Attack Surface Discovery"])


# ---------------------------------------------------------------------------
# Domains Endpoints
# ---------------------------------------------------------------------------

@router.get("/domains", response_model=List[DiscoveredDomainResponse])
async def list_discovered_domains(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all discovered domains and subdomains for a project."""
    project, _ = await verify_project_access(project_id, current_user, session)
    stmt = (
        select(DiscoveredDomain)
        .where(DiscoveredDomain.project_id == project_id)
        .order_by(DiscoveredDomain.created_at.desc())
    )
    result = await session.execute(stmt)
    return result.scalars().all()


@router.post("/domains", response_model=DiscoveredDomainResponse, status_code=status.HTTP_201_CREATED)
async def create_discovered_domain(
    project_id: uuid.UUID,
    payload: DiscoveredDomainCreate,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Add a domain or subdomain to the project attack surface."""
    project, _ = await verify_project_access(project_id, current_user, session, min_role="TESTER")

    clean_fqdn = payload.fqdn.strip().lower()
    stmt = select(DiscoveredDomain).where(
        DiscoveredDomain.project_id == project_id,
        DiscoveredDomain.fqdn == clean_fqdn
    )
    res = await session.execute(stmt)
    if res.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Domain '{clean_fqdn}' is already registered in this project"
        )

    domain = DiscoveredDomain(
        id=uuid.uuid4(),
        project_id=project_id,
        fqdn=clean_fqdn,
        resolved_ips=payload.resolved_ips,
        discovery_source=payload.discovery_source or "MANUAL",
        is_active=payload.is_active
    )
    session.add(domain)
    await session.flush()

    client_ip = request.client.host if request.client else None
    await record_audit_log(
        session=session,
        action="DOMAIN_REGISTERED",
        resource_type="discovered_domain",
        resource_id=str(domain.id),
        project_id=project_id,
        user_id=current_user.id,
        details={"fqdn": domain.fqdn, "source": domain.discovery_source},
        ip_address=client_ip
    )
    return domain


# ---------------------------------------------------------------------------
# Endpoint Inventory Endpoints
# ---------------------------------------------------------------------------

@router.get("/endpoints", response_model=EndpointListResponse)
async def list_endpoints(
    project_id: uuid.UUID,
    http_method: Optional[str] = Query(None, description="Filter by method: GET, POST, etc."),
    auth_required: Optional[bool] = Query(None, description="Filter by authentication requirement"),
    testing_status: Optional[str] = Query(None, description="Filter by testing status: Discovered, Testing, Tested"),
    search: Optional[str] = Query(None, description="Search keyword in url_path or fqdn"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List discovered endpoint inventory with filtering, search, and pagination."""
    project, _ = await verify_project_access(project_id, current_user, session)

    base_query = select(Endpoint).where(Endpoint.project_id == project_id)

    if http_method:
        base_query = base_query.where(Endpoint.http_method == http_method.upper())
    if auth_required is not None:
        base_query = base_query.where(Endpoint.auth_required == auth_required)
    if testing_status:
        base_query = base_query.where(Endpoint.testing_status == testing_status)
    if search:
        s_term = f"%{search.strip()}%"
        base_query = base_query.where((Endpoint.url_path.ilike(s_term)) | (Endpoint.fqdn.ilike(s_term)))

    # Count total
    count_stmt = select(func.count()).select_from(base_query.subquery())
    total_count = (await session.execute(count_stmt)).scalar() or 0

    # Paginate
    paged_stmt = base_query.order_by(Endpoint.created_at.desc()).offset(offset).limit(limit)
    items = (await session.execute(paged_stmt)).scalars().all()

    return EndpointListResponse(total=total_count, items=items)


@router.post("/endpoints", response_model=EndpointResponse, status_code=status.HTTP_201_CREATED)
async def create_endpoint(
    project_id: uuid.UUID,
    payload: EndpointCreate,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Add an endpoint manually to the project inventory."""
    project, _ = await verify_project_access(project_id, current_user, session, min_role="TESTER")
    endpoint = await discovery_service.add_manual_endpoint(session, project_id, payload)

    client_ip = request.client.host if request.client else None
    await record_audit_log(
        session=session,
        action="ENDPOINT_CREATED",
        resource_type="endpoint",
        resource_id=str(endpoint.id),
        project_id=project_id,
        user_id=current_user.id,
        details={"fqdn": endpoint.fqdn, "url_path": endpoint.url_path, "method": endpoint.http_method},
        ip_address=client_ip
    )
    return endpoint


@router.get("/endpoints/{endpoint_id}", response_model=EndpointResponse)
async def get_endpoint(
    project_id: uuid.UUID,
    endpoint_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get endpoint details by ID."""
    project, _ = await verify_project_access(project_id, current_user, session)
    stmt = select(Endpoint).where(Endpoint.id == endpoint_id, Endpoint.project_id == project_id)
    res = await session.execute(stmt)
    endpoint = res.scalar_one_or_none()
    if not endpoint:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Endpoint '{endpoint_id}' not found in this project"
        )
    return endpoint


@router.put("/endpoints/{endpoint_id}", response_model=EndpointResponse)
async def update_endpoint(
    project_id: uuid.UUID,
    endpoint_id: uuid.UUID,
    payload: EndpointUpdate,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update endpoint testing status or parameters."""
    project, _ = await verify_project_access(project_id, current_user, session, min_role="TESTER")
    stmt = select(Endpoint).where(Endpoint.id == endpoint_id, Endpoint.project_id == project_id)
    res = await session.execute(stmt)
    endpoint = res.scalar_one_or_none()
    if not endpoint:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Endpoint '{endpoint_id}' not found"
        )

    if payload.testing_status is not None:
        endpoint.testing_status = payload.testing_status
    if payload.auth_required is not None:
        endpoint.auth_required = payload.auth_required
    if payload.parameter_schema is not None:
        endpoint.parameter_schema = payload.parameter_schema
    if payload.content_type is not None:
        endpoint.content_type = payload.content_type

    await session.commit()
    await session.refresh(endpoint)
    return endpoint


@router.delete("/endpoints/{endpoint_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_endpoint(
    project_id: uuid.UUID,
    endpoint_id: uuid.UUID,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete an endpoint from the inventory (requires LEAD or Admin)."""
    project, _ = await verify_project_access(project_id, current_user, session, min_role="LEAD")
    stmt = select(Endpoint).where(Endpoint.id == endpoint_id, Endpoint.project_id == project_id)
    res = await session.execute(stmt)
    endpoint = res.scalar_one_or_none()
    if not endpoint:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Endpoint '{endpoint_id}' not found"
        )

    await session.delete(endpoint)
    await session.commit()

    client_ip = request.client.host if request.client else None
    await record_audit_log(
        session=session,
        action="ENDPOINT_DELETED",
        resource_type="endpoint",
        resource_id=str(endpoint.id),
        project_id=project_id,
        user_id=current_user.id,
        details={"fqdn": endpoint.fqdn, "path": endpoint.url_path},
        ip_address=client_ip
    )
    return None


# ---------------------------------------------------------------------------
# Technologies Endpoints
# ---------------------------------------------------------------------------

@router.get("/technologies", response_model=List[TechnologyResponse])
async def list_technologies(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List detected technologies for a project."""
    project, _ = await verify_project_access(project_id, current_user, session)
    stmt = select(Technology).where(Technology.project_id == project_id).order_by(Technology.name.asc())
    result = await session.execute(stmt)
    return result.scalars().all()


# ---------------------------------------------------------------------------
# Attack Surface Graph
# ---------------------------------------------------------------------------

@router.get("/attack-surface/graph", response_model=AttackSurfaceGraphResponse)
async def get_attack_surface_graph(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve topological graph representation of the project attack surface."""
    project, _ = await verify_project_access(project_id, current_user, session)
    return await discovery_service.get_attack_surface_graph(session, project_id)


# ---------------------------------------------------------------------------
# Crawl Execution
# ---------------------------------------------------------------------------

@router.post("/discovery/crawl", response_model=CrawlSummaryResponse)
async def trigger_crawl(
    project_id: uuid.UUID,
    payload: CrawlRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Trigger an automated scope-enforced attack surface crawl."""
    project, _ = await verify_project_access(project_id, current_user, session, min_role="TESTER")

    client_ip = request.client.host if request.client else None
    await record_audit_log(
        session=session,
        action="ATTACK_SURFACE_CRAWL_STARTED",
        resource_type="project",
        resource_id=str(project_id),
        project_id=project_id,
        user_id=current_user.id,
        details={"max_depth": payload.max_depth, "max_pages": payload.max_pages},
        ip_address=client_ip
    )

    summary = await discovery_service.execute_crawl(session, project, payload)

    await record_audit_log(
        session=session,
        action="ATTACK_SURFACE_CRAWL_COMPLETED",
        resource_type="project",
        resource_id=str(project_id),
        project_id=project_id,
        user_id=current_user.id,
        details={
            "endpoints_discovered": summary.endpoints_discovered,
            "technologies_detected": summary.technologies_detected,
            "domains_discovered": summary.domains_discovered
        },
        ip_address=client_ip
    )

    return summary

