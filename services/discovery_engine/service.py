"""High-level Attack Surface Discovery Service orchestrating crawling and inventory persistence."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from database.models.discovery import Cookie, DiscoveredDomain, Endpoint, Technology
from database.models.project import Project
from database.models.scope import ScopeRule
from packages.schemas.discovery import (
    AttackSurfaceGraphResponse,
    CrawlRequest,
    CrawlSummaryResponse,
    EndpointCreate
)
from services.discovery_engine.crawler import ScopeEnforcedCrawler
from services.discovery_engine.graph import build_attack_surface_graph


class DiscoveryService:
    """Service for managing endpoints, domains, technologies, and discovery execution."""

    async def execute_crawl(
        self,
        session: AsyncSession,
        project: Project,
        config: CrawlRequest,
        custom_client=None
    ) -> CrawlSummaryResponse:
        """Run scope-enforced crawler and persist discovered attack surface entities."""
        rules_stmt = select(ScopeRule).where(ScopeRule.project_id == project.id)
        rules = (await session.execute(rules_stmt)).scalars().all()
        crawler = ScopeEnforcedCrawler(
            project=project,
            rules=rules,
            custom_client=custom_client
        )
        crawl_result = await crawler.crawl(config)

        # 1. Persist Discovered Domains
        domain_cache: Dict[str, DiscoveredDomain] = {}
        for fqdn in crawl_result["domains"]:
            stmt = select(DiscoveredDomain).where(
                DiscoveredDomain.project_id == project.id,
                DiscoveredDomain.fqdn == fqdn
            )
            res = await session.execute(stmt)
            dom = res.scalar_one_or_none()
            if not dom:
                dom = DiscoveredDomain(
                    id=uuid.uuid4(),
                    project_id=project.id,
                    fqdn=fqdn,
                    discovery_source="CRAWLER",
                    is_active=True
                )
                session.add(dom)
                await session.flush()
            domain_cache[fqdn] = dom

        # 2. Persist Discovered Endpoints (with unique constraint deduplication)
        endpoints_created = 0
        for ep in crawl_result["endpoints"]:
            fqdn = ep["fqdn"]
            url_path = ep["url_path"]
            method = ep["http_method"]

            stmt = select(Endpoint).where(
                Endpoint.project_id == project.id,
                Endpoint.fqdn == fqdn,
                Endpoint.url_path == url_path,
                Endpoint.http_method == method
            )
            res = await session.execute(stmt)
            existing = res.scalar_one_or_none()

            dom_id = domain_cache[fqdn].id if fqdn in domain_cache else None

            if not existing:
                endpoint = Endpoint(
                    id=uuid.uuid4(),
                    project_id=project.id,
                    domain_id=dom_id,
                    fqdn=fqdn,
                    url_path=url_path,
                    http_method=method,
                    parameter_schema=ep.get("parameter_schema", {}),
                    content_type=ep.get("content_type"),
                    auth_required=ep.get("auth_required", False),
                    discovery_source=ep.get("discovery_source", "CRAWLER"),
                    testing_status="Discovered"
                )
                session.add(endpoint)
                endpoints_created += 1
            else:
                # Merge parameters safely whether existing elements are dicts or strings
                existing_params = dict(existing.parameter_schema or {})
                new_params = ep.get("parameter_schema", {})
                for loc in ("query", "body", "path", "headers"):
                    curr_list = list(existing_params.get(loc, []))
                    curr_names = {
                        p.get("name") if isinstance(p, dict) else str(p)
                        for p in curr_list
                    }
                    for np in new_params.get(loc, []):
                        np_name = np.get("name") if isinstance(np, dict) else str(np)
                        if np_name not in curr_names:
                            curr_list.append(np)
                            curr_names.add(np_name)
                    existing_params[loc] = curr_list
                existing.parameter_schema = existing_params
                new_ct = ep.get("content_type")
                if new_ct and (
                    not existing.content_type
                    or ("multipart" in new_ct.lower() and "multipart" not in existing.content_type.lower())
                ):
                    existing.content_type = new_ct

        # 3. Persist Detected Technologies
        techs_created = 0
        for t in crawl_result["technologies"]:
            t_name = t["name"]
            stmt = select(Technology).where(
                Technology.project_id == project.id,
                Technology.name == t_name
            )
            res = await session.execute(stmt)
            existing_t = res.scalar_one_or_none()
            if not existing_t:
                tech_model = Technology(
                    id=uuid.uuid4(),
                    project_id=project.id,
                    name=t_name,
                    version=t.get("version"),
                    category=t.get("category", "UNKNOWN"),
                    confidence=t.get("confidence", 100),
                    detected_on_url=t.get("detected_on_url")
                )
                session.add(tech_model)
                techs_created += 1

        # 4. Persist Discovered Cookies
        for c in crawl_result.get("cookies", []):
            c_stmt = select(Cookie).where(
                Cookie.project_id == project.id,
                Cookie.name == c["name"],
                Cookie.domain == c["domain"],
                Cookie.path == c["path"],
            )
            existing_c = (await session.execute(c_stmt)).scalar_one_or_none()
            if existing_c:
                existing_c.is_secure = existing_c.is_secure or bool(c.get("is_secure"))
                existing_c.is_httponly = existing_c.is_httponly or bool(c.get("is_httponly"))
                if c.get("samesite") and not existing_c.samesite:
                    existing_c.samesite = c["samesite"]
            else:
                cookie_model = Cookie(
                    id=uuid.uuid4(),
                    project_id=project.id,
                    name=c["name"],
                    domain=c["domain"],
                    path=c.get("path") or "/",
                    is_secure=bool(c.get("is_secure")),
                    is_httponly=bool(c.get("is_httponly")),
                    samesite=c.get("samesite"),
                )
                session.add(cookie_model)

        await session.commit()

        return CrawlSummaryResponse(
            status="COMPLETED",
            total_urls_visited=len(crawl_result["visited_urls"]),
            endpoints_discovered=endpoints_created,
            technologies_detected=len(crawl_result["technologies"]),
            domains_discovered=len(crawl_result["domains"]),
            errors=crawl_result["errors"]
        )

    async def add_manual_endpoint(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
        payload: EndpointCreate
    ) -> Endpoint:
        """Add or update an endpoint manually in the inventory."""
        stmt = select(Endpoint).where(
            Endpoint.project_id == project_id,
            Endpoint.fqdn == payload.fqdn,
            Endpoint.url_path == payload.url_path,
            Endpoint.http_method == payload.http_method
        )
        res = await session.execute(stmt)
        existing = res.scalar_one_or_none()

        if existing:
            # Update
            existing.parameter_schema = payload.parameter_schema
            existing.auth_required = payload.auth_required
            existing.content_type = payload.content_type
            await session.commit()
            return existing

        endpoint = Endpoint(
            id=uuid.uuid4(),
            project_id=project_id,
            domain_id=payload.domain_id,
            fqdn=payload.fqdn,
            url_path=payload.url_path,
            http_method=payload.http_method,
            parameter_schema=payload.parameter_schema,
            content_type=payload.content_type,
            auth_required=payload.auth_required,
            discovery_source=payload.discovery_source or "MANUAL",
            testing_status=payload.testing_status or "Discovered"
        )
        session.add(endpoint)
        await session.commit()
        await session.refresh(endpoint)
        return endpoint

    async def get_attack_surface_graph(
        self,
        session: AsyncSession,
        project_id: uuid.UUID
    ) -> AttackSurfaceGraphResponse:
        """Fetch domains, endpoints, and technologies to construct the topology graph."""
        domains_res = await session.execute(select(DiscoveredDomain).where(DiscoveredDomain.project_id == project_id))
        domains = domains_res.scalars().all()

        endpoints_res = await session.execute(select(Endpoint).where(Endpoint.project_id == project_id))
        endpoints = endpoints_res.scalars().all()

        techs_res = await session.execute(select(Technology).where(Technology.project_id == project_id))
        technologies = techs_res.scalars().all()

        return build_attack_surface_graph(
            domains=domains,
            endpoints=endpoints,
            technologies=technologies
        )


discovery_service = DiscoveryService()

