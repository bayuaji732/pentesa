"""AGT-03: Reconnaissance Agent & AGT-04: Attack Surface Mapping Agent.

Discovers subdomains, crawls in-scope web applications, extracts parameters, and maps attack surface.
"""

import json
import logging
from typing import List, Optional
from urllib.parse import urlparse
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.base import BaseAgent
from agents.llm.provider import BaseLLMProvider
from database.models.discovery import DiscoveredDomain, Endpoint, Technology
from database.models.project import Project
from database.models.scope import ScopeRule
from packages.schemas.discovery import CrawlRequest
from services.discovery_engine.service import discovery_service
from services.execution_engine.runners import resolve_project_origin
from services.orchestrator.state import PentestWorkflowState

logger = logging.getLogger(__name__)


class ReconnaissanceAgent(BaseAgent):
    """Reconnaissance & Mapping Agent orchestrating discovery, crawling, and inventory building."""

    def __init__(
        self,
        session: AsyncSession,
        llm_provider: Optional[BaseLLMProvider] = None,
        http_transport: Optional[httpx.AsyncBaseTransport] = None,
    ):
        super().__init__(
            session=session,
            agent_id="AGT-03",
            agent_name="Reconnaissance & Surface Mapping Agent",
            phase="RECON",
            allowed_tools=["subfinder", "tls_inspector", "web_crawler", "parameter_extractor"],
            risk_tier="Low",
            system_prompt=(
                "You are the Reconnaissance & Attack Surface Mapping Agent (AGT-03/04) for Pentesa. "
                "Discover subdomains, crawl in-scope endpoints, extract parameters, and construct endpoint inventory."
            ),
            llm_provider=llm_provider,
        )
        self.http_transport = http_transport

    async def execute(self, state: PentestWorkflowState) -> PentestWorkflowState:
        # 1. Thought Trace via real configured LLM provider
        prompt = (
            f"Plan {state.scan_profile} reconnaissance for project {state.project_id}. "
            f"Approved scope targets: {json.dumps(state.approved_scope)}. "
            f"Determine seed URLs and crawl depth in concise JSON."
        )
        llm_res = await self.generate_llm_response(
            prompt=prompt,
            system_prompt=self.system_prompt,
            json_mode=True,
        )

        await self.log_decision(
            thought_trace=llm_res.content,
            intent="Execute scoped crawling and attack surface parameter discovery",
            confidence="High",
        )

        # 2. Extract seed hostnames/IPs from discovered domains, target_domains, or allowed_cidrs
        domains_stmt = select(DiscoveredDomain).where(DiscoveredDomain.project_id == state.project_id)
        existing_domains = (await self.session.execute(domains_stmt)).scalars().all()
        subdomains = [getattr(d, "fqdn", None) or getattr(d, "domain", "") for d in existing_domains]
        subdomains = [s for s in subdomains if s]

        if not subdomains:
            targets = state.approved_scope.get("target_domains") or []
            clean_targets = [t.lstrip("*.").strip() for t in targets if t and t.strip()]
            if not clean_targets:
                cidrs = state.approved_scope.get("allowed_cidrs") or []
                clean_targets = [c.split("/")[0].strip() for c in cidrs if c and c.strip()]
            if not clean_targets:
                rules_stmt = select(ScopeRule).where(
                    ScopeRule.project_id == state.project_id,
                    ScopeRule.target_type == "IN_SCOPE",
                )
                rules = (await self.session.execute(rules_stmt)).scalars().all()
                clean_targets = [
                    r.pattern.split("/")[0].lstrip("*.").strip()
                    for r in rules
                    if r.pattern and not r.pattern.startswith("/")
                ]
            subdomains = clean_targets

        state.discovered_subdomains = list(dict.fromkeys(subdomains))

        # 2b. Infer accurate target_base_url across hostnames, container services, and custom ports
        target_base_url = state.target_base_url
        if not target_base_url and state.discovered_subdomains:
            target_base_url = await resolve_project_origin(
                self.session,
                state.project_id,
                state.discovered_subdomains[0],
            )
            if not target_base_url:
                target_base_url = f"https://{state.discovered_subdomains[0]}"

        state.target_base_url = target_base_url

        # 3. Query existing discovered endpoints; perform lightweight live crawl if empty at runtime
        ep_stmt = select(Endpoint).where(Endpoint.project_id == state.project_id)
        existing_endpoints = (await self.session.execute(ep_stmt)).scalars().all()
        effective_transport = self.get_http_transport()

        if not existing_endpoints and target_base_url:
            proj_stmt = select(Project).where(Project.id == state.project_id)
            project = (await self.session.execute(proj_stmt)).scalar_one_or_none()
            if project:
                # Ensure scope_rules are loaded
                rules_stmt = select(ScopeRule).where(ScopeRule.project_id == state.project_id)
                _ = (await self.session.execute(rules_stmt)).scalars().all()
                custom_client = None
                try:
                    if effective_transport is not None:
                        custom_client = httpx.AsyncClient(
                            transport=effective_transport,
                            timeout=httpx.Timeout(4.0, connect=1.5),
                            verify=False,
                            follow_redirects=False,
                        )
                    crawl_summary = await discovery_service.execute_crawl(
                        session=self.session,
                        project=project,
                        config=CrawlRequest(
                            max_depth=1 if state.scan_profile == "QUICK" else 2,
                            max_pages=15 if state.scan_profile == "QUICK" else 35,
                            seed_urls=[f"{target_base_url.rstrip('/')}/"],
                        ),
                        custom_client=custom_client,
                    )
                    existing_endpoints = (await self.session.execute(ep_stmt)).scalars().all()

                    # Automatic HTTP fallback for public HTTP-only targets when default HTTPS probe yields 0 endpoints
                    parsed_init = urlparse(target_base_url)
                    if (
                        not existing_endpoints
                        and effective_transport is None
                        and parsed_init.scheme == "https"
                        and parsed_init.port is None
                        and getattr(crawl_summary, "errors", None)
                    ):
                        http_fallback = f"http://{parsed_init.netloc}"
                        if await self.check_scope(state.project_id, f"{http_fallback}/"):
                            await discovery_service.execute_crawl(
                                session=self.session,
                                project=project,
                                config=CrawlRequest(
                                    max_depth=1 if state.scan_profile == "QUICK" else 2,
                                    max_pages=15 if state.scan_profile == "QUICK" else 35,
                                    seed_urls=[f"{http_fallback}/"],
                                ),
                            )
                            existing_endpoints = (await self.session.execute(ep_stmt)).scalars().all()
                            if existing_endpoints:
                                target_base_url = http_fallback
                                state.target_base_url = http_fallback

                    refreshed_domains = (await self.session.execute(domains_stmt)).scalars().all()
                    for d in refreshed_domains:
                        fqdn = getattr(d, "fqdn", None)
                        if fqdn and fqdn not in state.discovered_subdomains:
                            state.discovered_subdomains.append(fqdn)
                except Exception as exc:
                    logger.warning("Automatic recon crawl skipped or failed for %s: %s", target_base_url, exc)
                finally:
                    if custom_client is not None:
                        await custom_client.aclose()

        parsed_base = urlparse(target_base_url) if target_base_url else None
        inventory: List[dict] = []
        for ep in existing_endpoints:
            if parsed_base and parsed_base.hostname == ep.fqdn and parsed_base.netloc:
                full_url = f"{parsed_base.scheme}://{parsed_base.netloc}{ep.url_path}"
            else:
                ep_origin = await resolve_project_origin(self.session, state.project_id, ep.fqdn)
                full_url = f"{ep_origin or f'https://{ep.fqdn}'}{ep.url_path}"
            inventory.append({
                "id": str(ep.id),
                "url": full_url,
                "fqdn": ep.fqdn,
                "url_path": ep.url_path,
                "http_method": ep.http_method,
                "parameters": ep.parameter_schema,
                "is_authenticated": ep.auth_required,
            })

        # 4. Log tool calls
        await self.log_tool_call(
            tool_name="web_crawler",
            input_arguments={
                "project_id": str(state.project_id),
                "seed_domains": state.discovered_subdomains,
                "base_url": target_base_url,
            },
            output_result={
                "discovered_endpoints_count": len(inventory),
                "base_url": target_base_url,
            },
            status="SUCCESS",
        )

        state.endpoints_inventory = inventory
        state.add_log(
            self.agent_id,
            f"Recon mapped {len(state.discovered_subdomains)} domain(s) and {len(inventory)} endpoint(s) (base: {target_base_url or 'none'}).",
        )
        state.transition_phase("WSTG_PLANNING")

        return state
