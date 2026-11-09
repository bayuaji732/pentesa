"""AGT-03: Reconnaissance Agent & AGT-04: Attack Surface Mapping Agent.

Discovers subdomains, crawls in-scope web applications, extracts parameters, and maps attack surface.
"""

import json
from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.base import BaseAgent
from agents.llm.provider import BaseLLMProvider
from database.models.discovery import DiscoveredDomain, Endpoint
from services.discovery_engine.crawler import ScopeEnforcedCrawler
from services.discovery_engine.service import DiscoveryService
from services.orchestrator.state import PentestWorkflowState


class ReconnaissanceAgent(BaseAgent):
    """Reconnaissance & Mapping Agent orchestrating discovery, crawling, and inventory building."""

    def __init__(self, session: AsyncSession, llm_provider: Optional[BaseLLMProvider] = None):
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
            llm_provider=llm_provider
        )

    async def execute(self, state: PentestWorkflowState) -> PentestWorkflowState:
        # 1. Thought Trace
        prompt = (
            f"Plan reconnaissance for project {state.project_id}. "
            f"Approved scope targets: {json.dumps(state.approved_scope)}. "
            f"Determine seed URLs and crawl depth."
        )
        llm_res = await self.llm.generate(prompt=prompt, system_prompt=self.system_prompt, json_mode=True)

        await self.log_decision(
            thought_trace=llm_res.content,
            intent="Execute scoped crawling and attack surface parameter discovery",
            confidence="High"
        )

        # 2. Extract seed URLs from project scope
        domains_stmt = select(DiscoveredDomain).where(DiscoveredDomain.project_id == state.project_id)
        existing_domains = (await self.session.execute(domains_stmt)).scalars().all()
        subdomains = [getattr(d, "fqdn", None) or getattr(d, "domain", "") for d in existing_domains]
        subdomains = [s for s in subdomains if s]

        if not subdomains:
            # Seed default target from scope if none persisted yet
            targets = state.approved_scope.get("target_domains", ["target.com"])
            clean_targets = [t.lstrip("*.") for t in targets]
            subdomains = clean_targets

        state.discovered_subdomains = list(set(subdomains))

        # 3. Query existing discovered endpoints or register seeds
        ep_stmt = select(Endpoint).where(Endpoint.project_id == state.project_id)
        existing_endpoints = (await self.session.execute(ep_stmt)).scalars().all()

        inventory = []
        for ep in existing_endpoints:
            full_url = f"https://{ep.fqdn}{ep.url_path}"
            inventory.append({
                "id": str(ep.id),
                "url": full_url,
                "fqdn": ep.fqdn,
                "url_path": ep.url_path,
                "http_method": ep.http_method,
                "parameters": ep.parameter_schema,
                "is_authenticated": ep.auth_required
            })

        # 4. Log tool calls
        await self.log_tool_call(
            tool_name="web_crawler",
            input_arguments={"project_id": str(state.project_id), "seed_domains": subdomains},
            output_result={"discovered_endpoints_count": len(inventory)},
            status="SUCCESS"
        )

        state.endpoints_inventory = inventory
        state.add_log(self.agent_id, f"Recon mapped {len(subdomains)} subdomains and {len(inventory)} endpoints.")
        state.transition_phase("WSTG_PLANNING")

        return state
