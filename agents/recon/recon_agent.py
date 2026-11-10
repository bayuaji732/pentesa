"""AGT-03: Reconnaissance Agent & AGT-04: Attack Surface Mapping Agent.

Discovers subdomains, crawls in-scope web applications, extracts parameters, and maps attack surface.
"""

import json
from typing import Optional
from urllib.parse import urlparse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.base import BaseAgent
from agents.llm.provider import BaseLLMProvider
from database.models.discovery import DiscoveredDomain, Endpoint, Technology
from database.models.scope import ScopeRule
from services.orchestrator.state import PentestWorkflowState
from services.scope_engine.validator import parse_port_range


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
            f"Plan {state.scan_profile} reconnaissance for project {state.project_id}. "
            f"Approved scope targets: {json.dumps(state.approved_scope)}. "
            f"Determine seed URLs and crawl depth in concise JSON."
        )
        llm_res = await self.generate_llm_response(prompt=prompt, system_prompt=self.system_prompt, json_mode=True)

        await self.log_decision(
            thought_trace=llm_res.content,
            intent="Execute scoped crawling and attack surface parameter discovery",
            confidence="High"
        )

        # 2. Extract seed URLs from project scope & discovered domains
        domains_stmt = select(DiscoveredDomain).where(DiscoveredDomain.project_id == state.project_id)
        existing_domains = (await self.session.execute(domains_stmt)).scalars().all()
        subdomains = [getattr(d, "fqdn", None) or getattr(d, "domain", "") for d in existing_domains]
        subdomains = [s for s in subdomains if s]

        if not subdomains:
            targets = state.approved_scope.get("target_domains", ["target.com"])
            clean_targets = [t.lstrip("*.") for t in targets if t]
            subdomains = clean_targets or ["target.com"]

        state.discovered_subdomains = list(dict.fromkeys(subdomains))

        # 2b. Infer accurate target_base_url (preserving non-standard port & HTTP scheme if crawled/configured)
        target_base_url = state.target_base_url
        if not target_base_url:
            tech_stmt = select(Technology).where(
                Technology.project_id == state.project_id,
                Technology.detected_on_url.is_not(None)
            ).limit(1)
            tech_row = (await self.session.execute(tech_stmt)).scalar_one_or_none()
            if tech_row and tech_row.detected_on_url:
                parsed_t = urlparse(tech_row.detected_on_url)
                if parsed_t.scheme and parsed_t.netloc:
                    target_base_url = f"{parsed_t.scheme}://{parsed_t.netloc}"

        if not target_base_url:
            rules_stmt = select(ScopeRule).where(
                ScopeRule.project_id == state.project_id,
                ScopeRule.target_type == "IN_SCOPE"
            )
            rules = (await self.session.execute(rules_stmt)).scalars().all()
            non_std_ports = []
            for r in rules:
                if r.port_range:
                    for p in parse_port_range(r.port_range):
                        if p not in (80, 443):
                            non_std_ports.append(p)
            primary_host = state.discovered_subdomains[0]
            if primary_host in ("127.0.0.1", "localhost") and non_std_ports:
                # Prefer common local service port (e.g. 9000 before 8000 if both exist)
                preferred = sorted(non_std_ports, reverse=True)[0]
                target_base_url = f"http://{primary_host}:{preferred}"
            else:
                target_base_url = f"https://{primary_host}"

        state.target_base_url = target_base_url
        parsed_base = urlparse(target_base_url)

        # 3. Query existing discovered endpoints
        ep_stmt = select(Endpoint).where(Endpoint.project_id == state.project_id)
        existing_endpoints = (await self.session.execute(ep_stmt)).scalars().all()

        inventory = []
        for ep in existing_endpoints:
            # Preserve inferred port when ep.fqdn matches target_base_url hostname
            if parsed_base.hostname == ep.fqdn and parsed_base.netloc:
                full_url = f"{parsed_base.scheme}://{parsed_base.netloc}{ep.url_path}"
            else:
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
            input_arguments={"project_id": str(state.project_id), "seed_domains": state.discovered_subdomains, "base_url": target_base_url},
            output_result={"discovered_endpoints_count": len(inventory), "base_url": target_base_url},
            status="SUCCESS"
        )

        state.endpoints_inventory = inventory
        state.add_log(self.agent_id, f"Recon mapped {len(state.discovered_subdomains)} domain(s) and {len(inventory)} endpoint(s) (base: {target_base_url}).")
        state.transition_phase("WSTG_PLANNING")

        return state
