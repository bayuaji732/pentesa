"""Scope-enforced asynchronous web crawler.

Crawls target applications while strictly obeying project authorization, Layer 1 scope
boundaries, excluded path rules, and rate limits.
"""

import asyncio
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx

from packages.schemas.discovery import CrawlRequest
from services.discovery_engine.extractor import (
    extract_html_artifacts,
    extract_js_endpoints,
    extract_query_parameters,
    normalize_url_path,
    parse_openapi_spec,
    parse_robots_txt,
    parse_sitemap_xml
)
from services.discovery_engine.fingerprint import detect_technologies
from services.scope_engine.service import scope_service

USER_AGENT = "Pentesa-Security-Scanner/1.0 (Authorized Penetration Testing Platform)"


class ScopeEnforcedCrawler:
    """Asynchronous crawler respecting project scope and depth guardrails."""

    def __init__(
        self,
        project: Any,
        rules: Optional[List[Any]] = None,
        max_concurrency: int = 5,
        custom_client: Optional[httpx.AsyncClient] = None
    ):
        self.project = project
        self.rules = rules if rules is not None else getattr(project, "scope_rules", [])
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.custom_client = custom_client

        # Discovered collections
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: Dict[str, Dict[str, Any]] = {}
        self.discovered_domains: Set[str] = set()
        self.detected_technologies: Dict[str, Dict[str, Any]] = {}
        self.errors: List[str] = []

    def _is_url_in_scope(self, url: str) -> bool:
        """Validate single URL using Layer 1 & 2 scope service."""
        try:
            res = scope_service.check_target(
                project=self.project,
                target_url=url,
                rules=self.rules,
                resolve_dns=False
            )
            return res.is_in_scope
        except Exception:
            return False

    def _record_endpoint(
        self,
        url: str,
        method: str = "GET",
        parameters: Optional[List[Dict[str, Any]]] = None,
        content_type: Optional[str] = None,
        auth_required: bool = False,
        source: str = "CRAWLER"
    ):
        """Record endpoint into inventory with path normalization."""
        parsed = urlparse(url)
        fqdn = parsed.hostname or ""
        if not fqdn:
            return

        self.discovered_domains.add(fqdn)
        norm_path, path_params = normalize_url_path(parsed.path or "/")

        all_params = (parameters or []) + path_params
        # Group parameters by location
        param_schema: Dict[str, List[Dict[str, Any]]] = {"query": [], "body": [], "path": [], "headers": []}
        for p in all_params:
            loc = p.get("location", "query")
            if loc in param_schema:
                param_schema[loc].append(p)

        key = f"{fqdn}:{norm_path}:{method.upper()}"
        if key not in self.discovered_endpoints:
            self.discovered_endpoints[key] = {
                "fqdn": fqdn,
                "url_path": norm_path,
                "http_method": method.upper(),
                "parameter_schema": param_schema,
                "content_type": content_type,
                "auth_required": auth_required,
                "discovery_source": source,
                "testing_status": "Discovered"
            }
        else:
            # Merge parameters
            existing = self.discovered_endpoints[key]["parameter_schema"]
            for loc in ("query", "body", "path", "headers"):
                existing_names = {p["name"] for p in existing.get(loc, [])}
                for new_p in param_schema.get(loc, []):
                    if new_p["name"] not in existing_names:
                        existing[loc].append(new_p)

    async def crawl(self, config: CrawlRequest) -> Dict[str, Any]:
        """Execute automated attack surface crawl starting from seed URLs."""
        # Determine seed URLs
        seeds: List[str] = []
        if config.seed_urls:
            seeds = config.seed_urls
        else:
            target_domains = getattr(self.project, "target_domains", [])
            for d in target_domains:
                clean_d = d.lstrip("*.")
                seeds.append(f"https://{clean_d}/")

        # Filter initial seeds by scope
        queue: List[Tuple[str, int]] = []
        for s in seeds:
            if self._is_url_in_scope(s):
                queue.append((s, 1))
            else:
                self.errors.append(f"Seed URL '{s}' is out of scope; skipping.")

        client = self.custom_client or httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT},
            timeout=10.0,
            verify=False,
            follow_redirects=True
        )

        try:
            # 1. Probe standard discovery paths (/robots.txt, /sitemap.xml, /openapi.json)
            if config.respect_robots_txt or config.parse_sitemap:
                await self._probe_standard_files(seeds, client, config)

            # 2. Main Crawl Loop
            while queue and len(self.visited_urls) < config.max_pages:
                current_url, depth = queue.pop(0)
                clean_url = current_url.split("#")[0]

                if clean_url in self.visited_urls:
                    continue
                self.visited_urls.add(clean_url)

                # Fetch URL
                async with self.semaphore:
                    try:
                        resp = await client.get(clean_url)
                    except Exception as e:
                        self.errors.append(f"Request failed for '{clean_url}': {str(e)}")
                        continue

                # Record endpoint
                content_type = resp.headers.get("content-type", "")
                self._record_endpoint(
                    url=clean_url,
                    method="GET",
                    parameters=extract_query_parameters(clean_url),
                    content_type=content_type,
                    source="CRAWLER"
                )

                # Run Technology Detection
                if config.detect_technologies:
                    techs = detect_technologies(
                        headers=dict(resp.headers),
                        cookies=[{"name": k, "value": v} for k, v in resp.cookies.items()],
                        html_body=resp.text if "text/html" in content_type else None,
                        url=clean_url
                    )
                    for t in techs:
                        self.detected_technologies[t["name"]] = t

                # Parse OpenAPI spec if JSON
                if "application/json" in content_type or clean_url.endswith((".json", "/openapi.json", "/swagger.json")):
                    try:
                        spec = resp.json()
                        if isinstance(spec, dict) and ("openapi" in spec or "swagger" in spec):
                            api_endpoints = parse_openapi_spec(spec)
                            parsed_seed = urlparse(clean_url)
                            for ep in api_endpoints:
                                self._record_endpoint(
                                    url=f"{parsed_seed.scheme}://{parsed_seed.hostname}{ep['url_path']}",
                                    method=ep["http_method"],
                                    parameters=ep["parameters"],
                                    content_type=ep.get("content_type"),
                                    auth_required=ep.get("auth_required", False),
                                    source="OPENAPI"
                                )
                    except Exception:
                        pass

                # If HTML and depth allowed, extract links & forms
                if "text/html" in content_type and depth < config.max_depth:
                    artifacts = extract_html_artifacts(resp.text, clean_url)

                    # Process forms as endpoints with input parameters
                    for f in artifacts["forms"]:
                        f_action = f["action"]
                        f_method = f["method"]
                        if self._is_url_in_scope(f_action):
                            form_params = [
                                {
                                    "name": inp["name"],
                                    "location": "body" if f_method in ("POST", "PUT") else "query",
                                    "type": "string",
                                    "required": inp.get("required", False)
                                }
                                for inp in f.get("inputs", [])
                            ]
                            self._record_endpoint(
                                url=f_action,
                                method=f_method,
                                parameters=form_params,
                                content_type="application/x-www-form-urlencoded" if f_method == "POST" else None,
                                source="FORM"
                            )

                    # Extract JS routes
                    if config.extract_js_routes:
                        for script_url in artifacts["scripts"]:
                            if self._is_url_in_scope(script_url):
                                try:
                                    js_resp = await client.get(script_url)
                                    if js_resp.status_code == 200:
                                        routes = extract_js_endpoints(js_resp.text)
                                        parsed_base = urlparse(clean_url)
                                        for r in routes:
                                            full_r = f"{parsed_base.scheme}://{parsed_base.hostname}{r}"
                                            if self._is_url_in_scope(full_r):
                                                self._record_endpoint(url=full_r, method="GET", source="JS_ANALYSIS")
                                except Exception:
                                    pass

                    # Enqueue new in-scope links
                    for link in artifacts["links"]:
                        if link not in self.visited_urls and self._is_url_in_scope(link):
                            queue.append((link, depth + 1))

        finally:
            if not self.custom_client:
                await client.aclose()

        return {
            "status": "COMPLETED",
            "visited_urls": sorted(list(self.visited_urls)),
            "endpoints": list(self.discovered_endpoints.values()),
            "technologies": list(self.detected_technologies.values()),
            "domains": sorted(list(self.discovered_domains)),
            "errors": self.errors
        }

    async def _probe_standard_files(
        self,
        seeds: List[str],
        client: httpx.AsyncClient,
        config: CrawlRequest
    ):
        """Probe /robots.txt and /sitemap.xml for early endpoint discovery."""
        probed_hosts: Set[str] = set()

        for s in seeds:
            parsed = urlparse(s)
            host_key = f"{parsed.scheme}://{parsed.hostname}"
            if host_key in probed_hosts:
                continue
            probed_hosts.add(host_key)

            # Probe robots.txt
            if config.respect_robots_txt:
                robots_url = f"{host_key}/robots.txt"
                if self._is_url_in_scope(robots_url):
                    try:
                        r = await client.get(robots_url)
                        if r.status_code == 200:
                            paths = parse_robots_txt(r.text)
                            for p in paths:
                                full_url = f"{host_key}{p}"
                                if self._is_url_in_scope(full_url):
                                    self._record_endpoint(full_url, method="GET", source="ROBOTS_TXT")
                    except Exception:
                        pass

            # Probe sitemap.xml
            if config.parse_sitemap:
                sitemap_url = f"{host_key}/sitemap.xml"
                if self._is_url_in_scope(sitemap_url):
                    try:
                        r = await client.get(sitemap_url)
                        if r.status_code == 200:
                            sitemap_urls = parse_sitemap_xml(r.text)
                            for u in sitemap_urls:
                                if self._is_url_in_scope(u):
                                    self._record_endpoint(u, method="GET", source="SITEMAP")
                    except Exception:
                        pass

