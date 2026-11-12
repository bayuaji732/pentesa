"""Scope-enforced asynchronous web crawler.

Crawls target applications while strictly obeying project authorization, Layer 1 scope
boundaries, excluded path rules, and rate limits.
"""

import asyncio
from typing import Any, Dict, List, Optional, Set, Tuple
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
from services.scope_engine.validator import parse_port_range

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
        self.discovered_cookies: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self.errors: List[str] = []

    def _capture_response_cookies(
        self,
        resp: httpx.Response,
        url: str,
        client: httpx.AsyncClient
    ) -> None:
        """Capture Set-Cookie headers and jar cookies with security flags."""
        parsed = urlparse(url)
        default_domain = parsed.hostname or "unknown"

        raw_headers: List[str] = []
        if hasattr(resp.headers, "get_list"):
            raw_headers = resp.headers.get_list("set-cookie")
        elif "set-cookie" in resp.headers:
            raw_headers = [resp.headers["set-cookie"]]

        for raw in raw_headers:
            parts = [p.strip() for p in raw.split(";") if p.strip()]
            if not parts or "=" not in parts[0]:
                continue
            c_name, _ = parts[0].split("=", 1)
            c_name = c_name.strip()
            if not c_name:
                continue

            c_domain = default_domain
            c_path = "/"
            is_secure = False
            is_httponly = False
            samesite: Optional[str] = None

            for attr in parts[1:]:
                low = attr.lower()
                if low == "secure":
                    is_secure = True
                elif low == "httponly":
                    is_httponly = True
                elif low.startswith("samesite="):
                    samesite = attr.split("=", 1)[1].strip()
                elif low.startswith("path="):
                    c_path = attr.split("=", 1)[1].strip() or "/"
                elif low.startswith("domain="):
                    dom_val = attr.split("=", 1)[1].strip().lstrip(".")
                    if dom_val:
                        c_domain = dom_val

            key = (c_name, c_domain, c_path)
            existing = self.discovered_cookies.get(key)
            if existing:
                existing["is_secure"] = existing["is_secure"] or is_secure
                existing["is_httponly"] = existing["is_httponly"] or is_httponly
                if samesite and not existing.get("samesite"):
                    existing["samesite"] = samesite
            else:
                self.discovered_cookies[key] = {
                    "name": c_name,
                    "domain": c_domain,
                    "path": c_path,
                    "is_secure": is_secure,
                    "is_httponly": is_httponly,
                    "samesite": samesite,
                }

        for jar_cookie in getattr(client.cookies, "jar", []):
            c_name = getattr(jar_cookie, "name", None)
            if not c_name:
                continue
            c_domain = (getattr(jar_cookie, "domain", "") or "").lstrip(".") or default_domain
            c_path = getattr(jar_cookie, "path", None) or "/"
            rest = {
                str(k).lower(): v
                for k, v in (getattr(jar_cookie, "_rest", {}) or {}).items()
            }
            is_secure = bool(getattr(jar_cookie, "secure", False))
            is_httponly = "httponly" in rest
            samesite = rest.get("samesite")

            key = (c_name, c_domain, c_path)
            existing = self.discovered_cookies.get(key)
            if existing:
                existing["is_secure"] = existing["is_secure"] or is_secure
                existing["is_httponly"] = existing["is_httponly"] or is_httponly
                if samesite and not existing.get("samesite"):
                    existing["samesite"] = samesite
            else:
                self.discovered_cookies[key] = {
                    "name": c_name,
                    "domain": c_domain,
                    "path": c_path,
                    "is_secure": is_secure,
                    "is_httponly": is_httponly,
                    "samesite": samesite,
                }

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
            if content_type:
                existing_ct = self.discovered_endpoints[key].get("content_type")
                if not existing_ct or (
                    "multipart" in content_type.lower() and "multipart" not in existing_ct.lower()
                ):
                    self.discovered_endpoints[key]["content_type"] = content_type

    async def crawl(self, config: CrawlRequest) -> Dict[str, Any]:
        """Execute automated attack surface crawl starting from seed URLs."""
        # Determine seed URLs
        seeds: List[str] = []
        if config.seed_urls and len(config.seed_urls) > 0:
            seeds = [s.strip() for s in config.seed_urls if s and s.strip()]
        else:
            target_domains = getattr(self.project, "target_domains", []) or []
            rules = self.rules if self.rules is not None else getattr(self.project, "scope_rules", [])

            rule_ports: Set[int] = set()
            in_scope_patterns: List[str] = []
            for r in (rules or []):
                t_type = getattr(r, "target_type", "") or (r.get("target_type") if isinstance(r, dict) else "")
                if t_type == "IN_SCOPE":
                    pat = getattr(r, "pattern", "") or (r.get("pattern", "") if isinstance(r, dict) else "")
                    pr = getattr(r, "port_range", None) or (r.get("port_range") if isinstance(r, dict) else None)
                    if pat:
                        clean_p = pat.split("/")[0].lstrip("*.")
                        if clean_p:
                            in_scope_patterns.append(clean_p)
                    if pr:
                        for p in parse_port_range(pr):
                            rule_ports.add(p)

            candidates = list(dict.fromkeys([d.lstrip("*.") for d in target_domains if d] + in_scope_patterns))

            for d in candidates:
                if not d:
                    continue
                if rule_ports:
                    for port in sorted(list(rule_ports)):
                        if port == 443:
                            seeds.append(f"https://{d}/")
                        elif port == 80:
                            seeds.append(f"http://{d}/")
                        else:
                            proto = "https" if port in (8443, 4433) else "http"
                            seeds.append(f"{proto}://{d}:{port}/")
                else:
                    seeds.append(f"https://{d}/")
                    seeds.append(f"http://{d}/")

        # Filter initial seeds by scope
        queue: List[Tuple[str, int]] = []
        for s in seeds:
            if self._is_url_in_scope(s):
                if s not in [q[0] for q in queue]:
                    queue.append((s, 1))
            else:
                self.errors.append(f"Seed URL '{s}' is out of scope; skipping.")

        client = self.custom_client or httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT},
            timeout=httpx.Timeout(8.0, connect=4.0),
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
                        resp = await asyncio.wait_for(client.get(clean_url), timeout=10.0)
                    except Exception as e:
                        err_detail = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
                        self.errors.append(f"Request failed for '{clean_url}': {err_detail}")
                        continue

                # Record cookies and endpoint
                self._capture_response_cookies(resp, clean_url, client)
                content_type = resp.headers.get("content-type", "")
                self._record_endpoint(
                    url=clean_url,
                    method="GET",
                    parameters=extract_query_parameters(clean_url),
                    content_type=content_type,
                    source="CRAWLER"
                )

                # Run Technology Detection (include both response Set-Cookie and shared jar cookies)
                if config.detect_technologies:
                    merged_cookies: Dict[str, str] = {}
                    for k, v in client.cookies.items():
                        merged_cookies[k] = v
                    for k, v in resp.cookies.items():
                        merged_cookies[k] = v
                    techs = detect_technologies(
                        headers=dict(resp.headers),
                        cookies=[{"name": k, "value": v} for k, v in merged_cookies.items()],
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
                                    url=f"{parsed_seed.scheme}://{parsed_seed.netloc}{ep['url_path']}",
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
                                    "location": "body" if f_method in ("POST", "PUT", "PATCH") else "query",
                                    "type": inp.get("type") or "string",
                                    "required": inp.get("required", False)
                                }
                                for inp in f.get("inputs", [])
                            ]
                            form_ct = f.get("enctype") or (
                                "application/x-www-form-urlencoded"
                                if f_method in ("POST", "PUT", "PATCH")
                                else None
                            )
                            self._record_endpoint(
                                url=f_action,
                                method=f_method,
                                parameters=form_params,
                                content_type=form_ct,
                                source="FORM"
                            )

                    # Extract JS routes
                    if config.extract_js_routes:
                        for script_url in artifacts["scripts"]:
                            if self._is_url_in_scope(script_url):
                                try:
                                    js_resp = await asyncio.wait_for(client.get(script_url), timeout=6.0)
                                    if js_resp.status_code == 200:
                                        routes = extract_js_endpoints(js_resp.text)
                                        parsed_base = urlparse(clean_url)
                                        for r in routes:
                                            full_r = f"{parsed_base.scheme}://{parsed_base.netloc}{r}"
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
            "cookies": list(self.discovered_cookies.values()),
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
            host_key = f"{parsed.scheme}://{parsed.netloc}"
            if host_key in probed_hosts:
                continue
            probed_hosts.add(host_key)

            # Probe robots.txt
            if config.respect_robots_txt:
                robots_url = f"{host_key}/robots.txt"
                if self._is_url_in_scope(robots_url):
                    try:
                        r = await asyncio.wait_for(client.get(robots_url), timeout=6.0)
                        self._capture_response_cookies(r, robots_url, client)
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
                        r = await asyncio.wait_for(client.get(sitemap_url), timeout=6.0)
                        self._capture_response_cookies(r, sitemap_url, client)
                        if r.status_code == 200:
                            sitemap_urls = parse_sitemap_xml(r.text)
                            for u in sitemap_urls:
                                if self._is_url_in_scope(u):
                                    self._record_endpoint(u, method="GET", source="SITEMAP")
                    except Exception:
                        pass

