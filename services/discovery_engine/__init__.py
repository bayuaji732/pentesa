"""Attack Surface Discovery Engine package."""

from services.discovery_engine.crawler import ScopeEnforcedCrawler
from services.discovery_engine.extractor import (
    extract_html_artifacts,
    extract_js_endpoints,
    extract_json_parameters,
    extract_query_parameters,
    normalize_url_path,
    parse_openapi_spec,
    parse_robots_txt,
    parse_sitemap_xml
)
from services.discovery_engine.fingerprint import detect_technologies
from services.discovery_engine.graph import build_attack_surface_graph
from services.discovery_engine.service import DiscoveryService, discovery_service

__all__ = [
    "ScopeEnforcedCrawler",
    "extract_html_artifacts",
    "extract_query_parameters",
    "extract_json_parameters",
    "normalize_url_path",
    "extract_js_endpoints",
    "parse_robots_txt",
    "parse_sitemap_xml",
    "parse_openapi_spec",
    "detect_technologies",
    "build_attack_surface_graph",
    "DiscoveryService",
    "discovery_service"
]

