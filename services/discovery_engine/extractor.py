"""Parameter and endpoint extraction engine.

Extracts URLs, form inputs, query parameters, JSON schemas, URL path variables,
JavaScript API routes, robots.txt, sitemaps, and OpenAPI specifications.
"""

import json
import re
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urljoin, urlparse

from packages.schemas.discovery import ParameterItem, ParameterLocation, ParameterSchema


class SimpleHTMLLinkExtractor(HTMLParser):
    """Fast, zero-dependency HTML parser to extract links, scripts, forms, and inputs."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: Set[str] = set()
        self.script_srcs: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): v for k, v in attrs if v is not None}

        # Links
        if tag in ("a", "link") and "href" in attr_dict:
            href = attr_dict["href"].strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                full_url = urljoin(self.base_url, href)
                self.links.add(full_url)

        # Scripts
        elif tag == "script" and "src" in attr_dict:
            src = attr_dict["src"].strip()
            if src:
                full_url = urljoin(self.base_url, src)
                self.script_srcs.add(full_url)

        # Forms
        elif tag == "form":
            action = attr_dict.get("action", "").strip()
            method = attr_dict.get("method", "GET").upper()
            form_url = urljoin(self.base_url, action) if action else self.base_url
            self._current_form = {
                "action": form_url,
                "method": method,
                "inputs": []
            }
            self.forms.append(self._current_form)

        # Form Inputs
        elif tag in ("input", "select", "textarea") and self._current_form is not None:
            name = attr_dict.get("name")
            if name:
                input_type = attr_dict.get("type", "text").lower() if tag == "input" else tag
                self._current_form["inputs"].append({
                    "name": name,
                    "type": input_type,
                    "required": "required" in attr_dict,
                    "value": attr_dict.get("value")
                })

    def handle_endtag(self, tag: str):
        if tag == "form":
            self._current_form = None


def extract_html_artifacts(html_content: str, base_url: str) -> Dict[str, Any]:
    """Parse HTML content to extract all links, script URLs, and form definitions."""
    parser = SimpleHTMLLinkExtractor(base_url)
    try:
        parser.feed(html_content)
    except Exception:
        pass
    return {
        "links": sorted(list(parser.links)),
        "scripts": sorted(list(parser.script_srcs)),
        "forms": parser.forms
    }


def infer_type_from_value(value: Any) -> str:
    """Infer JSON schema type from sample value."""
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        if value.isdigit():
            return "integer"
        if value.lower() in ("true", "false"):
            return "boolean"
    return "string"


def extract_query_parameters(url: str) -> List[Dict[str, Any]]:
    """Extract and type query parameters from URL."""
    parsed = urlparse(url)
    params = []
    seen = set()
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key not in seen:
            seen.add(key)
            params.append({
                "name": key,
                "location": ParameterLocation.QUERY.value,
                "type": infer_type_from_value(value),
                "example": value
            })
    return params


def extract_json_parameters(json_data: Any, prefix: str = "") -> List[Dict[str, Any]]:
    """Recursively extract parameters and types from JSON body."""
    params: List[Dict[str, Any]] = []

    if isinstance(json_data, dict):
        for k, v in json_data.items():
            param_name = f"{prefix}.{k}" if prefix else k
            param_type = infer_type_from_value(v)
            params.append({
                "name": param_name,
                "location": ParameterLocation.BODY.value,
                "type": param_type,
                "example": str(v)[:100] if not isinstance(v, (dict, list)) else None
            })
            if isinstance(v, (dict, list)):
                params.extend(extract_json_parameters(v, prefix=param_name))
    elif isinstance(json_data, list) and json_data and isinstance(json_data[0], dict):
        params.extend(extract_json_parameters(json_data[0], prefix=f"{prefix}[]" if prefix else "[]"))

    return params


# Common dynamic path segment patterns (UUIDs, integer IDs, hashes)
UUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
HASH_REGEX = re.compile(r"^[0-9a-f]{32,64}$", re.I)


def normalize_url_path(url_path: str) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Detect dynamic path variables (IDs, UUIDs, hashes) and normalize them into templates.
    e.g. /api/v1/users/42/orders/55 -> (/api/v1/users/{id}/orders/{order_id}, [extracted params])
    """
    clean_path = url_path.strip().split("?")[0].split("#")[0]
    segments = [s for s in clean_path.split("/") if s]
    new_segments = []
    path_params = []

    for idx, seg in enumerate(segments):
        prev_seg = segments[idx - 1] if idx > 0 else "item"

        if seg.isdigit():
            param_name = f"{prev_seg.rstrip('s')}_id" if prev_seg != "item" else "id"
            new_segments.append(f"{{{param_name}}}")
            path_params.append({
                "name": param_name,
                "location": ParameterLocation.PATH.value,
                "type": "integer",
                "example": seg
            })
        elif UUID_REGEX.match(seg):
            param_name = f"{prev_seg.rstrip('s')}_uuid" if prev_seg != "item" else "uuid"
            new_segments.append(f"{{{param_name}}}")
            path_params.append({
                "name": param_name,
                "location": ParameterLocation.PATH.value,
                "type": "string",
                "example": seg
            })
        elif HASH_REGEX.match(seg):
            param_name = f"{prev_seg.rstrip('s')}_hash" if prev_seg != "item" else "hash"
            new_segments.append(f"{{{param_name}}}")
            path_params.append({
                "name": param_name,
                "location": ParameterLocation.PATH.value,
                "type": "string",
                "example": seg
            })
        else:
            new_segments.append(seg)

    normalized = "/" + "/".join(new_segments) if new_segments else "/"
    return normalized, path_params


# Regexes to extract API routes inside JavaScript source files
JS_ROUTE_REGEXES = [
    re.compile(r"""(?:fetch|axios(?:\.[a-z]+)?|\$\.(?:get|post|ajax))\s*\(\s*['"`](/[a-zA-Z0-9_\-\./{}:]+)['"`]""", re.I),
    re.compile(r"""(?:url|path|endpoint)\s*:\s*['"`](/[a-zA-Z0-9_\-\./{}:]+)['"`]""", re.I),
    re.compile(r"""['"`](/api/v[0-9]+/[a-zA-Z0-9_\-\./{}:]+)['"`]""", re.I),
    re.compile(r"""['"`](/v[0-9]+/[a-zA-Z0-9_\-\./{}:]+)['"`]""", re.I),
]


def extract_js_endpoints(js_code: str) -> Set[str]:
    """Scan JavaScript bundle code to discover hidden API endpoints and routes."""
    discovered: Set[str] = set()
    if not js_code or len(js_code) > 5_000_000:  # Skip oversized bundles (>5MB)
        return discovered

    for rgx in JS_ROUTE_REGEXES:
        for match in rgx.finditer(js_code):
            route = match.group(1).strip()
            # Filter noise like image assets or file extensions
            if not route.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".ico", ".woff", ".woff2")):
                # Ensure valid path syntax
                if route.startswith("/") and len(route) > 1:
                    discovered.add(route.split("?")[0])

    return discovered


def parse_robots_txt(content: str) -> List[str]:
    """Extract paths mentioned in Disallow and Allow directives of robots.txt."""
    paths: Set[str] = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            directive, value = line.split(":", 1)
            directive = directive.strip().lower()
            val = value.strip().split("#")[0].strip()
            if directive in ("disallow", "allow") and val:
                # Clean up wildcards
                val = val.split("*")[0]
                if val.startswith("/"):
                    paths.add(val)
    return sorted(list(paths))


def parse_sitemap_xml(xml_content: str) -> List[str]:
    """Parse XML sitemap and return list of discovered <loc> URLs."""
    urls: Set[str] = set()
    try:
        root = ET.fromstring(xml_content)
        # Namespace agnostic findall for <loc> tags
        for elem in root.iter():
            if elem.tag.endswith("loc") and elem.text:
                url_str = elem.text.strip()
                if url_str.startswith("http"):
                    urls.add(url_str)
    except Exception:
        pass
    return sorted(list(urls))


def parse_openapi_spec(spec_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse OpenAPI v3 / Swagger v2 JSON dictionary into structured endpoint definitions."""
    endpoints: List[Dict[str, Any]] = []
    paths = spec_data.get("paths", {})
    if not isinstance(paths, dict):
        return endpoints

    for path_str, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method, operation in path_item.items():
            method_upper = method.upper()
            if method_upper in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS") and isinstance(operation, dict):
                parameters = []
                # Path item parameters
                common_params = path_item.get("parameters", [])
                op_params = operation.get("parameters", [])
                for p in common_params + op_params:
                    if isinstance(p, dict):
                        parameters.append({
                            "name": p.get("name", "unknown"),
                            "location": p.get("in", "query"),
                            "type": p.get("schema", {}).get("type", "string") if "schema" in p else p.get("type", "string"),
                            "required": p.get("required", False),
                            "description": p.get("description")
                        })

                # Request body parameters (OpenAPI v3)
                request_body = operation.get("requestBody", {})
                content = request_body.get("content", {})
                content_type = next(iter(content.keys()), "application/json") if content else None

                endpoints.append({
                    "url_path": path_str,
                    "http_method": method_upper,
                    "parameters": parameters,
                    "content_type": content_type,
                    "auth_required": bool(operation.get("security") or spec_data.get("security")),
                    "discovery_source": "OPENAPI"
                })

    return endpoints
