"""Unit tests for parameter and endpoint extraction engine."""

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


def test_extract_html_artifacts_links_and_forms():
    """Verify extraction of links, scripts, and forms from HTML."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <link rel="stylesheet" href="/assets/style.css">
        <script src="/static/bundle.js"></script>
    </head>
    <body>
        <a href="/dashboard">Dashboard</a>
        <a href="https://target.com/profile?user=42">Profile</a>
        <a href="javascript:void(0)">Ignored</a>
        <form action="/api/v1/login" method="POST">
            <input type="text" name="username" required>
            <input type="password" name="password" required>
            <input type="hidden" name="csrf_token" value="abc123xyz">
            <button type="submit">Log In</button>
        </form>
    </body>
    </html>
    """
    artifacts = extract_html_artifacts(html, "https://target.com")

    # Links
    assert "https://target.com/dashboard" in artifacts["links"]
    assert "https://target.com/profile?user=42" in artifacts["links"]

    # Scripts
    assert "https://target.com/static/bundle.js" in artifacts["scripts"]

    # Forms
    assert len(artifacts["forms"]) == 1
    form = artifacts["forms"][0]
    assert form["action"] == "https://target.com/api/v1/login"
    assert form["method"] == "POST"
    input_names = [i["name"] for i in form["inputs"]]
    assert "username" in input_names
    assert "password" in input_names
    assert "csrf_token" in input_names


def test_extract_query_parameters():
    """Verify extraction and type inference of query parameters."""
    url = "https://target.com/items?category=books&page=2&in_stock=true&rating=4.5"
    params = extract_query_parameters(url)
    param_dict = {p["name"]: p for p in params}

    assert param_dict["category"]["type"] == "string"
    assert param_dict["page"]["type"] == "integer"
    assert param_dict["in_stock"]["type"] == "boolean"
    assert param_dict["category"]["location"] == "query"


def test_extract_json_parameters():
    """Verify recursive extraction of JSON payload parameters and schemas."""
    payload = {
        "user_id": 101,
        "name": "Alice",
        "is_admin": False,
        "contact": {
            "email": "alice@example.com",
            "phone": "555-0199"
        },
        "tags": ["security", "audit"]
    }
    params = extract_json_parameters(payload)
    names = [p["name"] for p in params]

    assert "user_id" in names
    assert "name" in names
    assert "is_admin" in names
    assert "contact.email" in names
    assert "contact.phone" in names
    assert "tags" in names

    param_dict = {p["name"]: p for p in params}
    assert param_dict["user_id"]["type"] == "integer"
    assert param_dict["is_admin"]["type"] == "boolean"
    assert param_dict["contact"]["type"] == "object"


def test_normalize_url_path_dynamic_variables():
    """Verify detection and normalization of numeric IDs, UUIDs, and hashes into route templates."""
    # Numeric ID
    path1 = "/api/v1/users/42/orders/108"
    template1, params1 = normalize_url_path(path1)
    assert template1 == "/api/v1/users/{user_id}/orders/{order_id}"
    assert len(params1) == 2
    assert params1[0]["name"] == "user_id"
    assert params1[0]["type"] == "integer"

    # UUID
    path2 = "/api/v2/tenants/550e8400-e29b-41d4-a716-446655440000/settings"
    template2, params2 = normalize_url_path(path2)
    assert template2 == "/api/v2/tenants/{tenant_uuid}/settings"
    assert len(params2) == 1
    assert params2[0]["name"] == "tenant_uuid"
    assert params2[0]["type"] == "string"

    # Static path unchanged
    path3 = "/api/v1/auth/login"
    template3, params3 = normalize_url_path(path3)
    assert template3 == "/api/v1/auth/login"
    assert len(params3) == 0


def test_extract_js_endpoints():
    """Verify regex scanning of JavaScript source for hidden REST routes."""
    js_source = """
    function fetchUserData(userId) {
        return fetch('/api/v1/users/' + userId)
            .then(res => res.json());
    }
    axios.post('/api/v1/auth/token', { grant_type: 'password' });
    const config = {
        endpoint: '/internal/metrics',
        fallback: '/api/v2/health'
    };
    const image = '/assets/logo.png'; // Should be ignored
    """
    discovered = extract_js_endpoints(js_source)

    assert "/api/v1/users/" in discovered
    assert "/api/v1/auth/token" in discovered
    assert "/internal/metrics" in discovered
    assert "/api/v2/health" in discovered
    assert "/assets/logo.png" not in discovered


def test_parse_robots_txt():
    """Verify extraction of Disallow and Allow endpoints from robots.txt."""
    robots_content = """
    User-agent: *
    Disallow: /admin/
    Disallow: /private/secret.html
    Disallow: /backup*.tar.gz
    Allow: /public/
    # Comment
    """
    paths = parse_robots_txt(robots_content)
    assert "/admin/" in paths
    assert "/private/secret.html" in paths
    assert "/backup" in paths
    assert "/public/" in paths


def test_parse_sitemap_xml():
    """Verify parsing of XML sitemap <loc> URLs."""
    sitemap = """<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url>
            <loc>https://target.com/</loc>
            <priority>1.0</priority>
        </url>
        <url>
            <loc>https://target.com/products</loc>
        </url>
        <url>
            <loc>https://target.com/about</loc>
        </url>
    </urlset>
    """
    urls = parse_sitemap_xml(sitemap)
    assert "https://target.com/" in urls
    assert "https://target.com/products" in urls
    assert "https://target.com/about" in urls


def test_parse_openapi_spec():
    """Verify parsing of OpenAPI v3 definitions into structured endpoints."""
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/api/v1/pets": {
                "get": {
                    "summary": "List pets",
                    "parameters": [
                        {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                    ]
                },
                "post": {
                    "summary": "Create pet",
                    "requestBody": {
                        "content": {
                            "application/json": {}
                        }
                    },
                    "security": [{"BearerAuth": []}]
                }
            }
        }
    }
    endpoints = parse_openapi_spec(spec)
    assert len(endpoints) == 2

    get_ep = next(e for e in endpoints if e["http_method"] == "GET")
    assert get_ep["url_path"] == "/api/v1/pets"
    assert get_ep["parameters"][0]["name"] == "limit"
    assert get_ep["parameters"][0]["type"] == "integer"
    assert get_ep["auth_required"] is False

    post_ep = next(e for e in endpoints if e["http_method"] == "POST")
    assert post_ep["url_path"] == "/api/v1/pets"
    assert post_ep["content_type"] == "application/json"
    assert post_ep["auth_required"] is True

