"""Unit tests for ScopeEnforcedCrawler."""

import uuid
from datetime import datetime, timedelta, timezone
import httpx
import pytest

from packages.schemas.discovery import CrawlRequest
from packages.schemas.scope import ScopeRuleType, ScopeTargetType
from services.discovery_engine.crawler import ScopeEnforcedCrawler


class MockProject:
    """Mock project for crawler unit testing."""
    def __init__(self):
        self.id = uuid.uuid4()
        self.status = "ACTIVE"
        now = datetime.now(timezone.utc)
        self.authorization_start = now - timedelta(days=1)
        self.authorization_end = now + timedelta(days=10)
        self.target_domains = ["target.com", "*.target.com"]
        self.allow_internal_networks = False
        self.scope_rules = [
            {
                "id": uuid.uuid4(),
                "rule_type": ScopeRuleType.DOMAIN_WILDCARD,
                "target_type": ScopeTargetType.IN_SCOPE,
                "pattern": "*.target.com"
            },
            {
                "id": uuid.uuid4(),
                "rule_type": ScopeRuleType.EXCLUDED_PATH,
                "target_type": ScopeTargetType.OUT_OF_SCOPE,
                "pattern": "/logout"
            }
        ]


@pytest.mark.asyncio
async def test_crawler_scope_enforcement_and_discovery():
    """Verify crawler visits in-scope URLs, extracts forms, and blocks out-of-scope links."""
    project = MockProject()

    # Define mock HTTP handler
    def handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        if url_str == "https://target.com/":
            content = """
            <html>
                <a href="/about">About</a>
                <a href="/logout">Logout</a>
                <a href="https://external-attacker.com/malicious">External</a>
                <form action="/login" method="POST">
                    <input name="user" type="text" required>
                    <input name="pwd" type="password" required>
                </form>
            </html>
            """
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html", "Server": "nginx/1.24.0"},
                text=content
            )
        elif url_str == "https://target.com/about":
            content = "<html><h1>About Us</h1><a href='/contact?ref=about'>Contact</a></html>"
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html", "X-Powered-By": "Express"},
                text=content
            )
        elif url_str.startswith("https://target.com/contact"):
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text="<html>Contact</html>")
        elif url_str == "https://target.com/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /admin/\nDisallow: /secret")
        elif url_str == "https://target.com/sitemap.xml":
            return httpx.Response(404)
        return httpx.Response(404)

    mock_transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=mock_transport) as test_client:
        crawler = ScopeEnforcedCrawler(
            project=project,
            rules=project.scope_rules,
            custom_client=test_client
        )
        config = CrawlRequest(
            seed_urls=["https://target.com/"],
            max_depth=3,
            max_pages=20,
            respect_robots_txt=True,
            parse_sitemap=False,
            extract_js_routes=False
        )
        result = await crawler.crawl(config)

    # In-scope visited URLs
    assert "https://target.com/" in result["visited_urls"]
    assert "https://target.com/about" in result["visited_urls"]

    # Blocked out-of-scope and excluded URLs must NEVER be visited
    assert "https://external-attacker.com/malicious" not in result["visited_urls"]
    assert "https://target.com/logout" not in result["visited_urls"]

    # Discovered endpoints
    endpoints_map = {f"{e['http_method']} {e['url_path']}": e for e in result["endpoints"]}
    assert "GET /" in endpoints_map
    assert "GET /about" in endpoints_map
    assert "POST /login" in endpoints_map
    assert "GET /admin" in endpoints_map  # from robots.txt
    assert "GET /secret" in endpoints_map  # from robots.txt

    # Technologies detected
    tech_names = [t["name"] for t in result["technologies"]]
    assert "Nginx" in tech_names
    assert "Express" in tech_names


@pytest.mark.asyncio
async def test_crawler_detects_session_cookies_across_shared_client():
    """Verify cookies captured on /robots.txt remain visible to technology fingerprinting on /."""
    project = MockProject()

    def handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        if url_str == "https://target.com/robots.txt":
            return httpx.Response(
                200,
                headers={"Set-Cookie": "JSESSIONID=TEST12345; Path=/; HttpOnly"},
                text="User-agent: *\n"
            )
        elif url_str == "https://target.com/":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html", "Server": "Apache-Coyote/1.1"},
                text="<html><body><h1>Home</h1></body></html>"
            )
        return httpx.Response(404)

    mock_transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=mock_transport) as test_client:
        crawler = ScopeEnforcedCrawler(
            project=project,
            rules=project.scope_rules,
            custom_client=test_client
        )
        config = CrawlRequest(
            seed_urls=["https://target.com/"],
            max_depth=1,
            max_pages=5,
            respect_robots_txt=True,
            parse_sitemap=False,
            extract_js_routes=False
        )
        result = await crawler.crawl(config)

    tech_names = [t["name"] for t in result["technologies"]]
    assert "Apache HTTP Server" in tech_names
    assert "Java (Servlet/Spring)" in tech_names
    assert len(result["cookies"]) >= 1
    jsid = next(c for c in result["cookies"] if c["name"] == "JSESSIONID")
    assert jsid["is_httponly"] is True
    assert jsid["is_secure"] is False


@pytest.mark.asyncio
async def test_crawler_preserves_multipart_enctype_and_file_input_type():
    """Verify upload forms preserve multipart/form-data content_type and file parameter types."""
    project = MockProject()

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://target.com/":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text=(
                    '<html><form action="/upload" method="POST" enctype="multipart/form-data">'
                    '<input type="file" name="avatar">'
                    '</form></html>'
                ),
            )
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as test_client:
        crawler = ScopeEnforcedCrawler(project=project, rules=project.scope_rules, custom_client=test_client)
        config = CrawlRequest(
            seed_urls=["https://target.com/"],
            max_depth=2,
            max_pages=5,
            respect_robots_txt=False,
            parse_sitemap=False,
            extract_js_routes=False,
        )
        result = await crawler.crawl(config)

    upload_ep = next(e for e in result["endpoints"] if e["url_path"] == "/upload" and e["http_method"] == "POST")
    assert upload_ep["content_type"] == "multipart/form-data"
    body_params = upload_ep["parameter_schema"]["body"]
    assert body_params[0]["name"] == "avatar"
    assert body_params[0]["type"] == "file"

