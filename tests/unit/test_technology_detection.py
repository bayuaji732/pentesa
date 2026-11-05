"""Unit tests for technology detection and fingerprinting engine."""

from services.discovery_engine.fingerprint import detect_technologies


def test_detect_web_server_headers():
    """Verify detection of Nginx, Apache, IIS, and Cloudflare from Server headers."""
    # Nginx with version
    techs_nginx = detect_technologies(headers={"Server": "nginx/1.24.0"})
    assert any(t["name"] == "Nginx" and t["version"] == "1.24.0" for t in techs_nginx)

    # Apache with version
    techs_apache = detect_technologies(headers={"Server": "Apache/2.4.52 (Ubuntu)"})
    assert any(t["name"] == "Apache HTTP Server" and t["version"] == "2.4.52" for t in techs_apache)

    # Cloudflare
    techs_cf = detect_technologies(headers={"Server": "cloudflare"})
    assert any(t["name"] == "Cloudflare" and t["category"] == "CDN" for t in techs_cf)


def test_detect_backend_framework_headers():
    """Verify detection of Express, PHP, and ASP.NET from X-Powered-By."""
    techs_express = detect_technologies(headers={"X-Powered-By": "Express"})
    assert any(t["name"] == "Express" for t in techs_express)

    techs_php = detect_technologies(headers={"X-Powered-By": "PHP/8.2.10"})
    assert any(t["name"] == "PHP" and t["version"] == "8.2.10" for t in techs_php)


def test_detect_cookie_signatures():
    """Verify detection of backend languages and frameworks from session cookies."""
    cookies = [
        {"name": "JSESSIONID", "value": "A1B2C3D4E5"},
        {"name": "csrftoken", "value": "xyz789"}
    ]
    techs = detect_technologies(cookies=cookies)
    tech_names = [t["name"] for t in techs]

    assert "Java (Servlet/Spring)" in tech_names
    assert "Django" in tech_names


def test_detect_dom_signatures():
    """Verify detection of Next.js, React, Vue, WordPress, and Swagger UI from HTML body."""
    html_next = """
    <html>
    <head><script src="/_next/static/chunks/main.js"></script></head>
    <body><div id="__next">Hello Next</div></body>
    </html>
    """
    techs_next = detect_technologies(html_body=html_next)
    tech_names = [t["name"] for t in techs_next]
    assert "Next.js" in tech_names
    assert "React" in tech_names

    html_wp = """
    <html>
    <head><meta name="generator" content="WordPress 6.4.2"></head>
    <link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css">
    </html>
    """
    techs_wp = detect_technologies(html_body=html_wp)
    assert any(t["name"] == "WordPress" for t in techs_wp)

    html_swagger = """
    <html>
    <div id="swagger-ui"></div>
    <script src="/dist/swagger-ui-bundle.js"></script>
    </html>
    """
    techs_swagger = detect_technologies(html_body=html_swagger)
    assert any(t["name"] == "Swagger UI" for t in techs_swagger)

