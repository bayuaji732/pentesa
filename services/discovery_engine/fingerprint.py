"""Technology detection and fingerprinting engine.

Identifies web servers, frontend and backend frameworks, programming languages,
CDNs, CMS platforms, and API tooling using HTTP headers, cookies, and DOM indicators.
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple

# Predefined technology signatures
HEADER_SIGNATURES: List[Dict[str, Any]] = [
    {
        "name": "Nginx",
        "category": "WEB_SERVER",
        "header": "server",
        "regex": re.compile(r"nginx(?:/([0-9\.]+))?", re.I),
        "confidence": 100
    },
    {
        "name": "Apache HTTP Server",
        "category": "WEB_SERVER",
        "header": "server",
        "regex": re.compile(r"apache(?:/([0-9\.]+))?", re.I),
        "confidence": 100
    },
    {
        "name": "Microsoft IIS",
        "category": "WEB_SERVER",
        "header": "server",
        "regex": re.compile(r"microsoft-iis(?:/([0-9\.]+))?", re.I),
        "confidence": 100
    },
    {
        "name": "Cloudflare",
        "category": "CDN",
        "header": "server",
        "regex": re.compile(r"^cloudflare$", re.I),
        "confidence": 100
    },
    {
        "name": "Express",
        "category": "BACKEND_FRAMEWORK",
        "header": "x-powered-by",
        "regex": re.compile(r"express", re.I),
        "confidence": 95
    },
    {
        "name": "PHP",
        "category": "LANGUAGE",
        "header": "x-powered-by",
        "regex": re.compile(r"php(?:/([0-9\.]+))?", re.I),
        "confidence": 100
    },
    {
        "name": "ASP.NET",
        "category": "BACKEND_FRAMEWORK",
        "header": "x-powered-by",
        "regex": re.compile(r"asp\.net", re.I),
        "confidence": 95
    },
    {
        "name": "Next.js",
        "category": "FRONTEND_FRAMEWORK",
        "header": "x-powered-by",
        "regex": re.compile(r"next\.js", re.I),
        "confidence": 100
    },
]

COOKIE_SIGNATURES: List[Dict[str, Any]] = [
    {
        "name": "PHP",
        "category": "LANGUAGE",
        "cookie": "PHPSESSID",
        "confidence": 90
    },
    {
        "name": "Java (Servlet/Spring)",
        "category": "LANGUAGE",
        "cookie": "JSESSIONID",
        "confidence": 90
    },
    {
        "name": "Django",
        "category": "BACKEND_FRAMEWORK",
        "cookie": "csrftoken",
        "confidence": 85
    },
    {
        "name": "Express / Node.js",
        "category": "BACKEND_FRAMEWORK",
        "cookie": "connect.sid",
        "confidence": 90
    },
    {
        "name": "Laravel",
        "category": "BACKEND_FRAMEWORK",
        "cookie": "laravel_session",
        "confidence": 95
    },
    {
        "name": "ASP.NET",
        "category": "BACKEND_FRAMEWORK",
        "cookie": "ASP.NET_SessionId",
        "confidence": 95
    },
]

DOM_SIGNATURES: List[Dict[str, Any]] = [
    {
        "name": "Next.js",
        "category": "FRONTEND_FRAMEWORK",
        "regex": re.compile(r"/_next/static/", re.I),
        "confidence": 95
    },
    {
        "name": "Nuxt.js",
        "category": "FRONTEND_FRAMEWORK",
        "regex": re.compile(r"/_nuxt/", re.I),
        "confidence": 95
    },
    {
        "name": "React",
        "category": "FRONTEND_FRAMEWORK",
        "regex": re.compile(r"""(?:react\.production\.min\.js|data-reactroot|id=["']__next["'])""", re.I),
        "confidence": 85
    },
    {
        "name": "Vue.js",
        "category": "FRONTEND_FRAMEWORK",
        "regex": re.compile(r"""(?:vue\.runtime|data-v-[a-f0-9]+)""", re.I),
        "confidence": 90
    },
    {
        "name": "WordPress",
        "category": "CMS",
        "regex": re.compile(r"""(?:/wp-content/|/wp-includes/|<meta name=["']generator["'] content=["']WordPress)""", re.I),
        "confidence": 95
    },
    {
        "name": "Swagger UI",
        "category": "API_DOCUMENTATION",
        "regex": re.compile(r"""(?:swagger-ui\.css|swagger-ui-bundle\.js|<div id=["']swagger-ui["'])""", re.I),
        "confidence": 95
    },
    {
        "name": "Tailwind CSS",
        "category": "UI_LIBRARY",
        "regex": re.compile(r"""tailwindcss""", re.I),
        "confidence": 80
    },
]


def detect_technologies(
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[List[Dict[str, Any]]] = None,
    html_body: Optional[str] = None,
    url: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Fingerprint technologies from HTTP headers, cookies, and HTML body.
    Returns deduplicated list of detected technologies.
    """
    detected: Dict[str, Dict[str, Any]] = {}

    # 1. Inspect Headers
    if headers:
        headers_lower = {k.lower(): v for k, v in headers.items()}
        for sig in HEADER_SIGNATURES:
            hdr_val = headers_lower.get(sig["header"])
            if hdr_val:
                match = sig["regex"].search(hdr_val)
                if match:
                    version = match.group(1) if match.groups() and match.group(1) else None
                    name = sig["name"]
                    if name not in detected or detected[name]["confidence"] < sig["confidence"]:
                        detected[name] = {
                            "name": name,
                            "version": version,
                            "category": sig["category"],
                            "confidence": sig["confidence"],
                            "detected_on_url": url
                        }

    # 2. Inspect Cookies
    if cookies:
        cookie_names = {c.get("name") for c in cookies if isinstance(c, dict) and c.get("name")}
        for sig in COOKIE_SIGNATURES:
            if sig["cookie"] in cookie_names:
                name = sig["name"]
                if name not in detected or detected[name]["confidence"] < sig["confidence"]:
                    detected[name] = {
                        "name": name,
                        "version": None,
                        "category": sig["category"],
                        "confidence": sig["confidence"],
                        "detected_on_url": url
                    }

    # 3. Inspect HTML Body
    if html_body:
        for sig in DOM_SIGNATURES:
            if sig["regex"].search(html_body):
                name = sig["name"]
                if name not in detected or detected[name]["confidence"] < sig["confidence"]:
                    detected[name] = {
                        "name": name,
                        "version": None,
                        "category": sig["category"],
                        "confidence": sig["confidence"],
                        "detected_on_url": url
                    }

    return sorted(list(detected.values()), key=lambda x: x["name"])
