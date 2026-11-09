#!/usr/bin/env python3
"""Pentesa Autonomous Testing Sandbox - Local Vulnerable Target Application.

This server provides an intentional, isolated vulnerable web application running on
http://127.0.0.1:9000 specifically designed for end-to-end testing of Pentesa:
- Attack Surface Discovery & Web Crawling (robots.txt, sitemap.xml, HTML links)
- OWASP Top 10 / WSTG Vulnerabilities (SQLi, Reflected XSS, IDOR, Info Disclosure, Auth Bypass)
- Patch Simulation Switch: Toggle patches ON/OFF to test Pentesa's Empirical Retest Engine!
"""

import sqlite3
from typing import Optional
from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import uvicorn

app = FastAPI(
    title="Acme Vulnerable Mock Target",
    description="Authorized Testbed for Pentesa Penetration Testing Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# In-memory database initialization
db = sqlite3.connect(":memory:", check_same_thread=False)
cursor = db.cursor()

cursor.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    password TEXT,
    email TEXT,
    role TEXT,
    api_key TEXT
)
""")

cursor.execute("""
CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT,
    category TEXT,
    price REAL,
    description TEXT
)
""")

cursor.executemany("""
INSERT INTO users (username, password, email, role, api_key) VALUES (?, ?, ?, ?, ?)
""", [
    ("admin", "admin123", "admin@acme-corp.local", "administrator", "ak_live_9f823a4bce91"),
    ("alice", "Password!1", "alice@acme-corp.local", "engineer", "ak_live_1b82736cde82"),
    ("bob", "Summer2026!", "bob@acme-corp.local", "auditor", "ak_live_7c91823ab491"),
])

cursor.executemany("""
INSERT INTO products (name, category, price, description) VALUES (?, ?, ?, ?)
""", [
    ("Quantum Firewall Appliance", "Hardware", 4999.99, "Enterprise next-generation perimeter firewall."),
    ("Bastion Threat Sensor", "Hardware", 1299.50, "Intrusion detection sensor for micro-segments."),
    ("CyberShield Endpoint Agent", "Software", 49.00, "Automated EDR agent for Windows and Linux."),
    ("Cloud Vault Key Manager", "Software", 299.00, "HSM-backed cryptographic secret management."),
])
db.commit()

# Simulated Patch State: Can be toggled to verify Pentesa's Retest Engine
PATCH_STATE = {
    "sqli_patched": False,
    "xss_patched": False,
    "idor_patched": False,
}


# ============================================================================
# 1. Attack Surface Discovery & Reconnaissance Endpoints
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def home_page():
    """Web crawler entrypoint with links to attack surface."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Acme Corporate Portal - Testing Target</title>
        <style>
            body { font-family: -apple-system, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; }
            a { color: #38bdf8; text-decoration: none; }
            a:hover { text-decoration: underline; }
            .card { background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #334155; }
            code { background: #000; padding: 2px 6px; border-radius: 4px; color: #f43f5e; }
        </style>
    </head>
    <body>
        <h1>Acme Corporate Portal (Pentesa Authorized Target)</h1>
        <p>This is a simulated vulnerable web application for automated penetration testing.</p>

        <div class="card">
            <h3>Discovered Navigation Routes</h3>
            <ul>
                <li><a href="/products?search=Firewall">Product Catalog Search (SQLi)</a></li>
                <li><a href="/search?q=security">General Site Search (Reflected XSS)</a></li>
                <li><a href="/api/v1/users/1">User Profile API (IDOR / BOLA)</a></li>
                <li><a href="/debug/config">Debug Configuration (.env Exposure)</a></li>
                <li><a href="/robots.txt">robots.txt</a></li>
                <li><a href="/sitemap.xml">sitemap.xml</a></li>
            </ul>
        </div>

        <div class="card">
            <h3>Simulated Remediation Controls</h3>
            <p>Use these buttons to toggle patches and test Pentesa's <strong>Empirical Patch Retest Button</strong>:</p>
            <p>
                <a href="/patch/toggle-sqli"><strong>Toggle SQL Injection Patch</strong></a> |
                <a href="/patch/toggle-xss"><strong>Toggle XSS Patch</strong></a> |
                <a href="/patch/status">View Patch Status</a>
            </p>
        </div>
    </body>
    </html>
    """


@app.get("/robots.txt", response_class=Response)
async def robots_txt():
    content = """User-agent: *
Disallow: /debug/
Disallow: /admin/
Disallow: /api/v1/internal/
Sitemap: http://127.0.0.1:9000/sitemap.xml
"""
    return Response(content=content, media_type="text/plain")


@app.get("/sitemap.xml", response_class=Response)
async def sitemap_xml():
    content = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url><loc>http://127.0.0.1:9000/</loc></url>
    <url><loc>http://127.0.0.1:9000/products</loc></url>
    <url><loc>http://127.0.0.1:9000/search</loc></url>
    <url><loc>http://127.0.0.1:9000/api/v1/users/1</loc></url>
    <url><loc>http://127.0.0.1:9000/debug/config</loc></url>
</urlset>"""
    return Response(content=content, media_type="application/xml")


# ============================================================================
# 2. Vulnerability 1: SQL Injection (OWASP A03:2021 / WSTG-INPV-05)
# ============================================================================

@app.get("/products")
async def search_products(search: str = Query("", description="Product search keyword")):
    """Product catalog search. Vulnerable to SQL Injection when sqli_patched is False."""
    if PATCH_STATE["sqli_patched"]:
        # Secure parameterized query
        cursor.execute("SELECT id, name, category, price, description FROM products WHERE name LIKE ? OR category LIKE ?", (f"%{search}%", f"%{search}%"))
    else:
        # Intentionally vulnerable raw string concatenation
        raw_sql = f"SELECT id, name, category, price, description FROM products WHERE name LIKE '%{search}%' OR category LIKE '%{search}%'"
        try:
            cursor.execute(raw_sql)
        except sqlite3.OperationalError as e:
            # Verbose SQL error disclosure
            raise HTTPException(status_code=500, detail=f"SQLite3 Syntax Error in query: {raw_sql} - {str(e)}")

    rows = cursor.fetchall()
    results = [
        {"id": r[0], "name": r[1], "category": r[2], "price": r[3], "description": r[4]}
        for r in rows
    ]
    return {
        "status": "success",
        "query": search,
        "count": len(results),
        "products": results,
        "security_note": "PATCHED with prepared statement" if PATCH_STATE["sqli_patched"] else "VULNERABLE (Unsanitized SQL concatenation)"
    }


# ============================================================================
# 3. Vulnerability 2: Reflected Cross-Site Scripting (WSTG-INPV-01)
# ============================================================================

@app.get("/search", response_class=HTMLResponse)
async def search_page(q: str = Query("", description="Query string")):
    """Site search page. Vulnerable to unescaped reflection when xss_patched is False."""
    if PATCH_STATE["xss_patched"]:
        # Safe HTML entity encoding
        import html
        reflected_q = html.escape(q)
    else:
        # Dangerous raw reflection
        reflected_q = q

    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Search Results</title></head>
    <body style="font-family: sans-serif; background: #0f172a; color: #fff; padding: 40px;">
        <h2>Search Results for: <span>{reflected_q}</span></h2>
        <p>Zero matches found in corporate documents database.</p>
        <p><a href="/" style="color: #38bdf8;">← Back to Home</a></p>
    </body>
    </html>
    """


# ============================================================================
# 4. Vulnerability 3: IDOR / Broken Object Level Authorization (WSTG-ATHZ-02)
# ============================================================================

@app.get("/api/v1/users/{user_id}")
async def get_user_profile(user_id: int):
    """Retrieve user record without authorization check, exposing sensitive API keys."""
    cursor.execute("SELECT id, username, email, role, api_key FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if PATCH_STATE["idor_patched"]:
        # Redacts API key and sensitive credentials
        return {
            "id": user[0],
            "username": user[1],
            "email": user[2],
            "role": user[3],
        }

    # Vulnerable: exposes raw api_key and internal secrets
    return {
        "id": user[0],
        "username": user[1],
        "email": user[2],
        "role": user[3],
        "api_key": user[4],
        "security_warning": "IDOR: High-privilege API key exposed without caller verification"
    }


# ============================================================================
# 5. Vulnerability 4: Sensitive Information Disclosure (WSTG-INFO-05)
# ============================================================================

@app.get("/debug/config")
async def debug_config():
    """Unauthenticated debug configuration endpoint leaking environmental secrets."""
    return {
        "status": "DEBUG_MODE_ACTIVE",
        "environment": "staging",
        "database": {
            "connection_string": "postgresql://acme_db_user:SuperSecretPass2026!@10.0.1.45:5432/acme_prod",
            "max_connections": 100,
        },
        "jwt_secret": "insecure_static_test_key_xyz987654",
        "aws": {
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1"
        }
    }


# ============================================================================
# 6. Simulated Patch Management (For Pentesa Retest Verification)
# ============================================================================

@app.get("/patch/toggle-sqli")
async def toggle_sqli():
    PATCH_STATE["sqli_patched"] = not PATCH_STATE["sqli_patched"]
    return {
        "message": f"SQL Injection is now {'PATCHED (Prepared Statement)' if PATCH_STATE['sqli_patched'] else 'VULNERABLE (Unsanitized Raw SQL)'}",
        "state": PATCH_STATE
    }

@app.get("/patch/toggle-xss")
async def toggle_xss():
    PATCH_STATE["xss_patched"] = not PATCH_STATE["xss_patched"]
    return {
        "message": f"Reflected XSS is now {'PATCHED (HTML Encoded)' if PATCH_STATE['xss_patched'] else 'VULNERABLE (Raw Reflection)'}",
        "state": PATCH_STATE
    }

@app.get("/patch/status")
async def patch_status():
    return {"patch_state": PATCH_STATE}


if __name__ == "__main__":
    print("=" * 70)
    print(" [PENTESA DUMMY VULNERABLE TARGET APPLICATION]")
    print(" Listening on http://127.0.0.1:9000")
    print(" Target Endpoints:")
    print("   - Homepage:          http://127.0.0.1:9000/")
    print("   - SQLi Endpoint:     http://127.0.0.1:9000/products?search=' OR 1=1--")
    print("   - Reflected XSS:     http://127.0.0.1:9000/search?q=<script>alert(1)</script>")
    print("   - IDOR / BOLA:       http://127.0.0.1:9000/api/v1/users/1")
    print("   - Debug Secrets:     http://127.0.0.1:9000/debug/config")
    print("   - Swagger OpenAPI:   http://127.0.0.1:9000/docs")
    print("=" * 70)
    uvicorn.run(app, host="127.0.0.1", port=9000, log_level="warning")

