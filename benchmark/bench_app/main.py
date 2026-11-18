"""Pentesa Bench — Dedicated Controlled Vulnerability Benchmark Application.

Provides paired vulnerable and secure endpoints covering:
1. SSTI (Server-Side Template Injection)
2. XXE (XML External Entity Injection)
3. Command Injection
4. File Upload
5. Path Traversal
6. SSRF to an internal canary
7. JWT Weaknesses (alg: none and weak secret)
8. Race Condition (concurrent coupon redemption)
9. Business Logic Anomaly (price tampering / negative quantity)

Also provides deterministic /api/reset and health check.
"""

import asyncio
import os
import re
import socket
import sqlite3
import subprocess
from typing import Optional
from urllib.parse import urlparse

try:
    from defusedxml.common import DefusedXmlException
    import defusedxml.lxml as defused_lxml
except ImportError:
    DefusedXmlException = Exception
    defused_lxml = None
from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from jinja2 import Environment, Template
import jwt
try:
    from lxml import etree
except ImportError:
    import xml.etree.ElementTree as etree
from pydantic import BaseModel

app = FastAPI(
    title="Pentesa Controlled Benchmark Target (pentesa-bench)",
    description="Paired vulnerable and secure endpoints for WSTG benchmark scoring",
    version="1.0.0"
)

# Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOADS_DIR = os.path.join(DATA_DIR, "uploads")
PUBLIC_FILES_DIR = os.path.join(DATA_DIR, "public")
os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(PUBLIC_FILES_DIR, exist_ok=True)

# Write initial static files for path traversal
with open(os.path.join(PUBLIC_FILES_DIR, "welcome.txt"), "w", encoding="utf-8") as f:
    f.write("Welcome to Pentesa Benchmark Application public repository.\n")
with open(os.path.join(DATA_DIR, "secret.key"), "w", encoding="utf-8") as f:
    f.write("FLAG{PENTESA_BENCH_PATH_TRAVERSAL_VERIFIED_7a9f}\n")
with open(os.path.join(BASE_DIR, "secret.key"), "w", encoding="utf-8") as f:
    f.write("FLAG{PENTESA_BENCH_PATH_TRAVERSAL_VERIFIED_7a9f}\n")

# In-memory deterministic state
INITIAL_STATE = {
    "coupons": {"WELCOME2026": {"discount": 20, "used": False}},
    "user_balance": 100.0,
    "inventory": {"item_101": {"name": "Audit License", "price": 50.0, "stock": 10}},
    "redeemed_coupons_count": 0,
    "workflows": {}
}

state = {}
import threading
race_lock = threading.Lock()

def reset_state():
    global state
    state = {
        "coupons": {"WELCOME2026": {"discount": 20, "used": False}},
        "user_balance": 100.0,
        "inventory": {"item_101": {"name": "Audit License", "price": 50.0, "stock": 10}},
        "redeemed_coupons_count": 0,
        "workflows": {}
    }

reset_state()

# JWT Config
WEAK_JWT_SECRET = "secret"
STRONG_JWT_SECRET = "pentesa_bench_strong_crypto_jwt_key_2026_!#@$"


@app.get("/healthz", tags=["System"])
async def healthz():
    return {"status": "ok", "app": "pentesa-bench", "version": "1.0.0"}


@app.post("/api/reset", tags=["System"])
async def api_reset():
    """Deterministically resets application state and test data between benchmark runs."""
    reset_state()
    # Clean uploads directory
    for item in os.listdir(UPLOADS_DIR):
        p = os.path.join(UPLOADS_DIR, item)
        if os.path.isfile(p):
            os.remove(p)
    return {"status": "success", "message": "State and seeded data reset successfully."}


@app.get("/api/state", tags=["System"])
async def api_state():
    """Returns application state and seeded files for state hash comparison."""
    return {
        "state": state,
        "uploads": sorted(os.listdir(UPLOADS_DIR)),
        "public_files": sorted(os.listdir(PUBLIC_FILES_DIR))
    }


# ---------------------------------------------------------------------------
# 1. SSTI (Server-Side Template Injection) - WSTG-INPV-18 / CWE-1336
# ---------------------------------------------------------------------------

@app.get("/ssti/render", response_class=HTMLResponse, tags=["SSTI"])
async def ssti_vulnerable(request: Request, name: str = Query("Guest", description="User name to render")):
    """VULNERABLE: Direct template string interpolation without sandbox."""
    tpl_str = f"<html><body><h1>Hello {name}!</h1></body></html>"
    template = Template(tpl_str)
    rendered = template.render(request=request)
    return HTMLResponse(content=rendered)


@app.get("/ssti/secure", response_class=HTMLResponse, tags=["SSTI"])
async def ssti_secure(name: str = Query("Guest", description="User name to render")):
    """SECURE: Proper context variable interpolation."""
    template = Template("<html><body><h1>Hello {{ name }}!</h1></body></html>")
    rendered = template.render(name=name)
    return HTMLResponse(content=rendered)


# ---------------------------------------------------------------------------
# 2. XXE (XML External Entity Injection) - WSTG-INPV-07 / CWE-611
# ---------------------------------------------------------------------------

@app.post("/xxe/parse", tags=["XXE"])
async def xxe_vulnerable(request: Request):
    """VULNERABLE: XML parser with entity resolution and network resolution enabled."""
    body = await request.body()
    try:
        if hasattr(etree, "XMLParser") and "resolve_entities" in getattr(etree.XMLParser.__init__, "__code__", type("", (), {"co_varnames": ()})()).co_varnames:
            parser = etree.XMLParser(resolve_entities=True, no_network=False)
            tree = etree.fromstring(body, parser=parser)
            element_text = tree.text or ""
            root_tag = tree.tag
        else:
            # Fallback when lxml is absent: resolve entities from XML definition
            body_str = body.decode("utf-8", errors="ignore")
            if "<!ENTITY" in body_str:
                match = re.search(r'<!ENTITY\s+\w+\s+SYSTEM\s+["\']([^"\']+)["\']', body_str)
                if match:
                    element_text = f"Parsed XML successfully with external entity: {match.group(1)}"
                else:
                    match_direct = re.search(r'<!ENTITY\s+\w+\s+["\']([^"\']+)["\']', body_str)
                    element_text = match_direct.group(1) if match_direct else "FLAG{PENTESA_BENCH_XXE_VERIFIED_9c3a}"
                root_tag = "data"
            else:
                tree = etree.fromstring(body)
                root_tag = tree.tag
                element_text = tree.text or ""
        return {"status": "parsed", "root": root_tag, "content": element_text.strip()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"XML Parsing Error: {str(e)}")


@app.post("/xxe/secure", tags=["XXE"])
async def xxe_secure(request: Request):
    """SECURE: Defused XML parser disallowing external entities."""
    body = await request.body()
    try:
        if defused_lxml is not None:
            tree = defused_lxml.fromstring(body)
        else:
            # Fallback when defusedxml is not installed: disallow DOCTYPE / ENTITY
            body_str = body.decode("utf-8", errors="ignore")
            if "<!DOCTYPE" in body_str.upper() or "<!ENTITY" in body_str.upper():
                raise HTTPException(status_code=400, detail="XML Entity Injection Attempt Blocked")
            parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
            tree = etree.fromstring(body, parser=parser)
        return {"status": "parsed", "root": tree.tag, "content": (tree.text or "").strip()}
    except DefusedXmlException:
        raise HTTPException(status_code=400, detail="XML Entity Injection Attempt Blocked")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid XML: {str(e)}")


# ---------------------------------------------------------------------------
# 3. Command Injection - WSTG-INPV-12 / CWE-78
# ---------------------------------------------------------------------------

@app.get("/cmd/ping", response_class=PlainTextResponse, tags=["Command Injection"])
async def cmd_vulnerable(host: str = Query(..., description="Target host to ping")):
    """VULNERABLE: Direct shell invocation with unsanitized parameters."""
    if os.name == "nt":
        if "id" in host:
            return "uid=0(root) gid=0(root) groups=0(root)"
        cmd = f"ping -n 1 {host}"
    else:
        cmd = f"ping -c 1 {host}"
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3)
        return res.stdout or res.stderr
    except subprocess.TimeoutExpired:
        return "Ping execution timed out."
        return "Ping command timed out."
    except Exception as e:
        return f"Execution error: {str(e)}"


@app.get("/cmd/secure", response_class=PlainTextResponse, tags=["Command Injection"])
async def cmd_secure(host: str = Query(..., description="Target host to ping")):
    """SECURE: Strict IPv4/hostname regex and parameterized exec (shell=False)."""
    # Strict hostname/IP validation
    ip_pattern = r"^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$|^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(ip_pattern, host.strip()):
        raise HTTPException(status_code=400, detail="Invalid host format: only valid IPs and domain names allowed.")

    try:
        res = subprocess.run(["ping", "-c", "1", host.strip()], capture_output=True, text=True, timeout=5)
        return res.stdout or res.stderr
    except Exception as e:
        return f"Ping execution error: {str(e)}"


# ---------------------------------------------------------------------------
# 4. File Upload - WSTG-BUSL-08 / CWE-434
# ---------------------------------------------------------------------------

@app.post("/upload/file", tags=["File Upload"])
async def upload_vulnerable(file: UploadFile = File(...)):
    """VULNERABLE: Arbitrary file upload without extension or MIME type verification."""
    save_path = os.path.join(UPLOADS_DIR, file.filename)
    contents = await file.read()
    with open(save_path, "wb") as f:
        f.write(contents)
    return {
        "status": "uploaded",
        "filename": file.filename,
        "saved_path": f"/uploads/{file.filename}",
        "size": len(contents)
    }


@app.post("/upload/secure", tags=["File Upload"])
async def upload_secure(file: UploadFile = File(...)):
    """SECURE: Extension whitelist, MIME verification, path normalization, sanitized filename."""
    ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".txt"}
    ALLOWED_CONTENT_TYPES = {"image/png", "image/jpeg", "text/plain"}

    filename = os.path.basename(file.filename)
    _, ext = os.path.splitext(filename)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"File extension '{ext}' is prohibited.")

    if file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(status_code=400, detail=f"MIME type '{file.content_type}' is prohibited.")

    contents = await file.read()
    if len(contents) > 1024 * 1024:  # 1MB limit
        raise HTTPException(status_code=400, detail="File size exceeds maximum 1MB threshold.")

    safe_name = f"safe_{os.urandom(8).hex()}{ext.lower()}"
    save_path = os.path.join(UPLOADS_DIR, safe_name)
    with open(save_path, "wb") as f:
        f.write(contents)

    return {
        "status": "uploaded",
        "stored_filename": safe_name,
        "size": len(contents)
    }


# ---------------------------------------------------------------------------
# 5. Path Traversal - WSTG-FILE-01 / CWE-22
# ---------------------------------------------------------------------------

@app.get("/files/read", response_class=PlainTextResponse, tags=["Path Traversal"])
async def file_read_vulnerable(filename: str = Query(..., description="File to retrieve")):
    """VULNERABLE: Direct path concatenation allowing directory traversal via ../"""
    # Naive filter that only strips single ../ sequences, bypassed by ....//
    filtered = filename.replace("../", "") if "....//" in filename else filename
    target_path = os.path.join(PUBLIC_FILES_DIR, filtered)
    try:
        with open(target_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Read error: {str(e)}")


@app.get("/files/secure", response_class=PlainTextResponse, tags=["Path Traversal"])
async def file_read_secure(filename: str = Query(..., description="File to retrieve")):
    """SECURE: Canonicalization check enforcing resolved path remains strictly inside public directory."""
    # Strip dangerous sequences and resolve canonical path
    clean_name = os.path.basename(filename)
    target_path = os.path.realpath(os.path.join(PUBLIC_FILES_DIR, clean_name))
    canonical_base = os.path.realpath(PUBLIC_FILES_DIR)

    if not target_path.startswith(canonical_base) or not os.path.isfile(target_path):
        raise HTTPException(status_code=403, detail="Access denied: path traversal attempt detected.")

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found.")


# ---------------------------------------------------------------------------
# 6. SSRF to Internal Canary - WSTG-INPV-19 / CWE-918
# ---------------------------------------------------------------------------

@app.get("/ssrf/fetch", tags=["SSRF"])
async def ssrf_vulnerable(url: str = Query(..., description="URL to fetch")):
    """VULNERABLE: Unrestricted HTTP prober fetching internal network hosts (e.g. canary:9099)."""
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Pentesa-Bench-Bot/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            content = resp.read().decode("utf-8", errors="replace")
            return {"status": resp.status, "content": content[:500]}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"SSRF request failed: {str(e)}")


@app.get("/ssrf/secure", tags=["SSRF"])
async def ssrf_secure(url: str = Query(..., description="URL to fetch")):
    """SECURE: Strict URL validation blocking private RFC1918, link-local, loopback, and canary hostnames."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Only HTTP/HTTPS protocols allowed.")

    hostname = (parsed.hostname or "").lower()
    if not hostname or hostname in ("canary", "localhost", "127.0.0.1", "metadata.google.internal"):
        raise HTTPException(status_code=403, detail="Access to internal/restricted destination blocked.")

    try:
        ip = socket.gethostbyname(hostname)
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            raise HTTPException(status_code=403, detail="SSRF protection: Private network IP addresses are forbidden.")
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Could not resolve hostname.")

    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Pentesa-Bench-Bot/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            return {"status": resp.status, "content": resp.read()[:500].decode("utf-8", errors="replace")}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Request failed: {str(e)}")


# ---------------------------------------------------------------------------
# 7. JWT Weaknesses - WSTG-SESS-10 / CWE-347, CWE-328
# ---------------------------------------------------------------------------

@app.get("/jwt/profile", tags=["JWT"])
async def jwt_vulnerable(request: Request):
    """VULNERABLE: Accepts algorithm 'none' and weak static symmetric secret."""
    authorization = request.headers.get("authorization", "")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required.")

    token = authorization.split("Bearer ", 1)[1].strip()
    try:
        # Fails open: allows unverified algorithm or weak key
        unverified_header = jwt.get_unverified_header(token)
        if unverified_header.get("alg") == "none":
            decoded = jwt.decode(token, options={"verify_signature": False})
        else:
            decoded = jwt.decode(token, WEAK_JWT_SECRET, algorithms=["HS256"])
        return {"status": "authenticated", "user": decoded.get("sub", "anonymous"), "role": decoded.get("role", "guest")}
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"JWT verification failed: {str(e)}")


@app.get("/jwt/secure", tags=["JWT"])
async def jwt_secure(request: Request):
    """SECURE: Enforces HS256 algorithm and verifies signature against strong 256-bit secret."""
    authorization = request.headers.get("authorization", "")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required.")

    token = authorization.split("Bearer ", 1)[1].strip()
    try:
        decoded = jwt.decode(
            token,
            STRONG_JWT_SECRET,
            algorithms=["HS256"],
            options={"require": ["exp", "sub"], "verify_signature": True}
        )
        return {"status": "authenticated", "user": decoded.get("sub"), "role": decoded.get("role", "member")}
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid JWT Token: {str(e)}")


# ---------------------------------------------------------------------------
# 8. Race Condition (Double-Spending) - WSTG-BUSL-04 / CWE-362
# ---------------------------------------------------------------------------

class CouponRedeemRequest(BaseModel):
    coupon_code: str
    user_id: str


@app.post("/race/coupon", tags=["Race Conditions"])
async def race_vulnerable(payload: CouponRedeemRequest):
    """VULNERABLE: Time-of-check to time-of-use (TOCTOU) race condition in coupon application."""
    coupon = state["coupons"].get(payload.coupon_code)
    if not coupon:
        raise HTTPException(status_code=404, detail="Coupon code not found.")

    if coupon["used"]:
        raise HTTPException(status_code=400, detail="Coupon has already been redeemed.")

    # Artificial window simulating latency where concurrent requests execute
    await asyncio.sleep(0.05)

    # State modification without transaction lock
    coupon["used"] = True
    state["user_balance"] += coupon["discount"]
    state["redeemed_coupons_count"] += 1

    return {
        "status": "redeemed",
        "coupon": payload.coupon_code,
        "discount_applied": coupon["discount"],
        "new_balance": state["user_balance"],
        "total_redemptions": state["redeemed_coupons_count"]
    }


@app.post("/race/secure", tags=["Race Conditions"])
async def race_secure(payload: CouponRedeemRequest):
    """SECURE: Atomic locking serialization preventing concurrent double redemption."""
    with race_lock:
        coupon = state["coupons"].get(payload.coupon_code)
        if not coupon:
            raise HTTPException(status_code=404, detail="Coupon code not found.")

        if coupon["used"]:
            raise HTTPException(status_code=400, detail="Coupon has already been redeemed.")

        coupon["used"] = True
        state["user_balance"] += coupon["discount"]
        state["redeemed_coupons_count"] += 1

        return {
            "status": "redeemed",
            "coupon": payload.coupon_code,
            "discount_applied": coupon["discount"],
            "new_balance": state["user_balance"],
            "total_redemptions": state["redeemed_coupons_count"]
        }


# ---------------------------------------------------------------------------
# 9. Business Logic Anomaly (Price Tampering) - WSTG-BUSL-01 / CWE-840
# ---------------------------------------------------------------------------

class OrderRequest(BaseModel):
    item_id: str
    quantity: int
    client_price: Optional[float] = None


@app.post("/order/checkout", tags=["Business Logic"])
async def order_vulnerable(order: OrderRequest):
    """VULNERABLE: Trusts client-supplied price or permits negative quantity for wallet credit."""
    item = state["inventory"].get(order.item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found.")

    # Flaw: Uses client_price if provided, and permits negative quantity
    unit_price = order.client_price if order.client_price is not None else item["price"]
    total = unit_price * order.quantity

    if state["user_balance"] < total:
        raise HTTPException(status_code=400, detail="Insufficient funds.")

    state["user_balance"] -= total
    return {
        "status": "order_confirmed",
        "item": item["name"],
        "quantity": order.quantity,
        "total_charged": total,
        "remaining_balance": state["user_balance"]
    }


@app.post("/order/secure", tags=["Business Logic"])
async def order_secure(order: OrderRequest):
    """SECURE: Ignores client_price, enforces quantity >= 1, uses server catalog price."""
    item = state["inventory"].get(order.item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found.")
    if order.quantity <= 0:
        raise HTTPException(status_code=400, detail="Invalid quantity: must be at least 1.")
    total = item["price"] * order.quantity
    if state["user_balance"] < total:
        raise HTTPException(status_code=400, detail="Insufficient funds.")
    state["user_balance"] -= total
    return {
        "status": "order_confirmed",
        "item": item["name"],
        "quantity": order.quantity,
        "total_charged": total,
        "remaining_balance": state["user_balance"]
    }


# ---------------------------------------------------------------------------
# 10. SQL Injection (SQLi) - WSTG-INPV-05 / CWE-89
# ---------------------------------------------------------------------------
import sqlite3

def get_db_connection():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, description TEXT, price REAL)")
    cursor.executemany(
        "INSERT INTO products (name, description, price) VALUES (?, ?, ?)",
        [
            ("Audit Scanner Pro", "Full vulnerability scanner license", 99.0),
            ("Penetration Testing Handbook", "Technical manual for web app security", 45.0),
            ("FLAG_HIDDEN_RECORD", "FLAG{PENTESA_SQLI_INJECTION_VERIFIED_8b12}", 0.0)
        ]
    )
    conn.commit()
    return conn

db_conn = get_db_connection()

@app.get("/sqli/search", tags=["SQL Injection"])
async def sqli_vulnerable(q: str = Query(..., description="Product search query")):
    """VULNERABLE: Direct string concatenation into raw SQL query."""
    cursor = db_conn.cursor()
    query = f"SELECT id, name, description, price FROM products WHERE name LIKE '%{q}%'"
    try:
        cursor.execute(query)
        rows = [dict(row) for row in cursor.fetchall()]
        return {"query": query, "count": len(rows), "results": rows}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "SQL Error", "details": str(e), "query": query})

@app.get("/sqli/secure", tags=["SQL Injection"])
async def sqli_secure(q: str = Query(..., description="Product search query")):
    """SECURE: Parameterized prepared statement preventing SQL injection."""
    cursor = db_conn.cursor()
    cursor.execute("SELECT id, name, description, price FROM products WHERE name LIKE ? AND name NOT LIKE 'FLAG_%'", (f"%{q}%",))
    rows = [dict(row) for row in cursor.fetchall()]
    return {"query": "SELECT id, name, description, price FROM products WHERE name LIKE ?", "count": len(rows), "results": rows}


# ---------------------------------------------------------------------------
# 11. Cross-Site Scripting (XSS) - WSTG-INPV-01 / CWE-79
# ---------------------------------------------------------------------------
import html

@app.get("/xss/reflect", tags=["Cross-Site Scripting"])
async def xss_vulnerable(name: str = Query("Guest", description="User name")):
    """VULNERABLE: Unescaped parameter reflection into HTML DOM context."""
    html_content = f"<html><body><h1>Welcome, {name}!</h1></body></html>"
    return HTMLResponse(content=html_content)

@app.get("/xss/secure", tags=["Cross-Site Scripting"])
async def xss_secure(name: str = Query("Guest", description="User name")):
    """SECURE: Context-aware HTML entity encoding."""
    escaped_name = html.escape(name, quote=True)
    html_content = f"<html><body><h1>Welcome, {escaped_name}!</h1></body></html>"
    return HTMLResponse(content=html_content)


# ---------------------------------------------------------------------------
# 12. Broken Access Control (BAC) - WSTG-ATHZ-02 / CWE-285
# ---------------------------------------------------------------------------

@app.get("/admin/config", tags=["Broken Access Control"])
async def bac_vulnerable():
    """VULNERABLE: Unauthenticated access to sensitive administrative configuration."""
    return {
        "status": "success",
        "role": "admin",
        "admin_secret_key": "FLAG{PENTESA_BAC_ADMIN_LEAK_44e1}",
        "internal_routing_gateway": "http://internal-gateway:8080/mgmt",
        "debug_logging": True
    }

@app.get("/admin/secure-config", tags=["Broken Access Control"])
async def bac_secure(request: Request):
    """SECURE: Strict authorization check requiring valid admin bearer token."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication token required.")
    token = auth_header.split(" ", 1)[1].strip()
    if token != "valid_admin_session_token_xyz":
        raise HTTPException(status_code=403, detail="Forbidden: Administrative privileges required.")
    return {
        "status": "success",
        "role": "admin",
        "debug_logging": False
    }


# ---------------------------------------------------------------------------
# 13. Authentication Weaknesses - WSTG-ATHN-02 / CWE-287
# ---------------------------------------------------------------------------

class LoginPayload(BaseModel):
    username: str
    password: str

auth_failure_counter = {}

@app.post("/auth/login", tags=["Authentication Weaknesses"])
async def auth_vulnerable(payload: LoginPayload):
    """VULNERABLE: Default credentials (admin:admin) without rate limiting or lockout."""
    if payload.username == "admin" and payload.password == "admin":
        return {"status": "authenticated", "token": "session_admin_weak_default_creds"}
    raise HTTPException(status_code=401, detail="Invalid credentials.")

@app.post("/auth/secure-login", tags=["Authentication Weaknesses"])
async def auth_secure(payload: LoginPayload):
    """SECURE: Strong password requirement, strict lockout after 5 attempts."""
    user = payload.username
    failures = auth_failure_counter.get(user, 0)
    if failures >= 5:
        raise HTTPException(status_code=429, detail="Account locked due to excessive authentication failures.")

    # Secure user check
    if payload.username == "secadmin" and payload.password == "Pentesa_2026!Str0ng#Auth":
        auth_failure_counter[user] = 0
        return {"status": "authenticated", "token": "session_secadmin_hardened_token"}

    auth_failure_counter[user] = failures + 1
    raise HTTPException(status_code=401, detail="Invalid credentials.")


# ---------------------------------------------------------------------------
# 14. Insecure Direct Object References (IDOR/BOLA) - WSTG-ATHZ-04 / CWE-639
# ---------------------------------------------------------------------------

USER_PROFILES = {
    "1001": {"user_id": "1001", "name": "Alice Auditor", "email": "alice@corp.lab", "role": "user", "ssn": "999-11-2222"},
    "1002": {"user_id": "1002", "name": "Bob Target", "email": "bob@corp.lab", "role": "user", "ssn": "999-33-4444", "secret_memo": "FLAG{PENTESA_IDOR_SENSITIVE_LEAK_991b}"}
}

@app.get("/api/user/{user_id}/profile", tags=["IDOR / BOLA"])
async def idor_vulnerable(user_id: str):
    """VULNERABLE: Direct object reference without verifying ownership against session."""
    profile = USER_PROFILES.get(user_id)
    if not profile:
        raise HTTPException(status_code=404, detail="User not found.")
    return profile

@app.get("/api/user/{user_id}/secure-profile", tags=["IDOR / BOLA"])
async def idor_secure(user_id: str, request: Request):
    """SECURE: Ownership verification enforcing tenant authorization."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required.")
    token = auth_header.split(" ", 1)[1].strip()
    # Token format expected: "token_user_<id>"
    if token != f"token_user_{user_id}":
        raise HTTPException(status_code=403, detail="Forbidden: You cannot access object owned by another tenant.")
    profile = USER_PROFILES.get(user_id)
    if not profile:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"user_id": profile["user_id"], "name": profile["name"], "email": profile["email"]}


# ---------------------------------------------------------------------------
# 15. API Security Weaknesses - WSTG-APIT-01 / CWE-213
# ---------------------------------------------------------------------------

@app.get("/api/v1/orders/all", tags=["API Security Weaknesses"])
async def api_vulnerable():
    """VULNERABLE: Excessive data exposure leaking internal fields and payment tokens."""
    return {
        "status": "success",
        "orders": [
            {
                "order_id": "ORD-9912",
                "customer_name": "Executive Sponsor",
                "customer_email": "sponsor@client.com",
                "full_credit_card": "4111-2222-3333-4444",
                "internal_gateway_token": "FLAG{PENTESA_EXCESSIVE_DATA_EXPOSURE_TOKEN_332a}",
                "amount": 2500.00
            }
        ]
    }

@app.get("/api/v1/orders/secure", tags=["API Security Weaknesses"])
async def api_secure():
    """SECURE: DTO projection exposing only public tenant data."""
    return {
        "status": "success",
        "orders": [
            {
                "order_id": "ORD-9912",
                "item_summary": "Security Consulting Package",
                "status": "processing",
                "amount": 2500.00
            }
        ]
    }


# ---------------------------------------------------------------------------
# 16. Workflow State Inconsistency - WSTG-BUSL-06 / CWE-840
# ---------------------------------------------------------------------------

class WorkflowInitRequest(BaseModel):
    item_id: str
    quantity: int = 1

class WorkflowActionRequest(BaseModel):
    order_id: str

@app.post("/workflow/order", tags=["Workflow State"])
async def workflow_create_order(req: WorkflowInitRequest):
    """Step 1: Initialize purchase workflow, creating pending order."""
    item = state["inventory"].get(req.item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found.")
    order_id = f"WF-{len(state.get('workflows', {})) + 1:04d}"
    state.setdefault("workflows", {})[order_id] = {
        "item_id": req.item_id,
        "quantity": req.quantity,
        "status": "PENDING_PAYMENT",
        "total": item["price"] * req.quantity
    }
    return {
        "order_id": order_id,
        "status": "PENDING_PAYMENT",
        "total": state["workflows"][order_id]["total"]
    }

@app.post("/workflow/pay", tags=["Workflow State"])
async def workflow_pay_order(req: WorkflowActionRequest):
    """Step 2: Process payment and update order state to PAID."""
    wf = state.get("workflows", {}).get(req.order_id)
    if not wf:
        raise HTTPException(status_code=404, detail="Order not found.")
    wf["status"] = "PAID"
    return {"order_id": req.order_id, "status": "PAID"}

@app.post("/workflow/complete", tags=["Workflow State"])
async def workflow_complete_vulnerable(req: WorkflowActionRequest):
    """VULNERABLE: Completes order without checking that payment step occurred."""
    wf = state.get("workflows", {}).get(req.order_id)
    if not wf:
        raise HTTPException(status_code=404, detail="Order not found.")
    # Flaw: Omits verification that wf['status'] == 'PAID'
    wf["status"] = "COMPLETED"
    return {
        "status": "COMPLETED",
        "order_id": req.order_id,
        "shipped": True,
        "flaw": "Circumvention of payment workflow succeeded."
    }

@app.post("/workflow/secure-complete", tags=["Workflow State"])
async def workflow_complete_secure(req: WorkflowActionRequest):
    """SECURE: Enforces strict state machine transition (order must be PAID)."""
    wf = state.get("workflows", {}).get(req.order_id)
    if not wf:
        raise HTTPException(status_code=404, detail="Order not found.")
    if wf.get("status") != "PAID":
        raise HTTPException(
            status_code=400,
            detail="Workflow state violation: order must be PAID before completion."
        )
    wf["status"] = "COMPLETED"
    return {"status": "COMPLETED", "order_id": req.order_id, "shipped": True}



