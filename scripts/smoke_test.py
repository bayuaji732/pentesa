#!/usr/bin/env python3
"""Pentesa Platform End-to-End Bring-Up Smoke Test.

Validates:
1. Core API server liveness (/healthz)
2. Database connectivity & readiness (/readyz)
3. External security tool availability (/api/v1/tools)
4. Next.js Web Console accessibility (/login)
5. User authentication flow (/api/v1/auth/login)
6. Authenticated Project & User retrieval (/api/v1/projects, /api/v1/users/me)
"""

import os
import sys
import time
from typing import Dict, Any
import httpx


API_BASE = os.environ.get("PENTESA_API_URL", "http://localhost:8000")
WEB_BASE = os.environ.get("PENTESA_WEB_URL", "http://localhost:3000")
DEFAULT_USER = os.environ.get("PENTESA_SMOKE_USER", "admin@pentesa.local")
DEFAULT_PASS = os.environ.get("PENTESA_SMOKE_PASS", "AdminPass123!")


def print_status(step: str, success: bool, message: str = ""):
    status_icon = "[OK]" if success else "[FAIL]"
    print(f"{status_icon} {step}: {message}")


def run_smoke_test(timeout_seconds: float = 30.0) -> bool:
    print("=" * 60)
    print("PENTESA PLATFORM BRING-UP SMOKE TEST")
    print(f"API Target: {API_BASE}")
    print(f"Web Target: {WEB_BASE}")
    print("=" * 60)

    start_time = time.time()
    all_passed = True

    with httpx.Client(timeout=10.0) as client:
        # Step 1: API Liveness
        api_live = False
        while time.time() - start_time < timeout_seconds:
            try:
                r = client.get(f"{API_BASE}/healthz")
                if r.status_code == 200:
                    api_live = True
                    break
            except Exception:
                time.sleep(2)
        
        if not api_live:
            print_status("API Liveness (/healthz)", False, "API server did not respond within timeout")
            return False
        print_status("API Liveness (/healthz)", True, "API server alive")

        # Step 2: Database Readiness
        try:
            r = client.get(f"{API_BASE}/readyz")
            if r.status_code == 200 and r.json().get("status") == "ready":
                print_status("Database Readiness (/readyz)", True, "PostgreSQL connected and ready")
            else:
                print_status("Database Readiness (/readyz)", False, f"Unexpected response: {r.text}")
                all_passed = False
        except Exception as e:
            print_status("Database Readiness (/readyz)", False, str(e))
            all_passed = False

        # Step 3: Tool Inventory Check
        try:
            r = client.get(f"{API_BASE}/api/v1/tools")
            if r.status_code == 200:
                tools = r.json()
                nuclei_info = next((t for t in tools if t.get("name") == "nuclei"), {})
                ffuf_info = next((t for t in tools if t.get("name") == "ffuf"), {})
                print_status(
                    "Security Tools (/api/v1/tools)",
                    True,
                    f"nuclei: {nuclei_info.get('status', 'unknown')}, ffuf: {ffuf_info.get('status', 'unknown')}"
                )
            else:
                print_status("Security Tools (/api/v1/tools)", False, f"HTTP {r.status_code}")
        except Exception as e:
            print_status("Security Tools (/api/v1/tools)", False, str(e))

        # Step 4: Web Console Accessibility
        try:
            r = client.get(f"{WEB_BASE}/login", follow_redirects=True)
            if r.status_code in (200, 307, 308):
                print_status("Web Console (/login)", True, f"Next.js served response (HTTP {r.status_code})")
            else:
                print_status("Web Console (/login)", False, f"HTTP {r.status_code}")
                all_passed = False
        except Exception as e:
            print_status("Web Console (/login)", False, f"Could not reach web server: {e}")
            all_passed = False

        # Step 5: Authentication Flow
        access_token = None
        try:
            login_data = {"email": DEFAULT_USER, "password": DEFAULT_PASS}
            r = client.post(f"{API_BASE}/api/v1/auth/login", json=login_data)
            if r.status_code == 200:
                tokens = r.json()
                access_token = tokens.get("access_token")
                print_status("Authentication (/api/v1/auth/login)", True, "JWT token pair issued successfully")
            else:
                print_status("Authentication (/api/v1/auth/login)", False, f"HTTP {r.status_code}: {r.text}")
                all_passed = False
        except Exception as e:
            print_status("Authentication (/api/v1/auth/login)", False, str(e))
            all_passed = False

        # Step 6: Authenticated Endpoints
        if access_token:
            auth_headers = {"Authorization": f"Bearer {access_token}"}
            try:
                # Projects
                r = client.get(f"{API_BASE}/api/v1/projects", headers=auth_headers)
                if r.status_code == 200:
                    projects = r.json()
                    print_status("Projects API (/api/v1/projects)", True, f"Retrieved {len(projects)} project(s)")
                else:
                    print_status("Projects API (/api/v1/projects)", False, f"HTTP {r.status_code}")
                    all_passed = False

                # Current User
                r = client.get(f"{API_BASE}/api/v1/users/me", headers=auth_headers)
                if r.status_code == 200:
                    user_data = r.json()
                    print_status("User Profile (/api/v1/users/me)", True, f"Logged in as {user_data.get('email')} ({user_data.get('role')})")
                else:
                    print_status("User Profile (/api/v1/users/me)", False, f"HTTP {r.status_code}")
                    all_passed = False
            except Exception as e:
                print_status("Authenticated APIs", False, str(e))
                all_passed = False

    print("=" * 60)
    if all_passed:
        print("[SUCCESS] All smoke tests passed! Pentesa is healthy and ready.")
        return True
    else:
        print("[FAILURE] One or more smoke test checks failed.")
        return False


if __name__ == "__main__":
    success = run_smoke_test()
    sys.exit(0 if success else 1)
