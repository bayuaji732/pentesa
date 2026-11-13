#!/usr/bin/env python3
"""Seed OWASP Juice Shop with two normal users and one admin user.

Can be run idempotently to re-seed from scratch.
Saves issued JWT tokens and credentials to data/juiceshop_users.json.
"""

import json
import os
import sys
import time
import httpx

JUICESHOP_URL = os.environ.get("JUICESHOP_URL", "http://127.0.0.1:3001")
OUT_FILE = os.environ.get("JUICESHOP_CREDS_FILE", "./data/juiceshop_users.json")

USERS = [
    {
        "role": "admin",
        "email": "pentesa_admin@juice-sh.op",
        "password": "AdminJuice123!Secure",
        "securityQuestion": {"id": 1, "question": "Your eldest siblings middle name?"},
        "securityAnswer": "PentesaAdmin"
    },
    {
        "role": "user_a",
        "email": "pentesa_user1@juice-sh.op",
        "password": "User1Juice123!Secure",
        "securityQuestion": {"id": 2, "question": "Mother's maiden name?"},
        "securityAnswer": "AlphaTester"
    },
    {
        "role": "user_b",
        "email": "pentesa_user2@juice-sh.op",
        "password": "User2Juice123!Secure",
        "securityQuestion": {"id": 3, "question": "Your favorite pet's name?"},
        "securityAnswer": "BetaTester"
    }
]

def wait_for_juiceshop(client: httpx.Client, timeout_sec=60):
    start = time.time()
    while time.time() - start < timeout_sec:
        try:
            r = client.get(f"{JUICESHOP_URL}/rest/admin/application-version")
            if r.status_code == 200:
                print(f"[OK] Juice Shop is alive: version {r.json().get('version')}")
                return True
        except Exception:
            pass
        time.sleep(2)
    return False

def seed():
    print("=" * 60)
    print("SEEDING OWASP JUICE SHOP TEST ACCOUNTS")
    print(f"Target: {JUICESHOP_URL}")
    print("=" * 60)

    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    results = {}

    with httpx.Client(timeout=10.0) as client:
        if not wait_for_juiceshop(client):
            print("[FAIL] Juice Shop did not respond within timeout.")
            sys.exit(1)

        for u in USERS:
            # Try to register
            reg_payload = {
                "email": u["email"],
                "password": u["password"],
                "securityQuestion": u["securityQuestion"],
                "securityAnswer": u["securityAnswer"]
            }
            try:
                reg_resp = client.post(f"{JUICESHOP_URL}/api/Users/", json=reg_payload)
                if reg_resp.status_code in (201, 200):
                    print(f"[OK] Registered user: {u['email']} ({u['role']})")
                elif reg_resp.status_code == 400 and "already exists" in reg_resp.text:
                    print(f"[INFO] User already registered: {u['email']} ({u['role']})")
                else:
                    print(f"[WARN] Registration response for {u['email']}: {reg_resp.status_code} {reg_resp.text}")
            except Exception as e:
                print(f"[ERROR] Registration failed for {u['email']}: {e}")

            # Authenticate and obtain token
            login_payload = {
                "email": u["email"],
                "password": u["password"]
            }
            try:
                login_resp = client.post(f"{JUICESHOP_URL}/rest/user/login", json=login_payload)
                if login_resp.status_code == 200:
                    auth_data = login_resp.json().get("authentication", {})
                    token = auth_data.get("token")
                    bid = auth_data.get("bid")
                    umail = auth_data.get("umail")
                    print(f"[OK] Authenticated: {umail} (bid: {bid}, token: {token[:16]}...)")
                    results[u["role"]] = {
                        "email": u["email"],
                        "password": u["password"],
                        "token": token,
                        "bid": bid,
                        "header": f"Bearer {token}"
                    }
                else:
                    print(f"[FAIL] Login failed for {u['email']}: {login_resp.status_code} {login_resp.text}")
            except Exception as e:
                print(f"[ERROR] Login failed for {u['email']}: {e}")

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"[SUCCESS] Credentials saved to {OUT_FILE}")

if __name__ == "__main__":
    seed()

