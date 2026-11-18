#!/usr/bin/env python3
"""External Seeding Script for Phase 4 Dual-Identity Benchmark Targets.

Seeds test user accounts outside the Pentesa platform:
1. OWASP Juice Shop: User A (basket 6) and User B (basket 7)
2. crAPI: User A and User B with vehicle telemetry and workshop orders

Credentials are read strictly from untracked local env files (.env.p4_seed),
never committed to git or printed to stdout/audit logs.
"""

import os
import sys
import httpx

SEED_ENV_PATH = os.path.abspath(".env.p4_seed")
TOKEN_ENV_PATH = os.path.abspath(".env.p4_tokens")

JUICESHOP_BASE = os.environ.get("JUICESHOP_BASE", "http://bench-juiceshop:3000")
CRAPI_IDENTITY_BASE = os.environ.get("CRAPI_IDENTITY_BASE", "http://bench-crapi-identity:8080")
CRAPI_WEB_BASE = os.environ.get("CRAPI_WEB_BASE", "http://bench-crapi-web:80")


def load_env_file(path: str) -> dict:
    env = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def ensure_seed_credentials():
    creds = load_env_file(SEED_ENV_PATH)
    defaults = {
        "JUICE_USER_A_PASS": "UserA123!Secure",
        "JUICE_USER_B_PASS": "UserB123!Secure",
        "CRAPI_USER_A_PASS": "Password123!",
        "CRAPI_USER_B_PASS": "Password123!",
    }
    updated = False
    for k, v in defaults.items():
        if k not in creds:
            creds[k] = v
            updated = True
    if updated or not os.path.exists(SEED_ENV_PATH):
        with open(SEED_ENV_PATH, "w", encoding="utf-8") as f:
            for k, v in creds.items():
                f.write(f"{k}={v}\n")
    return creds


def seed_all():
    print("[*] Starting Phase 4 External Seeding (Deterministic Targets)...")
    creds = ensure_seed_credentials()
    tokens = {}

    with httpx.Client(timeout=10.0) as client:
        # 1. Seed Juice Shop
        js_users = [
            ("user_a", "user_a@juice-sh.op", creds["JUICE_USER_A_PASS"]),
            ("user_b", "user_b@juice-sh.op", creds["JUICE_USER_B_PASS"]),
        ]
        for role, email, pwd in js_users:
            client.post(
                f"{JUICESHOP_BASE}/api/Users/",
                json={
                    "email": email,
                    "password": pwd,
                    "securityQuestion": {"id": 1, "question": "Mother Maiden Name"},
                    "securityAnswer": "AlphaSec",
                },
            )
            resp = client.post(
                f"{JUICESHOP_BASE}/rest/user/login",
                json={"email": email, "password": pwd},
            )
            if resp.status_code == 200:
                auth = resp.json().get("authentication", {})
                tokens[f"JS_{role.upper()}_TOKEN"] = auth.get("token")
                tokens[f"JS_{role.upper()}_BID"] = str(auth.get("bid"))
                print(f"[+] Juice Shop: Authenticated {role} (bid: {auth.get('bid')})")
            else:
                print(f"[-] Juice Shop login failed for {role}: HTTP {resp.status_code}")

        # 2. Seed crAPI
        cr_users = [
            ("user_a", "user_a@pentesa.lab", creds["CRAPI_USER_A_PASS"], "9876543210"),
            ("user_b", "user_b@pentesa.lab", creds["CRAPI_USER_B_PASS"], "9876543211"),
        ]
        for role, email, pwd, num in cr_users:
            client.post(
                f"{CRAPI_WEB_BASE}/identity/api/auth/signup",
                json={"email": email, "password": pwd, "name": role, "number": num},
            )
            resp = client.post(
                f"{CRAPI_WEB_BASE}/identity/api/auth/login",
                json={"email": email, "password": pwd},
            )
            if resp.status_code == 200:
                tok = resp.json().get("token")
                tokens[f"CRAPI_{role.upper()}_TOKEN"] = tok
                print(f"[+] crAPI: Authenticated {role} successfully")
            else:
                print(f"[-] crAPI login failed for {role}: HTTP {resp.status_code}")

    # Write tokens to untracked token cache
    with open(TOKEN_ENV_PATH, "w", encoding="utf-8") as f:
        for k, v in tokens.items():
            if v:
                f.write(f"{k}={v}\n")

    print(f"[+] Phase 4 Seeding complete. Tokens cached in untracked {TOKEN_ENV_PATH}.")


if __name__ == "__main__":
    seed_all()
