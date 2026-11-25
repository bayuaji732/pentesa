"""Verify the entire audit log chain using the platform's verification function."""

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import httpx
from packages.common.audit import verify_audit_chain

PROD_ENV = REPO_ROOT / ".env.production"

def load_admin_creds():
    creds = {}
    for line in PROD_ENV.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            creds[k.strip()] = v.strip().strip("\"'")
    return creds["PENTESA_BOOTSTRAP_ADMIN_EMAIL"], creds["PENTESA_BOOTSTRAP_ADMIN_PASSWORD"]

def main():
    email, pwd = load_admin_creds()
    print("Testing GET /api/v1/audit-logs/verify over the wire...")
    with httpx.Client(base_url="http://127.0.0.1:8000", timeout=30.0) as client:
        r_login = client.post("/api/v1/auth/login", json={"email": email, "password": pwd})
        if r_login.status_code != 200:
            print(f"Login failed: {r_login.status_code}")
            sys.exit(1)
        token = r_login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        r_verify = client.get("/api/v1/audit-logs/verify", headers=headers)
        print("API Status:", r_verify.status_code)
        print("API Response:", r_verify.json())

if __name__ == "__main__":
    main()
