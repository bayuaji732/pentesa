#!/usr/bin/env python3
"""Interactive CLI script for self-service password rotation.

Adheres to ENV RULES v2:
- Passwords are never passed via CLI arguments, environment variables, or logged to disk.
- Inputs are collected interactively via getpass.
"""

import getpass
import os
import sys
import httpx


def main() -> int:
    default_api_url = os.getenv("PENTESA_API_URL", "http://localhost:8000").rstrip("/")
    print("========================================")
    print("   Pentesa Self-Service Password Change ")
    print("========================================")
    
    api_url = input(f"API Base URL [{default_api_url}]: ").strip()
    if not api_url:
        api_url = default_api_url

    email = input("Account Email: ").strip()
    if not email:
        print("Error: Email is required.", file=sys.stderr)
        return 1

    current_password = getpass.getpass("Current Password: ")
    if not current_password:
        print("Error: Current password is required.", file=sys.stderr)
        return 1

    new_password = getpass.getpass("New Password (min 12 chars, upper/lower/digit/special): ")
    if not new_password:
        print("Error: New password is required.", file=sys.stderr)
        return 1

    new_password_confirm = getpass.getpass("Confirm New Password: ")
    if new_password != new_password_confirm:
        print("Error: New passwords do not match.", file=sys.stderr)
        return 1

    with httpx.Client(base_url=api_url, timeout=15.0) as client:
        # Step 1: Authenticate to obtain short-lived access token
        try:
            login_resp = client.post(
                "/api/v1/auth/login",
                json={"email": email, "password": current_password},
            )
        except Exception as e:
            print(f"Connection error to {api_url}: {e}", file=sys.stderr)
            return 1

        if login_resp.status_code != 200:
            print(f"Authentication failed: {login_resp.text}", file=sys.stderr)
            return 1

        tokens = login_resp.json()
        access_token = tokens.get("access_token")
        if not access_token:
            print("Error: No access token received from server.", file=sys.stderr)
            return 1

        # Step 2: Request password change
        change_resp = client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {access_token}"},
            json={
                "current_password": current_password,
                "new_password": new_password,
                "new_password_confirm": new_password_confirm,
            },
        )

        if change_resp.status_code == 200:
            print("\n[SUCCESS] Password changed successfully.")
            print("Previous session tokens have been invalidated. Please log in with your new password.")
            return 0
        else:
            print(f"\n[FAILED] Password change failed: {change_resp.text}", file=sys.stderr)
            return 1


if __name__ == "__main__":
    sys.exit(main())
