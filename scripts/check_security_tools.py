"""Startup check for required security binaries."""

import shutil
import subprocess
import sys


def verify_tool(name: str, version_arg: str) -> bool:
    """Verify tool exists on PATH and executes properly."""
    bin_path = shutil.which(name)
    if not bin_path:
        print(f"[FAIL] Required tool '{name}' not found on PATH.")
        return False
    try:
        proc = subprocess.run([bin_path, version_arg], capture_output=True, text=True, timeout=10)
        output = (proc.stdout or proc.stderr).strip().splitlines()
        first_line = output[0] if output else "no output"
        print(f"[OK] {name} verified at {bin_path}: {first_line}")
        return True
    except Exception as exc:
        print(f"[FAIL] Failed executing {name}: {exc}")
        return False


def main():
    print("[*] Verifying installed security tools...")
    ok = True
    ok &= verify_tool("nuclei", "-version")
    ok &= verify_tool("ffuf", "-V")
    if not ok:
        print("[ERROR] One or more required security tools are missing or failed execution.")
        sys.exit(1)
    print("[SUCCESS] All required security tools verified and operational.")


if __name__ == "__main__":
    main()

