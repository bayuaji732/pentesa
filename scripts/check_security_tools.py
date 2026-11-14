"""Startup check for required security binaries."""

import os
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


def verify_assets() -> bool:
    """Verify pinned Nuclei templates and ffuf wordlists are present (TOOL-ASSETS-01)."""
    ok = True

    # Check Nuclei templates
    tpl_candidates = [
        os.getenv("PENTESA_NUCLEI_TEMPLATES_DIR", ""),
        "/opt/nuclei-templates",
        os.path.join(os.path.dirname(__file__), "../integrations/nuclei/templates"),
        os.path.join(os.path.dirname(__file__), "../tests/fixtures/nuclei"),
    ]
    tpl_dir = next((p for p in tpl_candidates if p and os.path.isdir(p)), None)
    if tpl_dir:
        yaml_count = len([f for f in os.listdir(tpl_dir) if f.endswith((".yaml", ".yml"))])
        if yaml_count > 0:
            print(f"[OK] Nuclei templates verified at {tpl_dir} ({yaml_count} templates found)")
        else:
            print(f"[FAIL] Nuclei templates directory {tpl_dir} contains no YAML templates")
            ok = False
    else:
        print("[FAIL] Pinned Nuclei templates directory not found in candidate paths")
        ok = False

    # Check ffuf wordlist
    wl_candidates = [
        os.getenv("PENTESA_FFUF_WORDLIST_PATH", ""),
        "/opt/wordlists/common_paths.txt",
        os.path.join(os.path.dirname(__file__), "../integrations/ffuf/wordlists/common_paths.txt"),
        os.path.join(os.path.dirname(__file__), "../tests/fixtures/ffuf/wordlist.txt"),
    ]
    wl_file = next((p for p in wl_candidates if p and os.path.isfile(p) and os.path.getsize(p) > 0), None)
    if wl_file:
        lines = len(open(wl_file, "r", encoding="utf-8", errors="ignore").readlines())
        print(f"[OK] ffuf wordlist verified at {wl_file} ({lines} words)")
    else:
        print("[FAIL] Pinned ffuf wordlist file not found or empty")
        ok = False

    return ok


def main():
    print("[*] Verifying installed security tools and baked assets...")
    ok = True
    ok &= verify_tool("nuclei", "-version")
    ok &= verify_tool("ffuf", "-V")
    ok &= verify_assets()
    if not ok:
        print("[ERROR] One or more required security tools or assets are missing or failed execution.")
        sys.exit(1)
    print("[SUCCESS] All required security tools and assets verified and operational.")


if __name__ == "__main__":
    main()

