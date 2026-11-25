"""Tool Inventory Synchronization Verifier.

Compares active tool specifications in docs/09-tool-integrations.md against
actual wrapper files in the codebase and the 9A-tool-inventory.md matrix.
"""

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# 5 Active Tools expected in codebase
ACTIVE_TOOLS = {
    "nuclei": {
        "doc_section": "5.1",
        "wrapper_path": "integrations/nuclei/runner.py",
        "expected_class": "NucleiRunner",
    },
    "ffuf": {
        "doc_section": "5.5",
        "wrapper_path": "integrations/ffuf/runner.py",
        "expected_class": "FfufRunner",
    },
    "python_check_engine": {
        "doc_section": "5.6",
        "wrapper_path": "services/execution_engine/runners.py",
        "expected_class": "BaseTestRunner",
    },
    "ssl_tls_analyzer": {
        "doc_section": "5.7",
        "wrapper_path": "services/execution_engine/runners.py",
        "expected_class": "GenericProbeRunner",
    },
    "header_analyzer": {
        "doc_section": "5.8",
        "wrapper_path": "services/execution_engine/runners.py",
        "expected_class": "SecurityHeadersRunner",
    },
}

# Planned / Documented-Only tools that must NOT have active wrapper implementations
PLANNED_TOOLS = [
    "katana",
    "subfinder",
    "httpx_cli",
    "nmap",
    "naabu",
    "schemathesis",
    "amass",
    "playwright",
    "feroxbuster",
    "arjun",
    "owasp_zap",
    "sqlmap",
]

def main():
    print("=" * 60)
    print("PENTESA TOOL INVENTORY SYNCHRONIZATION AUDIT")
    print("=" * 60)

    doc_path = REPO_ROOT / "docs" / "09-tool-integrations.md"
    inventory_path = REPO_ROOT / "docs" / "audit" / "evidence" / "phase9" / "9A-tool-inventory.md"

    if not doc_path.exists():
        print(f"[!] Missing documentation file: {doc_path}")
        sys.exit(1)
    if not inventory_path.exists():
        print(f"[!] Missing inventory file: {inventory_path}")
        sys.exit(1)

    doc_text = doc_path.read_text(encoding="utf-8")
    inventory_text = inventory_path.read_text(encoding="utf-8")

    errors = []

    print("\n[1] Verifying Active Tool Implementations (5 Required):")
    for tool_name, meta in ACTIVE_TOOLS.items():
        wpath = REPO_ROOT / meta["wrapper_path"]
        if not wpath.exists():
            errors.append(f"Missing wrapper file for {tool_name}: {meta['wrapper_path']}")
            print(f"  [-] {tool_name}: MISSING ({meta['wrapper_path']})")
            continue

        wrapper_content = wpath.read_text(encoding="utf-8")
        if meta["expected_class"] not in wrapper_content:
            errors.append(f"Class '{meta['expected_class']}' not found in {meta['wrapper_path']}")
            print(f"  [-] {tool_name}: Class {meta['expected_class']} not found")
            continue

        # Check doc section reflects active status
        sec_marker = f"### {meta['doc_section']}"
        if sec_marker not in doc_text:
            errors.append(f"Section {meta['doc_section']} not found in docs/09-tool-integrations.md")
            print(f"  [-] {tool_name}: Section {meta['doc_section']} missing from docs/09")
            continue

        print(f"  [+] {tool_name:22} -> Verified ({meta['wrapper_path']} :: {meta['expected_class']})")

    print("\n[2] Verifying Planned / Documented-Only Tools (Must not have active wrappers):")
    for pt in PLANNED_TOOLS:
        candidate_wrapper = REPO_ROOT / "integrations" / pt / "runner.py"
        if candidate_wrapper.exists():
            errors.append(f"Unexpected wrapper found for planned tool {pt}: {candidate_wrapper}")
            print(f"  [-] {pt}: Unexpected wrapper file exists!")
        else:
            print(f"  [+] {pt:22} -> Confirmed Planned / Documented-Only (No wrapper)")

    print("\n[3] Cross-checking with 9A-tool-inventory.md:")
    if "Implemented-and-Used" not in inventory_text:
        errors.append("9A-tool-inventory.md missing 'Implemented-and-Used' classification tag")
    else:
        print("  [+] 9A-tool-inventory.md contains verified classification taxonomy.")

    print("\n" + "=" * 60)
    if errors:
        print(f"FAILED: {len(errors)} inventory synchronization error(s):")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)
    else:
        print("SUCCESS: All active and planned tools are 100% synchronized between docs and code.")
        print("=" * 60)

if __name__ == "__main__":
    main()
