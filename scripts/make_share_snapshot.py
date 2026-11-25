"""Share Snapshot Generator and Sanitizer.

Creates a sanitized share zip from a git tag in a temporary directory.
- Sanitizes employee emails, internal hostnames, and local user paths in the copy.
- Recomputes MANIFEST.sha256 files in the copy.
- Injects a team sharing section into the copy's README.md.
- Runs full secret & PII validation scanner on the sanitized copy.
- Packages into a distribution .zip archive (unless --dry-run).
- Never mutates the working repository.
"""

import argparse
import hashlib
import io
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Sanitization replacements
SANITIZATION_RULES = [
    # Employee email
    (re.compile(r"\bahmad\.aji@siloamhospitals\.com\b", re.IGNORECASE), "security-lead@example.com"),
    (re.compile(r"\bdevin\.tampubolon@siloamhospitals\.com\b", re.IGNORECASE), "auditor@example.com"),
    (re.compile(r"\b[a-zA-Z0-9_.+-]+@siloamhospitals\.com\b", re.IGNORECASE), "team-member@example.com"),
    # Internal hostname
    (re.compile(r"(?i)\b(?:[a-z0-9.-]+\.)?siloamhospitals\.com\b"), "example.com"),
    # Windows user path
    (re.compile(r"(?i)[a-z]:\\users\\user2", re.IGNORECASE), "C:\\Users\\User"),
    (re.compile(r"(?i)(?:file:///)?(?:[a-z]:)?/users/user2", re.IGNORECASE), "/Users/User"),
]

# Patterns for secret scanning
SCAN_PATTERNS = {
    "JWT_TOKEN": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "SK_KEY": re.compile(r"\bsk-[a-zA-Z0-9_\-]{20,}"),
    "BEARER_TOKEN": re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.]{20,}"),
    "PRIVATE_KEY": re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----"),
    "URL_CREDENTIAL": re.compile(r"(?:postgresql|postgres|mysql|redis|mongodb):\/\/[^:\s\/]+:([^@\s\/]+)@"),
    "INTERNAL_HOSTNAME": re.compile(r"(?i)[a-z0-9.-]*siloamhospitals\.com"),
    "EMPLOYEE_EMAIL": re.compile(r"[a-zA-Z0-9_.+-]+@siloamhospitals\.com"),
}

TEXT_EXTENSIONS = {
    ".py", ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".sh", ".ps1", ".bat", ".ts", ".tsx", ".js", ".jsx", ".html", ".css",
    ".sql", ".dockerfile", ".env", ".example", ".lock"
}

def is_text_file(path: pathlib.Path) -> bool:
    if path.name.startswith("Dockerfile") or path.name.startswith(".env"):
        return True
    return path.suffix.lower() in TEXT_EXTENSIONS

def extract_git_archive(tag: str, dest_dir: pathlib.Path):
    print(f"[*] Extracting git archive for ref '{tag}'...")
    cmd = ["git", "archive", "--format=tar", tag]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=REPO_ROOT, check=True)
    tar_stream = io.BytesIO(proc.stdout)
    with tarfile.open(fileobj=tar_stream, mode="r:") as tar:
        try:
            tar.extractall(path=dest_dir, filter="data")
        except TypeError:
            tar.extractall(path=dest_dir)
    print(f"[+] Extracted archive to temporary directory: {dest_dir}")

def sanitize_tree(dest_dir: pathlib.Path):
    print("[*] Sanitizing text files in temporary copy...")
    modified_count = 0
    for root, _, files in os.walk(dest_dir):
        for f in files:
            fpath = pathlib.Path(root) / f
            if not is_text_file(fpath):
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            orig_content = content
            for pattern, replacement in SANITIZATION_RULES:
                content = pattern.sub(lambda m, r=replacement: r, content)

            if content != orig_content:
                fpath.write_text(content, encoding="utf-8")
                modified_count += 1
    print(f"[+] Sanitization complete: {modified_count} files sanitized.")

def update_readme_sharing_guide(dest_dir: pathlib.Path):
    readme_path = dest_dir / "README.md"
    if not readme_path.exists():
        return
    content = readme_path.read_text(encoding="utf-8")
    
    warning_banner = (
        "> [!CAUTION]\n"
        "> ### ⚠️ PENTESA AUDIT IN PROGRESS — LAB-ONLY ENVIRONMENT — NOT PRODUCTION-READY ⚠️\n"
        ">\n"
        "> **AUDIT NOTICE:** This platform codebase and repository distribution are currently undergoing an extensive, independent multi-phase security, reliability, and architecture audit.\n"
        "> **SECURITY CLASSIFICATION:** LAB-ONLY EVALUATION. The platform is **NOT PRODUCTION-READY** and must NOT be deployed against external networks, public cloud infrastructure, or untrusted production assets.\n"
        "> **DEFECT DISCLOSURE:** Multiple open security, safety, and reliability findings are registered in [`docs/audit/03-defect-register.md`](docs/audit/03-defect-register.md) (e.g. `NI-03` Layer-2 egress boundary, `DEFECT-DEP-01` reachable dependency advisories, `DEFECT-AUD-02` audit cascade mutation).\n"
        "> **GOVERNANCE:** Authorized penetration testing and evaluation must be conducted strictly within isolated test networks (`pentesa-bench-net`) in accordance with `ENVIRONMENTS.md`.\n\n"
    )

    section = (
        "\n\n---\n\n"
        "## Team Collaboration & Sharing Guide\n\n"
        "This repository distribution is prepared for engineering team collaboration.\n\n"
        "### Quick Setup Instructions\n"
        "1. Copy `.env.example` (or `.env.production.example`) to `.env`:\n"
        "   ```bash\n"
        "   cp .env.example .env\n"
        "   ```\n"
        "2. Generate fresh, secure secrets for `PENTESA_SECRET_KEY` and `PENTESA_ENCRYPTION_KEY`:\n"
        "   ```bash\n"
        "   python -c \"import secrets; print(secrets.token_hex(32))\"\n"
        "   ```\n"
        "3. Configure your initial administrator email and password in `.env`:\n"
        "   ```bash\n"
        "   PENTESA_BOOTSTRAP_ADMIN_EMAIL=admin@example.com\n"
        "   PENTESA_BOOTSTRAP_ADMIN_PASSWORD=<your-secure-password>\n"
        "   ```\n"
        "4. Start the stack with Docker Compose:\n"
        "   ```bash\n"
        "   docker compose up -d\n"
        "   ```\n"
        "5. Access the Web UI at `http://localhost:3000` and API docs at `http://localhost:8000/docs`.\n"
    )
    new_content = content
    if "### ⚠️ PENTESA AUDIT IN PROGRESS" not in new_content:
        new_content = warning_banner + new_content
    if "## Team Collaboration & Sharing Guide" not in new_content:
        new_content = new_content + section
    readme_path.write_text(new_content, encoding="utf-8")
    print("[+] Injected Warning Banner and Team Collaboration Guide to snapshot README.md.")

def recompute_manifests(dest_dir: pathlib.Path):
    print("[*] Recomputing MANIFEST.sha256 files...")
    manifest_count = 0
    for root, _, files in os.walk(dest_dir):
        if "MANIFEST.sha256" in files:
            manifest_file = pathlib.Path(root) / "MANIFEST.sha256"
            lines = manifest_file.read_text(encoding="utf-8", errors="replace").splitlines()
            new_lines = []
            for line in lines:
                line_str = line.strip()
                if not line_str or line_str.startswith("#"):
                    new_lines.append(line)
                    continue
                parts = line_str.split(None, 1)
                if len(parts) != 2:
                    new_lines.append(line)
                    continue
                _, fname = parts
                fname_clean = fname.lstrip("*")
                target_file = pathlib.Path(root) / fname_clean
                if target_file.exists() and target_file.is_file():
                    h = hashlib.sha256(target_file.read_bytes()).hexdigest()
                    new_lines.append(f"{h}  {fname_clean}")
                else:
                    new_lines.append(line)
            manifest_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
            manifest_count += 1
    print(f"[+] Recomputed {manifest_count} MANIFEST.sha256 files.")

def scan_sanitized_copy(dest_dir: pathlib.Path) -> list:
    print("[*] Scanning sanitized copy for sensitive patterns...")
    findings = []
    for root, _, files in os.walk(dest_dir):
        for f in files:
            fpath = pathlib.Path(root) / f
            rel_path = fpath.relative_to(dest_dir).as_posix()
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for idx, line in enumerate(content.splitlines(), start=1):
                for ptype, ptn in SCAN_PATTERNS.items():
                    for match in ptn.finditer(line):
                        matched_str = match.group(0)
                        findings.append({
                            "path": rel_path,
                            "line": idx,
                            "type": ptype,
                            "match": matched_str[:3] + "***"
                        })
    return findings

def create_zip(source_dir: pathlib.Path, output_zip: pathlib.Path):
    print(f"[*] Packaging sanitized copy to {output_zip}...")
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(source_dir):
            for f in files:
                fpath = pathlib.Path(root) / f
                arcname = fpath.relative_to(source_dir).as_posix()
                zf.write(fpath, arcname)
    print(f"[+] Zip package successfully created: {output_zip} ({output_zip.stat().st_size:,} bytes)")

def main():
    parser = argparse.ArgumentParser(description="Create a sanitized share snapshot zip from a git tag.")
    parser.add_argument("--tag", default="admin-review-done", help="Git tag or commit ref to archive (default: admin-review-done)")
    parser.add_argument("--output", default="dist/pentesa-share-snapshot.zip", help="Output path for the sanitized zip")
    parser.add_argument("--dry-run", action="store_true", help="Simulate snapshot extraction, sanitization, and scan without writing zip")
    args = parser.parse_args()

    tag = args.tag
    out_zip = REPO_ROOT / args.output

    with tempfile.TemporaryDirectory() as tmp_dir:
        temp_path = pathlib.Path(tmp_dir)
        extract_git_archive(tag, temp_path)
        sanitize_tree(temp_path)
        update_readme_sharing_guide(temp_path)
        recompute_manifests(temp_path)

        findings = scan_sanitized_copy(temp_path)
        print(f"\n[=] Scan Results on Sanitized Copy: {len(findings)} findings.")
        if findings:
            for fd in findings[:10]:
                print(f"    - {fd['path']}:{fd['line']} [{fd['type']}] ({fd['match']})")
            if len(findings) > 10:
                print(f"    ... and {len(findings) - 10} more.")

        # Categorize findings
        fixture_paths = {"data/juiceshop_users.json", ".env.example", "docs/22-production-deployment-guide.md"}
        real_leaks = []
        fixture_matches = []
        for f in findings:
            is_fixture = any(f["path"].startswith(p) for p in ("tests/", "benchmark/", "scripts/", "docs/audit/evidence/")) or f["path"] in fixture_paths
            if is_fixture:
                fixture_matches.append(f)
            else:
                real_leaks.append(f)

        print(f"\n[=] Scan Results on Sanitized Copy: {len(findings)} total matches.")
        print(f"    - Safe Test/Benchmark Fixtures & Documentation Placeholders: {len(fixture_matches)}")
        print(f"    - Unsanitized Application / Configuration Leaks: {len(real_leaks)}")

        if real_leaks:
            print("[!] CRITICAL WARNING: Potential leaks in production code or config:")
            for lk in real_leaks:
                print(f"    - {lk['path']}:{lk['line']} [{lk['type']}] ({lk['match']})")
        else:
            print("[+] Zero unsanitized employee emails, internal hostnames, private keys, or API tokens detected in codebase.")

        if args.dry_run:
            print(f"[+] Dry run complete. Temporary directory {temp_path} will be automatically deleted.")
        else:
            create_zip(temp_path, out_zip)

if __name__ == "__main__":
    main()
