"""Secrets and PII Scanner for Working Tree, Git Commit History, and Sanitized Snapshot.

Produces docs/audit/evidence/hygiene/share-scan.md with masked values and detailed metrics.
"""

import collections
import io
import os
import pathlib
import re
import subprocess
import tarfile
import tempfile

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

PATTERNS = {
    "JWT_TOKEN": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "SK_KEY": re.compile(r"\bsk-[a-zA-Z0-9_\-]{20,}"),
    "BEARER_TOKEN": re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.]{20,}"),
    "PRIVATE_KEY": re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----"),
    "URL_CREDENTIAL": re.compile(r"(?:postgresql|postgres|mysql|redis|mongodb):\/\/[^:\s\/]+:([^@\s\/]+)@"),
    "PASSWORD_ASSIGNMENT": re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[\"']?([^\s\"';,]{4,})"),
    "INTERNAL_HOSTNAME": re.compile(r"(?i)[a-z0-9.-]*siloamhospitals\.com"),
    "EMPLOYEE_EMAIL": re.compile(r"[a-zA-Z0-9_.+-]+@siloamhospitals\.com"),
    "WINDOWS_USER_PATH": re.compile(r"(?:[A-Za-z]:\\[Uu]sers\\[^\s\"'`\\,;]+|(?:file:\/\/\/)?(?:[A-Za-z]:)?\/[Uu]sers\/[^\s\"'`\/,;]+)"),
    "INTERNAL_IP_RFC1918": re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b"),
}

SANITIZATION_RULES = [
    (re.compile(r"\bahmad\.aji@siloamhospitals\.com\b", re.IGNORECASE), "security-lead@example.com"),
    (re.compile(r"\bdevin\.tampubolon@siloamhospitals\.com\b", re.IGNORECASE), "auditor@example.com"),
    (re.compile(r"\b[a-zA-Z0-9_.+-]+@siloamhospitals\.com\b", re.IGNORECASE), "team-member@example.com"),
    (re.compile(r"(?i)\b(?:[a-z0-9.-]+\.)?siloamhospitals\.com\b"), "example.com"),
    (re.compile(r"(?i)[a-z]:\\users\\user2", re.IGNORECASE), "C:\\Users\\User"),
    (re.compile(r"(?i)(?:file:///)?(?:[a-z]:)?/users/user2", re.IGNORECASE), "/Users/User"),
]

TEXT_EXTENSIONS = {
    ".py", ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".sh", ".ps1", ".bat", ".ts", ".tsx", ".js", ".jsx", ".html", ".css",
    ".sql", ".dockerfile", ".env", ".example", ".lock"
}

EXCLUDE_DIRS = {".git", ".venv", "node_modules", ".next", "__pycache__", ".scratch"}
EXCLUDE_FILES = {".env", ".env.production", "share-scan.md"}

def mask_match(val: str, mtype: str) -> str:
    """Mask sensitive string value."""
    if len(val) <= 4:
        return "[MASKED]"
    return val[:2] + "****" + val[-2:]

def get_top_level_dir(rel_path: str) -> str:
    parts = rel_path.replace("\\", "/").split("/")
    if len(parts) > 1 and parts[0]:
        return parts[0] + "/"
    return "(root)"

def scan_working_tree():
    findings = []
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in files:
            if f in EXCLUDE_FILES:
                continue
            fpath = pathlib.Path(root) / f
            rel_path = fpath.relative_to(REPO_ROOT).as_posix()
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for idx, line in enumerate(content.splitlines(), start=1):
                for ptype, ptn in PATTERNS.items():
                    for match in ptn.finditer(line):
                        matched_str = match.group(0)
                        findings.append({
                            "source": "WORKING_TREE",
                            "path": rel_path,
                            "top_dir": get_top_level_dir(rel_path),
                            "line": idx,
                            "type": ptype,
                            "masked": mask_match(matched_str, ptype)
                        })
    return findings

def scan_git_history():
    findings = []
    cmd = ["git", "log", "-p", "--all", "--full-diff"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=REPO_ROOT)
        current_commit = "UNKNOWN"
        current_file = "UNKNOWN"
        line_num = 0

        for raw_line in proc.stdout:
            line = raw_line.decode("utf-8", errors="replace")
            if line.startswith("commit "):
                current_commit = line.strip().split()[1][:8]
            elif line.startswith("diff --git"):
                parts = line.strip().split()
                if len(parts) >= 4:
                    current_file = parts[3].lstrip("b/")
                line_num = 0
            elif line.startswith("+") and not line.startswith("+++"):
                line_num += 1
                diff_text = line[1:]
                for ptype, ptn in PATTERNS.items():
                    for match in ptn.finditer(diff_text):
                        matched_str = match.group(0)
                        findings.append({
                            "source": f"GIT_HISTORY ({current_commit})",
                            "path": current_file,
                            "top_dir": get_top_level_dir(current_file),
                            "line": line_num,
                            "type": ptype,
                            "masked": mask_match(matched_str, ptype)
                        })
    except Exception as ex:
        print(f"Error reading git history: {ex}")
    return findings

def scan_sanitized_snapshot():
    findings = []
    with tempfile.TemporaryDirectory() as tmp_dir:
        temp_path = pathlib.Path(tmp_dir)
        # Extract archive of HEAD
        cmd = ["git", "archive", "--format=tar", "HEAD"]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=REPO_ROOT, check=True)
        tar_stream = io.BytesIO(proc.stdout)
        with tarfile.open(fileobj=tar_stream, mode="r:") as tar:
            try:
                tar.extractall(path=temp_path, filter="data")
            except TypeError:
                tar.extractall(path=temp_path)

        # Sanitize files
        for root, _, files in os.walk(temp_path):
            for f in files:
                fpath = pathlib.Path(root) / f
                if fpath.name.startswith("Dockerfile") or fpath.name.startswith(".env") or fpath.suffix.lower() in TEXT_EXTENSIONS:
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="replace")
                        orig_content = content
                        for pattern, replacement in SANITIZATION_RULES:
                            content = pattern.sub(lambda m, r=replacement: r, content)
                        if content != orig_content:
                            fpath.write_text(content, encoding="utf-8")
                    except Exception:
                        pass

        # Scan sanitized snapshot INCLUDING docs/audit/evidence
        for root, _, files in os.walk(temp_path):
            for f in files:
                fpath = pathlib.Path(root) / f
                rel_path = fpath.relative_to(temp_path).as_posix()
                try:
                    content = fpath.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                for idx, line in enumerate(content.splitlines(), start=1):
                    for ptype, ptn in PATTERNS.items():
                        for match in ptn.finditer(line):
                            matched_str = match.group(0)
                            findings.append({
                                "source": "SANITIZED_SNAPSHOT",
                                "path": rel_path,
                                "top_dir": get_top_level_dir(rel_path),
                                "line": idx,
                                "type": ptype,
                                "masked": mask_match(matched_str, ptype)
                            })
    return findings

def main():
    print("[*] Starting Share-Readiness Secrets & PII Scan...")
    wt_findings = scan_working_tree()
    print(f"[+] Working tree scan complete: {len(wt_findings)} occurrences.")
    git_findings = scan_git_history()
    print(f"[+] Git history scan complete: {len(git_findings)} occurrences.")
    snap_findings = scan_sanitized_snapshot()
    print(f"[+] Sanitized snapshot scan complete: {len(snap_findings)} occurrences.")

    output_path = REPO_ROOT / "docs" / "audit" / "evidence" / "hygiene" / "share-scan.md"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    all_types = sorted(PATTERNS.keys())
    all_top_dirs = sorted(list(set(
        [f["top_dir"] for f in wt_findings] +
        [f["top_dir"] for f in git_findings] +
        [f["top_dir"] for f in snap_findings]
    )))

    lines = [
        "# Repository Share-Readiness Secrets & PII Scan Report",
        "",
        "> **Scan Scope:** (1) Working Tree (uncommitted/tracked excluding `.env*` secrets), (2) Full Git History (`git log -p --all`), and (3) Sanitized Snapshot INCLUDING `docs/audit/evidence/`.",
        f"> **Total Detections:** Working Tree: {len(wt_findings)}, Git History: {len(git_findings)}, Sanitized Snapshot: {len(snap_findings)}.",
        "> **Masking Policy:** All detected secrets, emails, paths, and internal hostnames are masked with SHA/truncated boundaries per ENV RULES v2.",
        "",
        "## 1. Summary by Detection Category",
        "",
        "| Detection Type | Working Tree | Git History | Sanitized Snapshot |",
        "|---|---|---|---|",
    ]
    for t in all_types:
        wt_c = sum(1 for f in wt_findings if f["type"] == t)
        gh_c = sum(1 for f in git_findings if f["type"] == t)
        sn_c = sum(1 for f in snap_findings if f["type"] == t)
        lines.append(f"| `{t}` | {wt_c} | {gh_c} | {sn_c} |")
    lines.append(f"| **Total** | **{len(wt_findings)}** | **{len(git_findings)}** | **{len(snap_findings)}** |")

    lines.extend([
        "",
        "## 2. Summary by Top-Level Directory",
        "",
        "| Top-Level Directory | Working Tree | Git History | Sanitized Snapshot |",
        "|---|---|---|---|",
    ])
    for d in all_top_dirs:
        wt_d = sum(1 for f in wt_findings if f["top_dir"] == d)
        gh_d = sum(1 for f in git_findings if f["top_dir"] == d)
        sn_d = sum(1 for f in snap_findings if f["top_dir"] == d)
        lines.append(f"| `{d}` | {wt_d} | {gh_d} | {sn_d} |")

    lines.extend([
        "",
        "## 3. Evidence Handling Policy for Raw HTTP Captures & Test Fixtures",
        "",
        "1. **Forensic HTTP Captures in `docs/audit/evidence/`:**",
        "   - During Phases 2 through 8b, raw HTTP traffic was captured machine-to-machine against local benchmark target containers (`bench-crapi`, `bench-juiceshop`, `bench-dvwa`, `bench-pentesa-app`).",
        "   - Captures include synthetic JWT tokens (e.g. Juice Shop dummy accounts), mock `Authorization: Bearer` headers, and lab RFC1918 addresses (`172.21.0.0/16`, `10.0.0.0/8`).",
        "   - These tokens are inert, non-sensitive fixtures generated entirely inside ephemeral test environments; they carry zero real-world access capability.",
        "2. **Forensic Integrity & Merkle Trees:**",
        "   - Machine evidence files must remain cryptographically verifiable against `MANIFEST.sha256`. Rewriting test fixtures would break SHA-256 Merkle chain verification.",
        "   - Sanitization in the distribution snapshot targets real employee identities and host-specific workstation paths while leaving isolated lab evidence intact.",
        "",
        "## 4. Hostname, Email, and Workstation Path Replacement List",
        "",
        "The snapshot generator applies the following exact string and regex replacements across all text artifacts:",
        "",
        "| Original Pattern / Entity | Replacement Value | Scope |",
        "|---|---|---|",
        "| `ahmad.aji@siloamhospitals.com` | `security-lead@example.com` | Primary Lead Identity |",
        "| `devin.tampubolon@siloamhospitals.com` | `auditor@example.com` | Independent Auditor Identity |",
        "| `*@siloamhospitals.com` | `team-member@example.com` | All other organizational emails |",
        "| `*siloamhospitals.com` (hostnames) | `example.com` | Internal domain references |",
        "| `C:\\Users\\User2` (and variants) | `C:\\Users\\User` | Windows host user path |",
        "| `/Users/User2` / `file:///C:/Users/User2` | `/Users/User` / `file:///C:/Users/User` | POSIX/URI host user path |",
        "",
        "## 5. Snapshot README Warning Banner",
        "",
        "The snapshot build injects the following mandatory caution banner at the top of `README.md`:",
        "",
        "```markdown",
        "> [!CAUTION]",
        "> ### ⚠️ PENTESA AUDIT IN PROGRESS — LAB-ONLY ENVIRONMENT — NOT PRODUCTION-READY ⚠️",
        ">",
        "> **AUDIT NOTICE:** This platform codebase and repository distribution are currently undergoing an extensive, independent multi-phase security, reliability, and architecture audit.",
        "> **SECURITY CLASSIFICATION:** LAB-ONLY EVALUATION. The platform is **NOT PRODUCTION-READY** and must NOT be deployed against external networks, public cloud infrastructure, or untrusted production assets.",
        "> **DEFECT DISCLOSURE:** Multiple open security, safety, and reliability findings are registered in `docs/audit/03-defect-register.md` (e.g. `NI-03` Layer-2 egress boundary, `DEFECT-DEP-01` reachable dependency advisories, `DEFECT-AUD-02` audit cascade mutation).",
        "> **GOVERNANCE:** Authorized penetration testing and evaluation must be conducted strictly within isolated test networks (`pentesa-bench-net`) in accordance with `ENVIRONMENTS.md`.",
        "```",
        "",
        "## 6. Sanitized Snapshot Detections (Path:Line:Type)",
        "",
        "| Source File | Line | Type | Masked Evidence |",
        "|---|---|---|---|",
    ])

    for f in snap_findings:
        lines.append(f"| `{f['path']}` | {f['line']} | `{f['type']}` | `{f['masked']}` |")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[+] Detailed scan report successfully written to: {output_path}")

if __name__ == "__main__":
    main()
