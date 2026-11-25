"""Secrets and PII Scanner for Working Tree and Git Commit History.

Produces docs/audit/evidence/hygiene/share-scan.md with masked values.
"""

import os
import re
import subprocess
import pathlib

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

EXCLUDE_DIRS = {".git", ".venv", "node_modules", ".next", "__pycache__", ".scratch"}
EXCLUDE_FILES = {".env", ".env.production", "share-scan.md"}

def mask_match(val: str, mtype: str) -> str:
    """Mask sensitive string value."""
    if len(val) <= 4:
        return "[MASKED]"
    return val[:2] + "****" + val[-2:]

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
                            "line": line_num,
                            "type": ptype,
                            "masked": mask_match(matched_str, ptype)
                        })
    except Exception as ex:
        print(f"Error reading git history: {ex}")
    return findings

def main():
    print("Starting Secret & PII Scan...")
    wt_findings = scan_working_tree()
    print(f"Working tree scan complete: {len(wt_findings)} occurrences.")
    git_findings = scan_git_history()
    print(f"Git history scan complete: {len(git_findings)} occurrences.")

    output_path = REPO_ROOT / "docs" / "audit" / "evidence" / "hygiene" / "share-scan.md"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Repository Share-Readiness Secrets & PII Scan Report",
        "",
        "> **Scan Scope:** Working Tree (uncommitted/tracked excluding `.env*` secrets) + Full Git History (`git log -p --all`).",
        f"> **Total Detections:** {len(wt_findings) + len(git_findings)} (Working Tree: {len(wt_findings)}, Git History: {len(git_findings)}).",
        "> **Masking Policy:** All detected secrets, emails, paths, and internal hostnames are masked per ENV RULES v2.",
        "",
        "## 1. Summary by Detection Type",
        "",
        "| Detection Type | Working Tree | Git History | Total |",
        "|---|---|---|---|",
    ]

    all_types = sorted(PATTERNS.keys())
    for t in all_types:
        wt_c = sum(1 for f in wt_findings if f["type"] == t)
        gh_c = sum(1 for f in git_findings if f["type"] == t)
        lines.append(f"| `{t}` | {wt_c} | {gh_c} | {wt_c + gh_c} |")

    lines.extend([
        "",
        "## 2. Working Tree Detections (Path:Line:Type)",
        "",
        "| Source File | Line | Type | Masked Evidence |",
        "|---|---|---|---|",
    ])
    for f in wt_findings:
        lines.append(f"| `{f['path']}` | {f['line']} | `{f['type']}` | `{f['masked']}` |")

    lines.extend([
        "",
        "## 3. Git History Detections (Commit:Path:Type)",
        "",
        "| Git Commit & File | Diff Line | Type | Masked Evidence |",
        "|---|---|---|---|",
    ])
    for f in git_findings:
        lines.append(f"| `{f['source']}`: `{f['path']}` | {f['line']} | `{f['type']}` | `{f['masked']}` |")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Scan report written to: {output_path}")

if __name__ == "__main__":
    main()
