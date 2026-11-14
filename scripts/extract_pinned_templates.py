"""Bake and extract pinned Nuclei templates (TOOL-ASSETS-01 / FIX-11).

Extracts official pinned Nuclei templates release (v10.5.2) with SHA-256 verification,
strictly limited to non-intrusive directories (exposures, misconfiguration,
technologies, exposed-panels) and excluding intrusive/dos/fuzz/bruteforce tags.
"""

import hashlib
import os
import re
import sys
import zipfile

EXPECTED_TAG = "v10.5.2"
EXPECTED_SHA256 = "24551e1ef6a5f99f6a0a3cb98abc4325a1e554367d2a8ce09caaf82d860cd50b"

ALLOWED_HTTP_DIRS = {"exposures", "misconfiguration", "technologies", "exposed-panels"}
EXCLUDED_TAGS_RE = re.compile(r"tags:\s*.*\b(dos|intrusive|fuzz|bruteforce)\b", re.IGNORECASE)


def extract_templates(zip_path: str, dest_dir: str) -> int:
    """Verify SHA-256 and extract non-intrusive templates to dest_dir."""
    if not os.path.isfile(zip_path):
        raise FileNotFoundError(f"Nuclei templates zip archive not found at: {zip_path}")

    # 1. SHA-256 Verification
    h = hashlib.sha256()
    with open(zip_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    actual_hash = h.hexdigest().lower()

    if actual_hash != EXPECTED_SHA256.lower():
        raise ValueError(
            f"SHA-256 checksum mismatch for {zip_path}!\n"
            f"Expected: {EXPECTED_SHA256}\n"
            f"Actual:   {actual_hash}"
        )

    print(f"[OK] SHA-256 verified for nuclei-templates {EXPECTED_TAG}: {actual_hash}")

    os.makedirs(dest_dir, exist_ok=True)
    extracted_count = 0

    with zipfile.ZipFile(zip_path, "r") as z:
        for item in z.infolist():
            if not item.filename.endswith((".yaml", ".yml")):
                continue
            parts = item.filename.split("/")
            # Look for http/<allowed_dir>/...
            if len(parts) >= 3 and parts[1] == "http" and parts[2] in ALLOWED_HTTP_DIRS:
                content = z.read(item).decode("utf-8", errors="ignore")
                if EXCLUDED_TAGS_RE.search(content):
                    continue

                rel_path = "/".join(parts[2:])
                target_path = os.path.join(dest_dir, rel_path)
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with open(target_path, "w", encoding="utf-8") as out_f:
                    out_f.write(content)
                extracted_count += 1

    print(f"[SUCCESS] Extracted {extracted_count} non-intrusive Nuclei templates into {dest_dir}")
    return extracted_count


if __name__ == "__main__":
    zip_p = sys.argv[1] if len(sys.argv) > 1 else "integrations/nuclei/nuclei-templates.zip"
    dest = sys.argv[2] if len(sys.argv) > 2 else "/opt/nuclei-templates"
    extract_templates(zip_p, dest)
