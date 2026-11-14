"""Soft-404 baseline detector and response discriminator (TOOL-FP-01 / F4)."""

import hashlib
import logging
from typing import Any, Dict, List, Optional, Tuple
import uuid
import httpx

logger = logging.getLogger(__name__)


class Soft404Baseline:
    """Represents the multi-probe baseline response of a target server for non-existent paths."""

    def __init__(
        self,
        has_soft_404: bool = False,
        status_code: int = 404,
        content_length: int = 0,
        content_hash: str = "",
        body_snippet: str = "",
        signatures: Optional[List[Dict[str, Any]]] = None,
        probes_sent: int = 0,
        probes_soft_404: int = 0
    ):
        self.has_soft_404 = has_soft_404
        self.status_code = status_code
        self.content_length = content_length
        self.content_hash = content_hash
        self.body_snippet = body_snippet
        self.signatures = signatures or []
        self.probes_sent = probes_sent
        self.probes_soft_404 = probes_soft_404

        if has_soft_404 and not self.signatures and content_length > 0:
            self.signatures.append({
                "status_code": status_code,
                "content_length": content_length,
                "content_hash": content_hash,
                "body_snippet": body_snippet,
                "probe_type": "primary"
            })

    def is_match_with_reason(
        self,
        status: int,
        length: Optional[int] = None,
        body: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Return (True, reason) if response matches any soft-404 baseline probe."""
        if not self.has_soft_404:
            return False, ""

        # Check against all recorded baseline signatures
        for sig in self.signatures:
            sig_status = sig["status_code"]
            sig_len = sig["content_length"]
            sig_hash = sig["content_hash"]
            sig_snip = sig.get("body_snippet", "")
            probe_t = sig.get("probe_type", "baseline")

            if status != sig_status:
                continue

            # Length matching within +/- 5 bytes (covers dynamic CSRF / timestamp fluctuations)
            if length is not None and sig_len > 0:
                if abs(length - sig_len) <= 5:
                    return True, f"length {length}B matches {probe_t} soft-404 baseline ({sig_len}B +/- 5B, status {status})"

            if body:
                b_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
                if sig_hash and b_hash == sig_hash:
                    return True, f"SHA-256 hash match against {probe_t} soft-404 baseline ({sig_hash[:12]}...)"
                if sig_snip and len(sig_snip) >= 50 and sig_snip in body:
                    return True, f"HTML body signature matches {probe_t} soft-404 SPA index snippet"

        # Fallback to primary baseline attributes for backwards compatibility
        if status == self.status_code:
            if length is not None and self.content_length > 0 and abs(length - self.content_length) <= 5:
                return True, f"length {length}B matches primary soft-404 baseline ({self.content_length}B)"
            if body:
                b_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
                if self.content_hash and b_hash == self.content_hash:
                    return True, f"SHA-256 hash match ({self.content_hash[:12]}...)"

        return False, ""

    def is_match(self, status: int, length: Optional[int] = None, body: Optional[str] = None) -> bool:
        """Return True if the response matches the soft-404 baseline."""
        matched, _ = self.is_match_with_reason(status=status, length=length, body=body)
        return matched

    def to_dict(self) -> Dict[str, Any]:
        return {
            "has_soft_404": self.has_soft_404,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "content_hash": self.content_hash,
            "signatures_count": len(self.signatures),
            "probes_sent": self.probes_sent,
            "probes_soft_404": self.probes_soft_404
        }


async def detect_soft_404_baseline(
    target_url: str,
    client: Optional[httpx.AsyncClient] = None,
    timeout: float = 5.0
) -> Soft404Baseline:
    """Probe 3 non-existent variants (extensionless, .html, trailing slash) to detect SPA catch-alls."""
    token = uuid.uuid4().hex[:12]
    clean_target = target_url.rstrip("/")

    # 3 distinct baseline probe shapes (F4-4)
    probes = [
        ("extensionless", f"{clean_target}/pentesa_fp_probe_{token}"),
        ("html_extension", f"{clean_target}/pentesa_fp_probe_{token}.html"),
        ("trailing_slash", f"{clean_target}/pentesa_fp_probe_{token}/")
    ]

    signatures: List[Dict[str, Any]] = []
    has_soft_404 = False
    probes_sent = 0
    probes_soft_404 = 0

    close_client = False
    if client is None:
        client = httpx.AsyncClient(verify=False)
        close_client = True

    try:
        for probe_type, probe_url in probes:
            probes_sent += 1
            try:
                resp = await client.get(probe_url, timeout=timeout, follow_redirects=False)
                # Soft-404 occurs when a non-existent route returns 200 or 206
                if resp.status_code in (200, 206):
                    has_soft_404 = True
                    probes_soft_404 += 1
                    body_bytes = resp.content
                    length = len(body_bytes)
                    hdr_len = resp.headers.get("content-length")
                    if hdr_len and hdr_len.isdigit():
                        length = int(hdr_len)

                    b_hash = hashlib.sha256(body_bytes).hexdigest()
                    body_text = resp.text
                    snippet = body_text[:200] if len(body_text) >= 200 else body_text

                    # Add signature if not already present
                    if not any(s["content_length"] == length and s["status_code"] == resp.status_code for s in signatures):
                        signatures.append({
                            "status_code": resp.status_code,
                            "content_length": length,
                            "content_hash": b_hash,
                            "body_snippet": snippet,
                            "probe_type": probe_type
                        })
                    logger.info(
                        f"[Soft-404 Detected] Probe '{probe_type}' ({probe_url}) -> "
                        f"HTTP {resp.status_code} ({length} bytes, SHA256: {b_hash[:12]}...)"
                    )
            except Exception as e:
                logger.debug(f"Soft-404 probe failed for {probe_url}: {e}")

        if has_soft_404 and signatures:
            primary = signatures[0]
            return Soft404Baseline(
                has_soft_404=True,
                status_code=primary["status_code"],
                content_length=primary["content_length"],
                content_hash=primary["content_hash"],
                body_snippet=primary["body_snippet"],
                signatures=signatures,
                probes_sent=probes_sent,
                probes_soft_404=probes_soft_404
            )
        else:
            return Soft404Baseline(
                has_soft_404=False,
                probes_sent=probes_sent,
                probes_soft_404=0
            )

    finally:
        if close_client:
            await client.aclose()
