"""Soft-404 baseline detector and response discriminator (TOOL-FP-01)."""

import hashlib
import logging
from typing import Any, Dict, Optional
import uuid
import httpx

logger = logging.getLogger(__name__)


class Soft404Baseline:
    """Represents the baseline response of a target server for non-existent paths."""

    def __init__(
        self,
        has_soft_404: bool = False,
        status_code: int = 404,
        content_length: int = 0,
        content_hash: str = "",
        body_snippet: str = ""
    ):
        self.has_soft_404 = has_soft_404
        self.status_code = status_code
        self.content_length = content_length
        self.content_hash = content_hash
        self.body_snippet = body_snippet

    def is_match(self, status: int, length: Optional[int] = None, body: Optional[str] = None) -> bool:
        """Return True if the response matches the soft-404 baseline."""
        if not self.has_soft_404:
            return False
        if status != self.status_code:
            return False
        if length is not None and self.content_length > 0:
            if abs(length - self.content_length) <= 5:
                return True
        if body:
            b_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
            if self.content_hash and b_hash == self.content_hash:
                return True
            if self.body_snippet and self.body_snippet in body:
                return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "has_soft_404": self.has_soft_404,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "content_hash": self.content_hash
        }


async def detect_soft_404_baseline(
    target_url: str,
    client: Optional[httpx.AsyncClient] = None,
    timeout: float = 5.0
) -> Soft404Baseline:
    """Probe a random non-existent path to detect SPA catch-alls and soft-404 pages."""
    probe_slug = f"pentesa_fp_probe_{uuid.uuid4().hex[:12]}"
    probe_url = f"{target_url.rstrip('/')}/{probe_slug}"

    try:
        if client:
            resp = await client.get(probe_url, timeout=timeout, follow_redirects=False)
        else:
            async with httpx.AsyncClient(verify=False) as c:
                resp = await c.get(probe_url, timeout=timeout, follow_redirects=False)

        # Soft-404 occurs when a non-existent route returns 200 or 206
        if resp.status_code in (200, 206):
            body = resp.text
            body_bytes = resp.content
            length = len(body_bytes)
            hdr_len = resp.headers.get("content-length")
            if hdr_len and hdr_len.isdigit():
                length = int(hdr_len)

            b_hash = hashlib.sha256(body_bytes).hexdigest()
            snippet = body[:200] if len(body) >= 200 else body

            logger.info(
                f"[Soft-404 Detected] Target {target_url} returns HTTP {resp.status_code} "
                f"({length} bytes) for non-existent path /{probe_slug}"
            )
            return Soft404Baseline(
                has_soft_404=True,
                status_code=resp.status_code,
                content_length=length,
                content_hash=b_hash,
                body_snippet=snippet
            )
        else:
            return Soft404Baseline(
                has_soft_404=False,
                status_code=resp.status_code,
                content_length=len(resp.content),
                content_hash=""
            )
    except Exception as e:
        logger.warning(f"Could not probe soft-404 baseline for {target_url}: {e}")
        return Soft404Baseline(has_soft_404=False)
