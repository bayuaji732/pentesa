"""Cryptographic SHA-256 integrity hashing for evidence artifacts."""

import hashlib
from datetime import datetime, timezone
from typing import Optional


def compute_stream_hash(raw_stream: str) -> str:
    """Compute SHA-256 hexadecimal digest for raw HTTP text bytes."""
    if raw_stream is None:
        raw_stream = ""
    return hashlib.sha256(raw_stream.encode("utf-8")).hexdigest()


def compute_evidence_hash(
    request_hash: str,
    response_hash: str,
    captured_at: Optional[datetime] = None
) -> str:
    """Compute combined SHA-256 evidence integrity digest.
    
    Hash = SHA-256(RequestHash:ResponseHash:TimestampISO)
    """
    ts = captured_at or datetime.now(timezone.utc)
    ts_str = ts.isoformat()
    composite = f"{request_hash}:{response_hash}:{ts_str}"
    return hashlib.sha256(composite.encode("utf-8")).hexdigest()

