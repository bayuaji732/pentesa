"""Pentesa cryptographic audit logging engine with SHA-256 hash chaining."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

GENESIS_HASH = "0" * 64


def canonical_json(data: Optional[Dict[str, Any]]) -> str:
    """Format dictionary into deterministic canonical JSON for hashing."""
    if not data:
        return "{}"
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def compute_audit_hash(
    prev_hash: str,
    timestamp: datetime,
    user_id: Optional[str],
    action: str,
    resource_type: str,
    resource_id: Optional[str],
    details: Optional[Dict[str, Any]],
    ip_address: Optional[str] = None
) -> str:
    """
    Compute cryptographic SHA-256 hash for an audit log entry.
    Format: prev_hash:timestamp_iso:user_id:action:resource_type:resource_id:ip:canonical_details
    """
    if isinstance(timestamp, datetime):
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        ts_str = timestamp.isoformat()
    elif isinstance(timestamp, str):
        if not timestamp.endswith("+00:00") and not timestamp.endswith("Z"):
            ts_str = timestamp + "+00:00"
        else:
            ts_str = timestamp.replace("Z", "+00:00")
    else:
        ts_str = str(timestamp)
    payload = ":".join([
        prev_hash or GENESIS_HASH,
        ts_str,
        str(user_id or ""),
        action,
        resource_type,
        str(resource_id or ""),
        str(ip_address or ""),
        canonical_json(details)
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_audit_chain(entries: List[Dict[str, Any]]) -> Tuple[bool, Optional[str], Optional[int]]:
    """
    Verify the cryptographic integrity of an audit log chain.
    Returns:
        (is_valid, error_reason, failed_index)
    """
    if not entries:
        return True, None, None

    expected_prev = GENESIS_HASH
    for idx, entry in enumerate(entries):
        actual_prev = entry.get("prev_hash") or GENESIS_HASH
        if actual_prev != expected_prev:
            return (
                False,
                f"Broken hash chain at index {idx}: expected prev_hash {expected_prev}, got {actual_prev}",
                idx
            )

        ts = entry.get("timestamp") or entry.get("created_at")
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                pass
        if isinstance(ts, datetime) and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        calculated_hash = compute_audit_hash(
            prev_hash=actual_prev,
            timestamp=ts,
            user_id=entry.get("user_id"),
            action=entry.get("action", ""),
            resource_type=entry.get("resource_type", ""),
            resource_id=entry.get("resource_id"),
            details=entry.get("details"),
            ip_address=entry.get("ip_address")
        )

        recorded_hash = entry.get("hash")
        if calculated_hash != recorded_hash:
            return (
                False,
                f"Hash mismatch at index {idx}: recorded {recorded_hash}, calculated {calculated_hash}",
                idx
            )

        expected_prev = recorded_hash

    return True, None, None

