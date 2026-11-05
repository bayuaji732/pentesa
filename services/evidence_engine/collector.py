"""Forensic evidence serialization and collector engine."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from database.models.finding import FindingEvidence
from services.evidence_engine.curl_generator import generate_reproduction_curl
from services.evidence_engine.hasher import compute_evidence_hash, compute_stream_hash
from services.evidence_engine.redactor import redact_raw_stream


def serialize_raw_http_request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None
) -> str:
    """Format HTTP request into raw RFC 7230 wire format."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    lines = [f"{method.upper()} {path} HTTP/1.1"]

    hdrs = dict(headers or {})
    if "Host" not in hdrs and "host" not in hdrs and parsed.netloc:
        lines.append(f"Host: {parsed.netloc}")

    for k, v in hdrs.items():
        lines.append(f"{k}: {v}")

    lines.append("")  # Blank line separating headers and body

    if body:
        lines.append(body)

    return "\r\n".join(lines)


def serialize_raw_http_response(
    status_code: int,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    reason_phrase: str = "OK"
) -> str:
    """Format HTTP response into raw RFC 7230 wire format."""
    lines = [f"HTTP/1.1 {status_code} {reason_phrase}"]

    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")

    lines.append("")  # Blank line separating headers and body

    if body:
        lines.append(body)

    return "\r\n".join(lines)


def build_forensic_evidence(
    method: str,
    url: str,
    request_headers: Optional[Dict[str, str]] = None,
    request_body: Optional[str] = None,
    response_status: int = 200,
    response_headers: Optional[Dict[str, str]] = None,
    response_body: Optional[str] = None,
    screenshot_path: Optional[str] = None
) -> Dict[str, Any]:
    """Compile, sanitize, hash, and format raw request/response into forensic evidence."""
    # 1. Serialize raw wire streams
    raw_req_unredacted = serialize_raw_http_request(
        method=method,
        url=url,
        headers=request_headers,
        body=request_body
    )
    raw_resp_unredacted = serialize_raw_http_response(
        status_code=response_status,
        headers=response_headers,
        body=response_body
    )

    # 2. Apply sensitive redaction
    sanitized_req = redact_raw_stream(raw_req_unredacted)
    sanitized_resp = redact_raw_stream(raw_resp_unredacted)

    # 3. Compute SHA-256 cryptographic hashes
    req_hash = compute_stream_hash(sanitized_req)
    resp_hash = compute_stream_hash(sanitized_resp)
    now = datetime.now(timezone.utc)
    evidence_hash = compute_evidence_hash(req_hash, resp_hash, now)

    # 4. Generate reproduction curl
    repro_curl = generate_reproduction_curl(
        method=method,
        url=url,
        headers=request_headers,
        body=request_body,
        redact_auth=True
    )

    return {
        "raw_request": sanitized_req,
        "raw_response": sanitized_resp,
        "reproduction_curl": repro_curl,
        "request_hash_sha256": req_hash,
        "response_hash_sha256": resp_hash,
        "evidence_hash": evidence_hash,
        "screenshot_path": screenshot_path,
        "captured_at": now
    }

