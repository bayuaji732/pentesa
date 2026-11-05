"""Evidence collection and forensic artifact management package."""

from services.evidence_engine.collector import (
    build_forensic_evidence,
    serialize_raw_http_request,
    serialize_raw_http_response
)
from services.evidence_engine.curl_generator import (
    escape_shell_arg,
    generate_reproduction_curl
)
from services.evidence_engine.finding_service import (
    VALID_FINDING_TRANSITIONS,
    FindingService
)
from services.evidence_engine.hasher import (
    compute_evidence_hash,
    compute_stream_hash
)
from services.evidence_engine.redactor import (
    mask_sensitive_headers,
    redact_raw_stream
)

__all__ = [
    "redact_raw_stream",
    "mask_sensitive_headers",
    "compute_stream_hash",
    "compute_evidence_hash",
    "escape_shell_arg",
    "generate_reproduction_curl",
    "serialize_raw_http_request",
    "serialize_raw_http_response",
    "build_forensic_evidence",
    "FindingService",
    "VALID_FINDING_TRANSITIONS"
]

