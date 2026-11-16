"""Unit tests for forensic evidence engine: redaction, hashing, cURL generation, and serialization."""

import pytest
from services.evidence_engine.collector import (
    build_forensic_evidence,
    serialize_raw_http_request,
    serialize_raw_http_response
)
from services.evidence_engine.curl_generator import (
    escape_shell_arg,
    generate_reproduction_curl
)
from services.evidence_engine.hasher import (
    compute_evidence_hash,
    compute_stream_hash
)
from services.evidence_engine.redactor import (
    mask_sensitive_headers,
    redact_raw_stream
)


def test_mask_sensitive_headers():
    """Verify dictionary-level header redaction."""
    headers = {
        "Host": "api.example.com",
        "Authorization": "Bearer supersecretjwttoken12345",
        "X-Api-Key": "adminkey9988",
        "Cookie": "session=secret_cookie_val",
        "Content-Type": "application/json"
    }
    masked = mask_sensitive_headers(headers)
    assert masked["Host"] == "api.example.com"
    assert masked["Authorization"] == "Bearer [REDACTED]"
    assert masked["X-Api-Key"] == "[REDACTED]"
    assert masked["Cookie"] == "[REDACTED]"
    assert masked["Content-Type"] == "application/json"


def test_redact_raw_stream_credentials():
    """Verify regex-based stream redaction for credentials and sensitive tokens."""
    raw_stream = (
        "POST /api/v1/login HTTP/1.1\r\n"
        "Host: api.example.com\r\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDc\r\n"
        "Cookie: sessionid=secret_session_123456789; theme=light\r\n"
        "Content-Type: application/json\r\n\r\n"
        '{"username": "admin", "password": "SuperSecretPassword123!"}'
    )

    redacted = redact_raw_stream(raw_stream)
    assert "Authorization: Bearer [REDACTED]" in redacted
    assert "sessionid=[REDACTED]" in redacted
    assert '"password": "[REDACTED]"' in redacted
    assert "SuperSecretPassword123!" not in redacted


def test_redact_raw_stream_credit_card():
    """Verify credit card number masking in HTTP streams."""
    raw_stream = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n\r\n"
        '{"customer": "John Doe", "pan": "4532-1234-5678-9012"}'
    )
    redacted = redact_raw_stream(raw_stream)
    assert "[REDACTED_PAN]" in redacted
    assert "4532-1234-5678-9012" not in redacted


def test_compute_stream_hash():
    """Verify deterministic SHA-256 computation."""
    content = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    h1 = compute_stream_hash(content)
    h2 = compute_stream_hash(content)
    assert h1 == h2
    assert len(h1) == 64
    assert h1 != compute_stream_hash("different content")


def test_compute_evidence_hash():
    """Verify combined evidence integrity digest generation."""
    req_hash = compute_stream_hash("request")
    resp_hash = compute_stream_hash("response")
    composite = compute_evidence_hash(req_hash, resp_hash)
    assert len(composite) == 64


def test_escape_shell_arg():
    """Verify POSIX single-quote escaping for shell arguments."""
    assert escape_shell_arg("normal") == "'normal'"
    assert escape_shell_arg("user's payload") == "'user'\\''s payload'"
    assert escape_shell_arg("") == "''"


def test_generate_reproduction_curl():
    """Verify reproducible cURL syntax formatting."""
    curl_cmd = generate_reproduction_curl(
        method="POST",
        url="https://api.target.com/v1/users",
        headers={
            "Authorization": "Bearer sensitive_token_abc_xyz",
            "Content-Type": "application/json"
        },
        body='{"role": "admin"}'
    )

    assert "curl -i -s" in curl_cmd
    assert "-X POST" in curl_cmd
    assert "'https://api.target.com/v1/users'" in curl_cmd
    assert "-H 'Authorization: Bearer [REDACTED]'" in curl_cmd
    assert "--data-raw '{\"role\": \"admin\"}'" in curl_cmd
    assert "sensitive_token_abc_xyz" not in curl_cmd


def test_generate_reproduction_curl_redacts_body_secrets():
    """Verify passwords and tokens in POST bodies are redacted in reproduction cURL commands."""
    curl_cmd = generate_reproduction_curl(
        method="POST",
        url="https://api.target.com/v1/login",
        headers={"Content-Type": "application/json"},
        body='{"email": "admin@juice-sh.op", "password": "SuperSecretPassword123!"}',
        redact_auth=True
    )
    assert "SuperSecretPassword123!" not in curl_cmd
    assert "[REDACTED]" in curl_cmd


def test_serialize_raw_http_wire_format():
    """Verify RFC 7230 request and response wire stream formatting."""
    req = serialize_raw_http_request(
        method="GET",
        url="https://target.com/api/search?q=test",
        headers={"Accept": "application/json"}
    )
    assert req.startswith("GET /api/search?q=test HTTP/1.1\r\n")
    assert "Host: target.com\r\n" in req
    assert "Accept: application/json\r\n" in req

    resp = serialize_raw_http_response(
        status_code=404,
        headers={"Content-Type": "text/plain"},
        body="Not Found",
        reason_phrase="Not Found"
    )
    assert resp.startswith("HTTP/1.1 404 Not Found\r\n")
    assert "Content-Type: text/plain\r\n" in resp
    assert resp.endswith("\r\n\r\nNot Found")


def test_build_forensic_evidence_bundle():
    """Verify complete evidence bundle construction with hashes and redaction."""
    evidence = build_forensic_evidence(
        method="POST",
        url="https://target.com/auth",
        request_headers={"Authorization": "Bearer secret_jwt_token_12345"},
        request_body='{"password": "mypassword123"}',
        response_status=200,
        response_headers={"Set-Cookie": "sessionid=xyz123abc; Secure"},
        response_body='{"authenticated": true}'
    )

    assert "raw_request" in evidence
    assert "raw_response" in evidence
    assert "request_hash_sha256" in evidence
    assert "response_hash_sha256" in evidence
    assert "evidence_hash" in evidence
    assert "reproduction_curl" in evidence

    assert "secret_jwt_token_12345" not in evidence["raw_request"]
    assert "mypassword123" not in evidence["raw_request"]
    assert "xyz123abc" not in evidence["raw_response"]
