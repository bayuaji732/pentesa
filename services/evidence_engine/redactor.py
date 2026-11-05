"""Automated sensitive data masking and PII redaction engine.

Cleanses raw HTTP requests and responses prior to persistent database storage or reporting,
preventing credentials, session keys, and sensitive customer PII from leaking.
"""

import re
from typing import Dict

# Regex patterns for sensitive tokens
BEARER_TOKEN_REGEX = re.compile(r"(Authorization:\s*Bearer\s+)[A-Za-z0-9_\-\.]{15,}", re.IGNORECASE)
BASIC_AUTH_REGEX = re.compile(r"(Authorization:\s*Basic\s+)[A-Za-z0-9+/=]{8,}", re.IGNORECASE)
GENERIC_AUTH_HEADER_REGEX = re.compile(r"(X-Api-Key|Api-Key|Token|Secret|X-Auth-Token)(:\s*)[^\r\n]+", re.IGNORECASE)

# JSON password & secret fields
JSON_PASSWORD_REGEX = re.compile(
    r'("(?:password|passwd|pass|secret|client_secret|access_token|refresh_token|private_key)"\s*:\s*)"[^"]+"',
    re.IGNORECASE
)

# Form-urlencoded password fields
FORM_PASSWORD_REGEX = re.compile(
    r"((?:^|[&?])(?:password|passwd|pass|secret|access_token|token)=)[^&]+",
    re.IGNORECASE
)

# Session cookies in Cookie or Set-Cookie headers
COOKIE_TOKEN_REGEX = re.compile(
    r"((?:session|sessionid|sess|token|jwt|auth|PHPSESSID|JSESSIONID|connect\.sid)=)[^;\r\n]+",
    re.IGNORECASE
)

# Credit card numbers (13 to 16 digits, with optional hyphens or spaces)
CREDIT_CARD_REGEX = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")


def mask_sensitive_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Return a copy of headers with sensitive values redacted."""
    sensitive_keys = {
        "authorization", "proxy-authorization", "x-api-key", "api-key",
        "token", "secret", "cookie", "set-cookie", "x-auth-token"
    }
    sanitized = {}
    for k, v in headers.items():
        if k.lower() in sensitive_keys:
            if k.lower() == "authorization" and v.lower().startswith("bearer "):
                sanitized[k] = "Bearer [REDACTED]"
            elif k.lower() == "authorization" and v.lower().startswith("basic "):
                sanitized[k] = "Basic [REDACTED]"
            else:
                sanitized[k] = "[REDACTED]"
        else:
            sanitized[k] = v
    return sanitized


def redact_raw_stream(raw_text: str) -> str:
    """Mask credentials, tokens, session cookies, and PII from a raw HTTP stream."""
    if not raw_text:
        return ""

    sanitized = raw_text

    # Redact Authorization headers
    sanitized = BEARER_TOKEN_REGEX.sub(r"\1[REDACTED]", sanitized)
    sanitized = BASIC_AUTH_REGEX.sub(r"\1[REDACTED]", sanitized)
    sanitized = GENERIC_AUTH_HEADER_REGEX.sub(r"\1\2[REDACTED]", sanitized)

    # Redact cookie values
    sanitized = COOKIE_TOKEN_REGEX.sub(r"\1[REDACTED]", sanitized)

    # Redact JSON sensitive keys
    sanitized = JSON_PASSWORD_REGEX.sub(r'\1"[REDACTED]"', sanitized)

    # Redact form encoded parameters
    sanitized = FORM_PASSWORD_REGEX.sub(r"\1[REDACTED]", sanitized)

    # Redact credit card numbers
    sanitized = CREDIT_CARD_REGEX.sub("[REDACTED_PAN]", sanitized)

    return sanitized

