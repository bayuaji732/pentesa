"""Logging filter for sensitive credentials and tokens."""

import logging
from typing import List, Optional
from services.evidence_engine.redactor import redact_custom_secrets, redact_raw_stream


class SensitiveDataLoggingFilter(logging.Filter):
    """Logging filter that scrubs tokens, passwords, authorization headers, and secrets."""

    def __init__(self, custom_secrets: Optional[List[str]] = None):
        super().__init__()
        self.custom_secrets: List[str] = list(custom_secrets or [])

    def add_secrets(self, secrets: List[str]) -> None:
        """Register additional sensitive secret tokens to scrub."""
        for s in secrets:
            if s and s not in self.custom_secrets and len(s) >= 4:
                self.custom_secrets.append(s)

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter log record, redacting any sensitive data in message or args."""
        if isinstance(record.msg, str):
            record.msg = redact_raw_stream(record.msg)
            if self.custom_secrets:
                record.msg = redact_custom_secrets(record.msg, self.custom_secrets)

        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: (
                        redact_custom_secrets(redact_raw_stream(v), self.custom_secrets)
                        if isinstance(v, str)
                        else v
                    )
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    redact_custom_secrets(redact_raw_stream(a), self.custom_secrets)
                    if isinstance(a, str)
                    else a
                    for a in record.args
                )

        return True

