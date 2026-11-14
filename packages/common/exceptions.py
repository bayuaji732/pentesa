"""Pentesa custom typed exceptions."""

from typing import Any, Dict, Optional


class PentesaError(Exception):
    """Base exception for all Pentesa errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ScopeViolationError(PentesaError):
    """Raised when a request target violates the project's authorized scope."""
    pass


class UnauthorizedTargetError(ScopeViolationError):
    """Raised when a target resolves to a forbidden destination (e.g. metadata service, private IP)."""
    pass


class AuthenticationError(PentesaError):
    """Raised when authentication credentials or token are invalid."""
    pass


class AuthorizationError(PentesaError):
    """Raised when an authenticated user lacks required permissions."""
    pass


class ProjectAuthorizationExpiredError(AuthorizationError):
    """Raised when attempting testing on a project outside its authorized window."""
    pass


class ResourceNotFoundError(PentesaError):
    """Raised when a requested entity does not exist."""
    pass


class ConflictError(PentesaError):
    """Raised when an operation would violate unique constraints."""
    pass


class AuditIntegrityError(PentesaError):
    """Raised when cryptographic verification of the audit log chain fails."""
    pass


class BadRequestError(PentesaError):
    """Raised when an operation receives invalid parameters or triggers an illegal state transition."""
    pass


class ToolNotAvailableError(PentesaError):
    """Raised when a required external security tool binary is not installed or available."""

    def __init__(self, tool_name: str, message: Optional[str] = None):
        self.tool_name = tool_name
        super().__init__(
            message or f"Security tool binary '{tool_name}' is not installed or available on the host system."
        )


class LLMGatewayError(PentesaError, RuntimeError):
    """Raised when an upstream LLM gateway or provider is unreachable, times out, or fails (AGT-LLM-01)."""

    def __init__(
        self,
        message: str = "Upstream AI gateway unreachable",
        status_code: int = 502,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, details)
        self.status_code = status_code


# Aliases for naming compatibility
BadRequestException = BadRequestError
NotFoundException = ResourceNotFoundError
ScopeViolationException = ScopeViolationError
ToolNotAvailableException = ToolNotAvailableError



