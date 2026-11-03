"""High-level Scope Enforcement Service orchestrating Layer 1 and Layer 2 validation."""

from datetime import datetime, timezone
from typing import Any, List, Optional
from urllib.parse import urlparse

from packages.common.exceptions import ProjectAuthorizationExpiredError, ScopeViolationError
from packages.schemas.scope import ScopeCheckResult
from services.scope_engine.dns_pinning import DnsPinningValidator
from services.scope_engine.validator import ScopeValidator


class ScopeEnforcementService:
    """Service combining Layer 1 application filtering and Layer 2 DNS validation."""

    def __init__(self):
        pass

    def check_target(
        self,
        project: Any,
        target_url: str,
        rules: Optional[List[Any]] = None,
        resolve_dns: bool = False,
        custom_resolver=None
    ) -> ScopeCheckResult:
        """
        Evaluate target URL against project authorization, Layer 1 scope rules,
        and optional Layer 2 DNS verification.
        """
        now = datetime.now(timezone.utc)

        # 1. Project Authorization Window Verification
        def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
            if dt is None:
                return None
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt

        auth_start = ensure_utc(getattr(project, "authorization_start", None))
        auth_end = ensure_utc(getattr(project, "authorization_end", None))
        status = getattr(project, "status", "ACTIVE")

        if status in ("ARCHIVED", "COMPLETED"):
            return ScopeCheckResult(
                is_in_scope=False,
                status="BLOCKED",
                reason=f"Project is in '{status}' status; active security testing is forbidden",
                target_url=target_url
            )

        if auth_start and now < auth_start:
            return ScopeCheckResult(
                is_in_scope=False,
                status="BLOCKED",
                reason=f"Project authorization window has not started yet (starts at {auth_start.isoformat()})",
                target_url=target_url
            )

        if auth_end and now > auth_end:
            return ScopeCheckResult(
                is_in_scope=False,
                status="BLOCKED",
                reason=f"Project authorization window expired at {auth_end.isoformat()}",
                target_url=target_url
            )

        # 2. Gather Scope Rules
        scope_rules = rules if rules is not None else getattr(project, "scope_rules", [])
        allow_internal = getattr(project, "allow_internal_networks", False)

        # 3. Layer 1 Application-level Scope Validation
        validator = ScopeValidator(scope_rules, allow_internal=allow_internal)
        l1_result = validator.validate_url(target_url)

        if not l1_result.is_in_scope:
            return l1_result

        # 4. Layer 2 DNS & Rebinding Validation (if requested)
        if resolve_dns and l1_result.evaluated_host:
            dns_val = DnsPinningValidator(allow_internal=allow_internal)
            is_valid, reason, resolved_ips, pinned_ip, rebinding = dns_val.resolve_and_verify(
                host=l1_result.evaluated_host,
                port=l1_result.evaluated_port or 443,
                custom_resolver=custom_resolver
            )
            l1_result.resolved_ips = resolved_ips
            l1_result.dns_rebinding_detected = rebinding

            if not is_valid:
                l1_result.is_in_scope = False
                l1_result.status = "DNS_REBINDING_VIOLATION" if rebinding else "BLOCKED"
                l1_result.reason = reason

        return l1_result

    def enforce_target(
        self,
        project: Any,
        target_url: str,
        rules: Optional[List[Any]] = None,
        resolve_dns: bool = False
    ) -> ScopeCheckResult:
        """
        Enforce scope check and raise ScopeViolationError if out of scope.
        """
        result = self.check_target(
            project=project,
            target_url=target_url,
            rules=rules,
            resolve_dns=resolve_dns
        )
        if not result.is_in_scope:
            raise ScopeViolationError(f"Target '{target_url}' is out of scope: {result.reason}")
        return result


scope_service = ScopeEnforcementService()
