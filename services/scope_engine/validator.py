"""Layer 1 Application-level Scope Validator.

Enforces authorized penetration testing target boundaries through mathematical
regex compilation, dot-boundary isolation, CIDR containment, port whitelisting,
and private IP / cloud metadata access controls.
"""

import ipaddress
import posixpath
import re
from typing import Any, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse

from packages.schemas.scope import ScopeCheckResult, ScopeRuleType, ScopeTargetType

# Cloud Instance Metadata Service (IMDS) endpoints - ALWAYS strictly prohibited
METADATA_IPS = {
    "169.254.169.254",    # AWS/Azure/GCP IPv4 Link-Local Metadata
    "169.254.170.2",      # AWS ECS task metadata
    "fd00:ec2::254",      # AWS IPv6 metadata
}
METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
}

SAFE_PROTOCOLS = {"http", "https"}


def parse_port_range(port_spec: Optional[str]) -> Set[int]:
    """
    Parse port specification string (e.g. '80,443', '8000-8010', '8080') into a set of integers.
    If None or empty, defaults to standard HTTP/HTTPS ports (80, 443).
    """
    if not port_spec or not port_spec.strip():
        return {80, 443}

    allowed_ports: Set[int] = set()
    parts = [p.strip() for p in port_spec.split(",") if p.strip()]
    for part in parts:
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            try:
                start = int(start_str.strip())
                end = int(end_str.strip())
                if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                    allowed_ports.update(range(start, end + 1))
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    allowed_ports.add(p)
            except ValueError:
                continue

    return allowed_ports or {80, 443}


def compile_domain_regex(pattern: str) -> re.Pattern:
    """
    Compile domain pattern into strict dot-boundary regex.
    Wildcard *.example.com matches:
      - example.com
      - foo.example.com
      - bar.foo.example.com
    Does NOT match:
      - evil-example.com
      - notexample.com
      - example.com.attacker.com
    """
    clean = pattern.strip().lower()
    if clean.startswith("*."):
        root = clean[2:]
        escaped_root = re.escape(root)
        regex_str = rf"^(?:[a-zA-Z0-9-]+\.)*{escaped_root}$"
    elif clean.startswith("."):
        root = clean[1:]
        escaped_root = re.escape(root)
        regex_str = rf"^(?:[a-zA-Z0-9-]+\.)*{escaped_root}$"
    else:
        escaped_root = re.escape(clean)
        regex_str = rf"^{escaped_root}$"

    return re.compile(regex_str, re.IGNORECASE)


def normalize_ip(ip_str: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """
    Parse and normalize IP address, automatically unmapping IPv4-mapped IPv6 addresses (e.g. ::ffff:192.168.1.1).
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            return ip.ipv4_mapped
        return ip
    except ValueError:
        return None


def is_prohibited_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_internal: bool) -> Tuple[bool, str]:
    """
    Check if an IP address belongs to cloud metadata or prohibited network blocks.
    Cloud metadata is NEVER allowed, even if allow_internal is True.
    """
    ip_str = str(ip)
    if ip_str in METADATA_IPS:
        return True, "Cloud Instance Metadata Service (IMDS) address is strictly prohibited"

    if not allow_internal:
        if ip.is_loopback:
            return True, f"Loopback address ({ip_str}) is blocked without internal network authorization"
        if ip.is_private:
            return True, f"Private RFC 1918 address ({ip_str}) is blocked without internal network authorization"
        if ip.is_link_local:
            return True, f"Link-local address ({ip_str}) is blocked without internal network authorization"
        if ip.is_reserved:
            return True, f"Reserved address ({ip_str}) is blocked"
        if ip.is_multicast:
            return True, f"Multicast address ({ip_str}) is blocked"

    return False, ""


def normalize_path(raw_path: str) -> str:
    """Normalize and resolve URL path to defeat traversal evasion (e.g. /public/../admin)."""
    if not raw_path:
        return "/"
    # Decode percent-encoding first
    decoded = unquote(raw_path)
    # Posix normal form
    normalized = posixpath.normpath(decoded)
    if raw_path.endswith("/") and not normalized.endswith("/"):
        normalized += "/"
    return normalized


class ScopeValidator:
    """Validator for testing destinations against project scope rules."""

    def __init__(self, rules: List[Any], allow_internal: bool = False):
        """
        Initialize validator with a collection of ScopeRule models or dicts.
        """
        self.rules = rules
        self.allow_internal = allow_internal
        self._compiled_domain_in_scope: List[Tuple[re.Pattern, Set[int], Any]] = []
        self._compiled_domain_out_of_scope: List[Tuple[re.Pattern, Any]] = []
        self._cidr_in_scope: List[Tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, Set[int], Any]] = []
        self._cidr_out_of_scope: List[Tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, Any]] = []
        self._excluded_paths: List[Tuple[str, Any]] = []

        self._compile_rules()

    def _compile_rules(self) -> None:
        """Pre-compile all rules for efficient runtime matching."""
        for rule in self.rules:
            # Support both ORM models and dicts
            r_type = getattr(rule, "rule_type", None) or (rule.get("rule_type") if isinstance(rule, dict) else None)
            target_type = getattr(rule, "target_type", None) or (rule.get("target_type") if isinstance(rule, dict) else "IN_SCOPE")
            pattern = getattr(rule, "pattern", "") or (rule.get("pattern", "") if isinstance(rule, dict) else "")
            port_range = getattr(rule, "port_range", None) or (rule.get("port_range") if isinstance(rule, dict) else None)
            ports = parse_port_range(port_range)

            if not pattern:
                continue

            # Path exclusions
            if r_type == ScopeRuleType.EXCLUDED_PATH or (r_type == ScopeRuleType.PATH_PREFIX and target_type == ScopeTargetType.OUT_OF_SCOPE):
                self._excluded_paths.append((normalize_path(pattern), rule))
                continue

            # Domain rules
            if r_type in (ScopeRuleType.DOMAIN_WILDCARD, ScopeRuleType.EXACT_DOMAIN):
                compiled_rgx = compile_domain_regex(pattern)
                if target_type == ScopeTargetType.OUT_OF_SCOPE:
                    self._compiled_domain_out_of_scope.append((compiled_rgx, rule))
                else:
                    self._compiled_domain_in_scope.append((compiled_rgx, ports, rule))
                continue

            # IP / CIDR rules
            if r_type in (ScopeRuleType.IP_CIDR, ScopeRuleType.EXACT_IP):
                try:
                    net = ipaddress.ip_network(pattern.strip(), strict=False)
                    if target_type == ScopeTargetType.OUT_OF_SCOPE:
                        self._cidr_out_of_scope.append((net, rule))
                    else:
                        self._cidr_in_scope.append((net, ports, rule))
                except ValueError:
                    continue

    def validate_url(self, target_url: str) -> ScopeCheckResult:
        """Validate an absolute URL against the compiled scope rules."""
        if not target_url or not isinstance(target_url, str):
            return ScopeCheckResult(
                is_in_scope=False,
                status="BLOCKED",
                reason="Invalid or empty target URL",
                target_url=target_url
            )

        try:
            parsed = urlparse(target_url.strip())
        except Exception as e:
            return ScopeCheckResult(
                is_in_scope=False,
                status="BLOCKED",
                reason=f"Failed to parse target URL: {str(e)}",
                target_url=target_url
            )

        protocol = (parsed.scheme or "https").lower()
        if protocol not in SAFE_PROTOCOLS:
            return ScopeCheckResult(
                is_in_scope=False,
                status="BLOCKED",
                reason=f"Protocol '{protocol}' is forbidden; only {SAFE_PROTOCOLS} permitted",
                target_url=target_url
            )

        host = parsed.hostname or ""
        if not host:
            return ScopeCheckResult(
                is_in_scope=False,
                status="BLOCKED",
                reason="Missing target hostname in URL",
                target_url=target_url
            )

        port = parsed.port or (443 if protocol == "https" else 80)
        path = parsed.path or "/"

        return self.validate_target(
            host=host,
            port=port,
            protocol=protocol,
            path=path,
            original_url=target_url
        )

    def validate_target(
        self,
        host: str,
        port: int = 443,
        protocol: str = "https",
        path: str = "/",
        original_url: Optional[str] = None
    ) -> ScopeCheckResult:
        """Validate target host, port, protocol, and path."""
        clean_host = host.strip().lower()
        clean_path = normalize_path(path)

        # 1. Cloud Metadata check
        if clean_host in METADATA_HOSTS:
            return ScopeCheckResult(
                is_in_scope=False,
                status="PRIVATE_NETWORK_BLOCKED",
                reason="Target hostname matches prohibited cloud metadata service",
                target_url=original_url,
                evaluated_host=clean_host,
                evaluated_port=port
            )

        # 2. Check if host is direct IP address
        ip_obj = normalize_ip(clean_host)
        if ip_obj:
            is_prohibited, reason = is_prohibited_ip(ip_obj, self.allow_internal)
            if is_prohibited:
                return ScopeCheckResult(
                    is_in_scope=False,
                    status="PRIVATE_NETWORK_BLOCKED",
                    reason=reason,
                    target_url=original_url,
                    evaluated_host=clean_host,
                    evaluated_port=port,
                    resolved_ips=[str(ip_obj)]
                )

        # 3. Check Path Exclusions
        for excluded_prefix, rule in self._excluded_paths:
            if clean_path.startswith(excluded_prefix):
                rule_id = getattr(rule, "id", None) or (rule.get("id") if isinstance(rule, dict) else None)
                return ScopeCheckResult(
                    is_in_scope=False,
                    status="EXCLUDED",
                    reason=f"Target path '{clean_path}' matches excluded path prefix '{excluded_prefix}'",
                    target_url=original_url,
                    evaluated_host=clean_host,
                    evaluated_port=port,
                    matched_rule_id=rule_id
                )

        # 4. Check IP rules (if direct IP target)
        if ip_obj:
            # Check explicit out of scope CIDRs
            for net, rule in self._cidr_out_of_scope:
                if ip_obj in net:
                    rule_id = getattr(rule, "id", None) or (rule.get("id") if isinstance(rule, dict) else None)
                    return ScopeCheckResult(
                        is_in_scope=False,
                        status="BLOCKED",
                        reason=f"Target IP {ip_obj} falls within explicitly excluded CIDR {net}",
                        target_url=original_url,
                        evaluated_host=clean_host,
                        evaluated_port=port,
                        matched_rule_id=rule_id
                    )

            # Check in scope CIDRs
            for net, allowed_ports, rule in self._cidr_in_scope:
                if ip_obj in net:
                    if port not in allowed_ports:
                        return ScopeCheckResult(
                            is_in_scope=False,
                            status="BLOCKED",
                            reason=f"Target port {port} is not in allowed port list {sorted(list(allowed_ports))} for CIDR {net}",
                            target_url=original_url,
                            evaluated_host=clean_host,
                            evaluated_port=port
                        )
                    rule_id = getattr(rule, "id", None) or (rule.get("id") if isinstance(rule, dict) else None)
                    return ScopeCheckResult(
                        is_in_scope=True,
                        status="ALLOWED",
                        reason=f"Target IP {ip_obj} matches authorized in-scope CIDR {net}",
                        target_url=original_url,
                        evaluated_host=clean_host,
                        evaluated_port=port,
                        matched_rule_id=rule_id,
                        resolved_ips=[str(ip_obj)]
                    )

        # 5. Check Domain Rules
        # Check explicit out-of-scope domain matches first
        for rgx, rule in self._compiled_domain_out_of_scope:
            if rgx.match(clean_host):
                rule_id = getattr(rule, "id", None) or (rule.get("id") if isinstance(rule, dict) else None)
                return ScopeCheckResult(
                    is_in_scope=False,
                    status="BLOCKED",
                    reason=f"Target host '{clean_host}' matches explicitly excluded domain pattern",
                    target_url=original_url,
                    evaluated_host=clean_host,
                    evaluated_port=port,
                    matched_rule_id=rule_id
                )

        # Check in-scope domain matches
        for rgx, allowed_ports, rule in self._compiled_domain_in_scope:
            if rgx.match(clean_host):
                if port not in allowed_ports:
                    return ScopeCheckResult(
                        is_in_scope=False,
                        status="BLOCKED",
                        reason=f"Target port {port} is not in authorized ports {sorted(list(allowed_ports))} for target {clean_host}",
                        target_url=original_url,
                        evaluated_host=clean_host,
                        evaluated_port=port
                    )
                rule_id = getattr(rule, "id", None) or (rule.get("id") if isinstance(rule, dict) else None)
                return ScopeCheckResult(
                    is_in_scope=True,
                    status="ALLOWED",
                    reason=f"Target host '{clean_host}' matches authorized in-scope domain rule",
                    target_url=original_url,
                    evaluated_host=clean_host,
                    evaluated_port=port,
                    matched_rule_id=rule_id
                )

        return ScopeCheckResult(
            is_in_scope=False,
            status="BLOCKED",
            reason=f"Target host '{clean_host}' does not match any authorized in-scope rules for this project",
            target_url=original_url,
            evaluated_host=clean_host,
            evaluated_port=port
        )
