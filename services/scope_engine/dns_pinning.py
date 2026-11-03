"""Layer 2 Network/DNS-level Scope Validator & Anti-Rebinding Guard.

Resolves DNS records, inspects all resolved A/AAAA addresses against prohibited
spaces, validates IP pinning, and mitigates DNS rebinding attacks.
"""

import ipaddress
import socket
from typing import Any, List, Optional, Set, Tuple

from packages.schemas.scope import ScopeCheckResult
from services.scope_engine.validator import (
    METADATA_IPS,
    is_prohibited_ip,
    normalize_ip,
)


class DnsPinningValidator:
    """DNS Resolver and Anti-Rebinding validator."""

    def __init__(self, allow_internal: bool = False):
        self.allow_internal = allow_internal
        # Local pinning cache: host -> pinned_ip
        self._pinned_hosts: dict[str, str] = {}

    def resolve_and_verify(
        self,
        host: str,
        port: int = 443,
        custom_resolver=None
    ) -> Tuple[bool, str, List[str], Optional[str], bool]:
        """
        Resolve all A and AAAA records for host and verify them.
        Returns:
            (is_valid, reason, resolved_ips, pinned_ip, rebinding_detected)
        """
        clean_host = host.strip().lower()

        # If already an IP address, normalize directly
        direct_ip = normalize_ip(clean_host)
        if direct_ip:
            is_prohib, reason = is_prohibited_ip(direct_ip, self.allow_internal)
            if is_prohib:
                return False, reason, [str(direct_ip)], None, False
            return True, "Direct IP verified", [str(direct_ip)], str(direct_ip), False

        # Resolve DNS addresses
        resolved_ips: Set[str] = set()
        try:
            if custom_resolver:
                addr_info = custom_resolver(clean_host, port)
            else:
                addr_info = socket.getaddrinfo(
                    clean_host,
                    port,
                    socket.AF_UNSPEC,
                    socket.SOCK_STREAM
                )
            for item in addr_info:
                sockaddr = item[4]
                ip_str = sockaddr[0]
                norm = normalize_ip(ip_str)
                if norm:
                    resolved_ips.add(str(norm))
        except (socket.gaierror, socket.herror) as e:
            return False, f"DNS resolution failed for '{clean_host}': {str(e)}", [], None, False
        except Exception as e:
            return False, f"DNS resolution error: {str(e)}", [], None, False

        if not resolved_ips:
            return False, f"No DNS records resolved for host '{clean_host}'", [], None, False

        sorted_ips = sorted(list(resolved_ips))
        has_private = False
        has_public = False

        # Detect mixed public and private addresses (DNS Rebinding)
        for ip_str in sorted_ips:
            ip_obj = normalize_ip(ip_str)
            if ip_obj:
                if ip_obj.is_private or ip_obj.is_loopback:
                    has_private = True
                else:
                    has_public = True

        if has_private and has_public and not self.allow_internal:
            return (
                False,
                f"DNS Rebinding anomaly detected: host '{clean_host}' resolved to both public and private addresses",
                sorted_ips,
                None,
                True
            )

        # Inspect each resolved IP for forbidden spaces
        for ip_str in sorted_ips:
            ip_obj = normalize_ip(ip_str)
            if not ip_obj:
                continue

            if ip_str in METADATA_IPS:
                return (
                    False,
                    f"Host '{clean_host}' resolved to forbidden cloud metadata IP {ip_str}",
                    sorted_ips,
                    None,
                    True
                )

            is_prohib, reason = is_prohibited_ip(ip_obj, self.allow_internal)
            if is_prohib:
                return (
                    False,
                    f"Host '{clean_host}' resolved to forbidden IP {ip_str}: {reason}",
                    sorted_ips,
                    None,
                    True
                )

        # Pin the primary IP
        pinned_ip = self._pinned_hosts.get(clean_host)
        if not pinned_ip or pinned_ip not in resolved_ips:
            pinned_ip = sorted_ips[0]
            self._pinned_hosts[clean_host] = pinned_ip

        return True, "All resolved DNS records verified secure", sorted_ips, pinned_ip, rebinding_detected
