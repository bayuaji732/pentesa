"""Comprehensive unit tests for Scope Enforcement Engine (Layer 1 & Layer 2)."""

import uuid
from datetime import datetime, timedelta, timezone
import pytest

from packages.schemas.scope import ScopeRuleType, ScopeTargetType
from services.scope_engine.dns_pinning import DnsPinningValidator
from services.scope_engine.service import ScopeEnforcementService
from services.scope_engine.validator import ScopeValidator, compile_domain_regex, parse_port_range


def test_parse_port_range():
    """Verify port parsing for single ports, lists, and ranges."""
    assert parse_port_range(None) == {80, 443}
    assert parse_port_range("") == {80, 443}
    assert parse_port_range("80,443") == {80, 443}
    assert parse_port_range("8080") == {8080}
    assert parse_port_range("8000-8003") == {8000, 8001, 8002, 8003}
    assert parse_port_range("80, 443, 8080-8082") == {80, 443, 8080, 8081, 8082}


def test_domain_regex_compilation():
    """Verify mathematical dot-boundary regex prevents lookalike attacks."""
    # Wildcard *.example.com
    rgx = compile_domain_regex("*.example.com")
    assert rgx.match("example.com")
    assert rgx.match("api.example.com")
    assert rgx.match("sub.api.example.com")

    # Anti-bypass / lookalike rejections
    assert not rgx.match("evil-example.com")
    assert not rgx.match("notexample.com")
    assert not rgx.match("example.com.attacker.com")
    assert not rgx.match("attacker.com")

    # Exact domain
    rgx_exact = compile_domain_regex("api.example.com")
    assert rgx_exact.match("api.example.com")
    assert not rgx_exact.match("evil.api.example.com")
    assert not rgx_exact.match("example.com")


def test_scope_validator_domains_and_ports():
    """Verify Layer 1 domain and port validation."""
    rules = [
        {
            "id": uuid.uuid4(),
            "rule_type": ScopeRuleType.DOMAIN_WILDCARD,
            "target_type": ScopeTargetType.IN_SCOPE,
            "pattern": "*.secure.corp",
            "port_range": "80,443,8443",
            "protocol": "https,http"
        }
    ]
    validator = ScopeValidator(rules, allow_internal=False)

    # In scope targets
    r1 = validator.validate_url("https://secure.corp")
    assert r1.is_in_scope is True
    assert r1.status == "ALLOWED"

    r2 = validator.validate_url("https://api.secure.corp:8443/v1/users")
    assert r2.is_in_scope is True
    assert r2.status == "ALLOWED"

    # Out of scope domain
    r3 = validator.validate_url("https://evil-secure.corp")
    assert r3.is_in_scope is False
    assert r3.status == "BLOCKED"

    # Out of scope port
    r4 = validator.validate_url("https://secure.corp:8080")
    assert r4.is_in_scope is False
    assert r4.status == "BLOCKED"
    assert "not in authorized ports" in r4.reason


def test_scope_validator_protocol_restrictions():
    """Verify unsafe protocols are rejected."""
    rules = [
        {
            "id": uuid.uuid4(),
            "rule_type": ScopeRuleType.DOMAIN_WILDCARD,
            "target_type": ScopeTargetType.IN_SCOPE,
            "pattern": "*.secure.corp"
        }
    ]
    validator = ScopeValidator(rules)

    r_file = validator.validate_url("file:///etc/passwd")
    assert r_file.is_in_scope is False
    assert "Protocol 'file' is forbidden" in r_file.reason

    r_gopher = validator.validate_url("gopher://secure.corp:70/")
    assert r_gopher.is_in_scope is False
    assert "forbidden" in r_gopher.reason


def test_scope_validator_path_exclusions_and_traversal():
    """Verify path exclusions and anti-traversal normalization."""
    rules = [
        {
            "id": uuid.uuid4(),
            "rule_type": ScopeRuleType.DOMAIN_WILDCARD,
            "target_type": ScopeTargetType.IN_SCOPE,
            "pattern": "*.target.com"
        },
        {
            "id": uuid.uuid4(),
            "rule_type": ScopeRuleType.EXCLUDED_PATH,
            "target_type": ScopeTargetType.OUT_OF_SCOPE,
            "pattern": "/logout"
        },
        {
            "id": uuid.uuid4(),
            "rule_type": ScopeRuleType.EXCLUDED_PATH,
            "target_type": ScopeTargetType.OUT_OF_SCOPE,
            "pattern": "/admin/delete"
        }
    ]
    validator = ScopeValidator(rules)

    # Allowed endpoint
    r_ok = validator.validate_url("https://target.com/api/v1/profile")
    assert r_ok.is_in_scope is True

    # Excluded path
    r_logout = validator.validate_url("https://target.com/logout")
    assert r_logout.is_in_scope is False
    assert r_logout.status == "EXCLUDED"

    # Traversal bypass attempt (/public/../logout)
    r_trav = validator.validate_url("https://target.com/public/../logout")
    assert r_trav.is_in_scope is False
    assert r_trav.status == "EXCLUDED"


def test_scope_validator_cidr_and_ip_normalization():
    """Verify CIDR containment and IPv4-mapped IPv6 normalization."""
    rules = [
        {
            "id": uuid.uuid4(),
            "rule_type": ScopeRuleType.IP_CIDR,
            "target_type": ScopeTargetType.IN_SCOPE,
            "pattern": "93.184.216.0/24",
            "port_range": "443"
        }
    ]
    validator = ScopeValidator(rules)

    # IP in CIDR
    r1 = validator.validate_url("https://93.184.216.25")
    assert r1.is_in_scope is True

    # IP outside CIDR
    r2 = validator.validate_url("https://93.184.217.1")
    assert r2.is_in_scope is False

    # IPv4-mapped IPv6 address
    r3 = validator.validate_url("https://[::ffff:93.184.216.25]")
    assert r3.is_in_scope is True


def test_cloud_metadata_strict_blocking():
    """Verify cloud metadata IPs and hosts are blocked unconditionally."""
    rules = [
        {
            "id": uuid.uuid4(),
            "rule_type": ScopeRuleType.DOMAIN_WILDCARD,
            "target_type": ScopeTargetType.IN_SCOPE,
            "pattern": "*"
        }
    ]
    # Even if internal networks are authorized!
    validator = ScopeValidator(rules, allow_internal=True)

    # AWS/Azure/GCP 169.254.169.254
    r_meta = validator.validate_url("http://169.254.169.254/latest/meta-data/")
    assert r_meta.is_in_scope is False
    assert r_meta.status == "PRIVATE_NETWORK_BLOCKED"
    assert "Metadata Service" in r_meta.reason

    # GCP hostname metadata.google.internal
    r_gcp = validator.validate_url("http://metadata.google.internal/computeMetadata/v1/")
    assert r_gcp.is_in_scope is False
    assert r_gcp.status == "PRIVATE_NETWORK_BLOCKED"


def test_private_rfc1918_blocking():
    """Verify RFC 1918 private IPs are blocked unless allow_internal=True."""
    rules = [
        {
            "id": uuid.uuid4(),
            "rule_type": ScopeRuleType.IP_CIDR,
            "target_type": ScopeTargetType.IN_SCOPE,
            "pattern": "10.0.0.0/8"
        }
    ]
    # Internal networks not allowed
    val_strict = ScopeValidator(rules, allow_internal=False)
    r1 = val_strict.validate_url("http://10.0.0.5")
    assert r1.is_in_scope is False
    assert r1.status == "PRIVATE_NETWORK_BLOCKED"

    # Internal networks explicitly allowed
    val_internal = ScopeValidator(rules, allow_internal=True)
    r2 = val_internal.validate_url("http://10.0.0.5:80")
    assert r2.is_in_scope is True
    assert r2.status == "ALLOWED"


def test_dns_rebinding_detection():
    """Verify Layer 2 detects DNS rebinding when host resolves to both public and private IPs."""
    validator = DnsPinningValidator(allow_internal=False)

    # Simulated DNS resolver returning mixed public & private IPs
    def mock_mixed_resolver(host, port):
        return [
            (None, None, None, None, ("93.184.216.34", port)),
            (None, None, None, None, ("127.0.0.1", port)),
        ]

    is_valid, reason, ips, pinned, rebinding = validator.resolve_and_verify(
        "rebind.attacker.com",
        port=80,
        custom_resolver=mock_mixed_resolver
    )
    assert is_valid is False
    assert rebinding is True
    assert "DNS Rebinding anomaly detected" in reason

    def mock_clean_resolver(host, port):
        return [(None, None, None, None, ("93.184.216.34", port))]

    ok, ok_reason, ok_ips, ok_pinned, ok_rebinding = validator.resolve_and_verify(
        "example.com",
        port=443,
        custom_resolver=mock_clean_resolver,
    )
    assert ok is True
    assert ok_rebinding is False
    assert ok_pinned == "93.184.216.34"


def test_scope_service_project_authorization_window():
    """Verify high-level scope service blocks tests on expired or inactive projects."""
    service = ScopeEnforcementService()
    now = datetime.now(timezone.utc)

    # Expired project
    class ExpiredProject:
        status = "ACTIVE"
        authorization_start = now - timedelta(days=10)
        authorization_end = now - timedelta(days=1)
        allow_internal_networks = False
        scope_rules = []

    res_expired = service.check_target(ExpiredProject(), "https://example.com")
    assert res_expired.is_in_scope is False
    assert "expired" in res_expired.reason

    # Archived project
    class ArchivedProject:
        status = "ARCHIVED"
        authorization_start = now - timedelta(days=1)
        authorization_end = now + timedelta(days=10)
        allow_internal_networks = False
        scope_rules = []

    res_archived = service.check_target(ArchivedProject(), "https://example.com")
    assert res_archived.is_in_scope is False
    assert "ARCHIVED" in res_archived.reason


def test_scope_validator_multiple_rules_port_aggregation():
    """Verify additional IN_SCOPE port rules are not shadowed by earlier default 80/443 rules."""
    rules = [
        {
            "id": uuid.uuid4(),
            "rule_type": ScopeRuleType.EXACT_DOMAIN,
            "target_type": ScopeTargetType.IN_SCOPE,
            "pattern": "127.0.0.1",
            "port_range": None,  # defaults to {80, 443}
        },
        {
            "id": uuid.uuid4(),
            "rule_type": ScopeRuleType.EXACT_DOMAIN,
            "target_type": ScopeTargetType.IN_SCOPE,
            "pattern": "127.0.0.1",
            "port_range": "9000",
        },
        {
            "id": uuid.uuid4(),
            "rule_type": ScopeRuleType.IP_CIDR,
            "target_type": ScopeTargetType.IN_SCOPE,
            "pattern": "10.0.0.0/8",
            "port_range": None,
        },
        {
            "id": uuid.uuid4(),
            "rule_type": ScopeRuleType.IP_CIDR,
            "target_type": ScopeTargetType.IN_SCOPE,
            "pattern": "10.0.0.0/8",
            "port_range": "3000",
        },
    ]
    validator = ScopeValidator(rules, allow_internal=True)

    r_9000 = validator.validate_url("http://127.0.0.1:9000/products")
    assert r_9000.is_in_scope is True
    assert r_9000.status == "ALLOWED"

    r_3000 = validator.validate_url("http://10.0.0.5:3000/")
    assert r_3000.is_in_scope is True
    assert r_3000.status == "ALLOWED"

    r_bad = validator.validate_url("http://127.0.0.1:9999/")
    assert r_bad.is_in_scope is False
    assert r_bad.status == "BLOCKED"
    assert "9000" in r_bad.reason
