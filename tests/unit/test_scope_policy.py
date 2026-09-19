"""ScopePolicy tests — wildcards, CIDR, exclusions, IPv6."""

from __future__ import annotations

import ipaddress

import pytest

from spiderforge.network.policies import ScopePolicy


# ═══════════════════════════════════════════════════════════════
#  Exact hostname
# ═══════════════════════════════════════════════════════════════

def test_exact_host_match(basic_scope):
    assert basic_scope.is_in_scope("example.com") is True


def test_exact_host_case_insensitive(basic_scope):
    assert basic_scope.is_in_scope("EXAMPLE.COM") is True
    assert basic_scope.is_in_scope("Example.Com") is True


def test_wrong_host_rejected(basic_scope):
    assert basic_scope.is_in_scope("attacker.com") is False
    assert basic_scope.is_in_scope("example.org") is False


# ═══════════════════════════════════════════════════════════════
#  Wildcard semantics (must match spiderforge.scope.matcher)
# ═══════════════════════════════════════════════════════════════

def test_wildcard_does_not_match_apex():
    """'*.example.com' should NOT match 'example.com'."""
    scope = ScopePolicy(
        target_host="other.com",
        allowed_domains={"*.example.com"},
    )
    assert scope.is_in_scope("example.com") is False


def test_wildcard_matches_subdomain():
    scope = ScopePolicy(
        target_host="other.com",
        allowed_domains={"*.example.com"},
    )
    assert scope.is_in_scope("api.example.com") is True
    assert scope.is_in_scope("deep.sub.example.com") is True


def test_apex_pattern_matches_subdomains():
    """'example.com' pattern matches apex AND subdomains."""
    scope = ScopePolicy(
        target_host="example.com",
        allowed_domains={"example.com"},
    )
    assert scope.is_in_scope("example.com") is True
    assert scope.is_in_scope("api.example.com") is True
    assert scope.is_in_scope("deep.sub.example.com") is True


def test_apex_pattern_rejects_evil_suffix():
    """'example.com' must NOT match 'example.com.attacker.net'."""
    scope = ScopePolicy(
        target_host="example.com",
        allowed_domains={"example.com"},
    )
    assert scope.is_in_scope("example.com.attacker.net") is False


# ═══════════════════════════════════════════════════════════════
#  Exclusions always win
# ═══════════════════════════════════════════════════════════════

def test_exclusion_overrides_inclusion():
    scope = ScopePolicy(
        target_host="example.com",
        allowed_domains={"example.com", "*.example.com"},
        excluded_hosts={"admin.example.com"},
    )
    assert scope.is_in_scope("example.com") is True
    assert scope.is_in_scope("api.example.com") is True
    assert scope.is_in_scope("admin.example.com") is False


# ═══════════════════════════════════════════════════════════════
#  CIDR / IP-based scopes
# ═══════════════════════════════════════════════════════════════

def test_cidr_match_via_resolved_ip():
    scope = ScopePolicy(
        target_host="nothing.example",
        allowed_domains=set(),
        allowed_subnets=[
            ipaddress.ip_network("203.0.113.0/24"),
        ],
    )
    resolved = ipaddress.ip_address("203.0.113.42")
    assert scope.is_in_scope("some.host", resolved_ip=resolved) is True


def test_cidr_miss_via_resolved_ip():
    scope = ScopePolicy(
        target_host="nothing.example",
        allowed_domains=set(),
        allowed_subnets=[ipaddress.ip_network("203.0.113.0/24")],
    )
    resolved = ipaddress.ip_address("198.51.100.5")
    assert scope.is_in_scope("some.host", resolved_ip=resolved) is False


def test_exact_ip_pattern():
    scope = ScopePolicy(
        target_host="other.example",
        allowed_domains={"192.0.2.1"},
    )
    assert scope.is_in_scope("192.0.2.1") is True
    assert scope.is_in_scope("192.0.2.2") is False


# ═══════════════════════════════════════════════════════════════
#  IPv6
# ═══════════════════════════════════════════════════════════════

def test_ipv6_cidr_match():
    scope = ScopePolicy(
        target_host="x.example",
        allowed_domains=set(),
        allowed_subnets=[ipaddress.ip_network("2001:db8::/32")],
    )
    resolved = ipaddress.ip_address("2001:db8::1")
    assert scope.is_in_scope("x.example", resolved_ip=resolved) is True


# ═══════════════════════════════════════════════════════════════
#  Backward-compat alias
# ═══════════════════════════════════════════════════════════════

def test_is_allowed_alias(basic_scope):
    assert basic_scope.is_allowed("example.com") is True
    assert basic_scope.is_allowed("attacker.com") is False