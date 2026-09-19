"""SSRF protection tests — every private/loopback range must be blocked."""

from __future__ import annotations

import ipaddress

import pytest

from spiderforge.network.exceptions import SSRFBlockedError
from spiderforge.network.policies import DestinationSafetyPolicy


@pytest.fixture
def policy():
    return DestinationSafetyPolicy(allow_private_targets=False)


@pytest.fixture
def permissive_policy():
    return DestinationSafetyPolicy(allow_private_targets=True)


# ═══════════════════════════════════════════════════════════════
#  Blocked: loopback
# ═══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("ip", [
    "127.0.0.1",
    "127.1.1.1",
    "127.255.255.255",
    "::1",                      # IPv6 loopback
    "::ffff:127.0.0.1",         # IPv4-mapped IPv6 loopback
])
def test_loopback_blocked(policy, ip):
    with pytest.raises(SSRFBlockedError):
        policy.validate_destination_ip(ipaddress.ip_address(ip))


# ═══════════════════════════════════════════════════════════════
#  Blocked: RFC1918 private IPv4
# ═══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("ip", [
    "10.0.0.1",
    "10.255.255.254",
    "172.16.0.1",
    "172.31.255.254",
    "192.168.0.1",
    "192.168.255.254",
])
def test_rfc1918_blocked(policy, ip):
    with pytest.raises(SSRFBlockedError):
        policy.validate_destination_ip(ipaddress.ip_address(ip))


# ═══════════════════════════════════════════════════════════════
#  Blocked: link-local (169.254.0.0/16) — critical for cloud metadata
# ═══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("ip", [
    "169.254.0.1",
    "169.254.169.254",     # AWS / GCP / Azure metadata
    "169.254.255.254",
])
def test_link_local_blocked(policy, ip):
    with pytest.raises(SSRFBlockedError):
        policy.validate_destination_ip(ipaddress.ip_address(ip))


# ═══════════════════════════════════════════════════════════════
#  Blocked: cloud metadata endpoints
# ═══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("ip", [
    "169.254.169.254",     # AWS / GCP / Azure
    "100.100.100.200",     # Alibaba Cloud
])
def test_cloud_metadata_blocked(policy, ip):
    with pytest.raises(SSRFBlockedError):
        policy.validate_destination_ip(ipaddress.ip_address(ip))


# ═══════════════════════════════════════════════════════════════
#  Blocked: unspecified / multicast / reserved
# ═══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("ip", [
    "0.0.0.0",
    "::",
    "224.0.0.1",           # multicast IPv4
    "ff02::1",             # multicast IPv6
    "240.0.0.1",           # reserved
])
def test_special_ranges_blocked(policy, ip):
    with pytest.raises(SSRFBlockedError):
        policy.validate_destination_ip(ipaddress.ip_address(ip))


# ═══════════════════════════════════════════════════════════════
#  Allowed: public IPs
# ═══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("ip", [
    "8.8.8.8",              # Google DNS
    "1.1.1.1",              # Cloudflare DNS
    "93.184.216.34",        # example.com
    "2001:4860:4860::8888", # Google DNS v6
])
def test_public_ips_allowed(policy, ip):
    # Should NOT raise
    policy.validate_destination_ip(ipaddress.ip_address(ip))


# ═══════════════════════════════════════════════════════════════
#  Permissive mode (lab environments)
# ═══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("ip", [
    "127.0.0.1",
    "10.0.0.1",
    "192.168.1.1",
])
def test_private_ips_allowed_when_permitted(permissive_policy, ip):
    # Should NOT raise
    permissive_policy.validate_destination_ip(ipaddress.ip_address(ip))


def test_metadata_still_blocked_in_permissive_mode(permissive_policy):
    """Even with allow_private_targets=True, cloud metadata stays blocked."""
    with pytest.raises(SSRFBlockedError):
        permissive_policy.validate_destination_ip(
            ipaddress.ip_address("169.254.169.254")
        )


def test_multicast_still_blocked_in_permissive_mode(permissive_policy):
    with pytest.raises(SSRFBlockedError):
        permissive_policy.validate_destination_ip(ipaddress.ip_address("224.0.0.1"))