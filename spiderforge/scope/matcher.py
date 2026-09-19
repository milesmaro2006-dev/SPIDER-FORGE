from __future__ import annotations

import ipaddress


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def match_pattern(host: str, pattern: str) -> bool:
    """Match a hostname against a scope pattern.

    Patterns:
      - "example.com"   -> apex + any subdomain
      - "*.example.com" -> subdomains only, NOT apex
      - "10.0.0.0/8"    -> CIDR
      - "192.168.1.5"   -> exact IP
    """
    pattern = pattern.strip().lower()
    host = host.lower()

    if not pattern:
        return False

    if "/" in pattern:
        try:
            net = ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return False
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return ip in net

    if _is_ip(pattern):
        return host == pattern

    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host.endswith("." + suffix) and host != suffix

    if host == pattern:
        return True
    return host.endswith("." + pattern)
