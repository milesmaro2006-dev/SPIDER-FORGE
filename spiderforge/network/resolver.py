"""Secure DNS Resolver protecting against DNS Rebinding & SSRF."""

import asyncio
import ipaddress
import socket

from spiderforge.network.exceptions import (
    DNSResolutionError,
    InvalidSchemeError,
)
from spiderforge.network.policies import DestinationSafetyPolicy


class SafeResolver:
    """Performs pre-flight DNS resolution and destination policy enforcement."""

    def __init__(self, safety_policy: DestinationSafetyPolicy) -> None:
        self.safety_policy = safety_policy

    async def resolve_and_validate(
        self, host: str, port: int
    ) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        # Direct IP?
        try:
            direct_ip = ipaddress.ip_address(host)
            self.safety_policy.validate_destination_ip(direct_ip)
            self.safety_policy.validate_port(port, resolved_ip=direct_ip)
            return [direct_ip]
        except ValueError:
            pass

        try:
            addr_info = await asyncio.to_thread(
                socket.getaddrinfo,
                host,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as err:
            raise DNSResolutionError(
                f"Failed to resolve '{host}': {err}"
            ) from err

        if not addr_info:
            raise DNSResolutionError(f"DNS returned no records for '{host}'")

        resolved: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for item in addr_info:
            sockaddr = item[4]
            ip_str = sockaddr[0]
            parsed_ip = ipaddress.ip_address(ip_str)
            self.safety_policy.validate_destination_ip(parsed_ip)
            resolved.append(parsed_ip)

        if not resolved:
            raise DNSResolutionError(f"All DNS records blocked for '{host}'")

        # Port validation against the first resolved IP
        self.safety_policy.validate_port(port, resolved_ip=resolved[0])

        seen: set = set()
        unique: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for ip in resolved:
            if str(ip) not in seen:
                seen.add(str(ip))
                unique.append(ip)
        return unique

    def validate_url_structure(self, url: str) -> tuple[str, str, int]:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        scheme = parsed.scheme.lower()

        if scheme not in self.safety_policy.allowed_schemes:
            raise InvalidSchemeError(
                f"Scheme '{scheme}' is prohibited. Only "
                f"{sorted(self.safety_policy.allowed_schemes)} allowed."
            )

        if not parsed.hostname:
            raise InvalidSchemeError(f"Invalid URL: missing hostname in '{url}'")

        port = parsed.port or (443 if scheme == "https" else 80)

        # Port check is deferred to resolve_and_validate (needs resolved IP
        # for the allow_any_port_for_local carve-out).
        return scheme, parsed.hostname, port
