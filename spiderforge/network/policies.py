"""Network, Scope, and Destination Safety Policies."""

import ipaddress
from dataclasses import dataclass, field

# ═══════════════════════════════════════════════════════════════
#  Scope Policy
# ═══════════════════════════════════════════════════════════════

@dataclass
class ScopePolicy:
    target_host: str
    allowed_domains: set[str] = field(default_factory=set)
    allowed_subnets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default_factory=list
    )
    excluded_hosts: set[str] = field(default_factory=set)
    allow_all_hosts: bool = False

    def _matches_pattern(self, host: str, pattern: str) -> bool:
        pattern = pattern.strip().lower()
        host = host.lower()
        if not pattern:
            return False

        if "/" in pattern:
            try:
                net = ipaddress.ip_network(pattern, strict=False)
                ip = ipaddress.ip_address(host)
            except ValueError:
                return False
            return ip in net

        try:
            ipaddress.ip_address(pattern)
            return host == pattern
        except ValueError:
            pass

        if pattern.startswith("*."):
            suffix = pattern[2:]
            return host.endswith("." + suffix) and host != suffix

        return host == pattern or host.endswith("." + pattern)

    def is_in_scope(
        self,
        host: str,
        resolved_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None,
    ) -> bool:
        if self.allow_all_hosts:
            return True

        host_lower = host.lower().strip()

        if host_lower in {h.lower() for h in self.excluded_hosts}:
            return False

        allowed = False
        if self.allowed_domains:
            allowed = any(
                self._matches_pattern(host_lower, p) for p in self.allowed_domains
            )
        else:
            allowed = self._matches_pattern(host_lower, self.target_host)

        if not allowed and resolved_ip is not None:
            for subnet in self.allowed_subnets:
                if resolved_ip in subnet:
                    allowed = True
                    break

        return allowed

    def is_allowed(self, host: str, resolved_ip=None) -> bool:
        return self.is_in_scope(host, resolved_ip=resolved_ip)


# ═══════════════════════════════════════════════════════════════
#  Destination Safety Policy (SSRF Protection)
# ═══════════════════════════════════════════════════════════════

@dataclass
class DestinationSafetyPolicy:
    allow_private_targets: bool = False
    allowed_schemes: set[str] = field(default_factory=lambda: {"http", "https"})
    allowed_ports: set[int] = field(default_factory=lambda: {80, 443})
    extra_allowed_ports: set[int] = field(default_factory=set)

    # Local mock servers (pytest-httpserver) use random ports.
    # This flag ONLY relaxes PORT checks for loopback/private IPs.
    # It must NEVER skip IP-family SSRF checks.
    allow_any_port_for_local: bool = True

    BLOCKED_IPS: set[str] = field(default_factory=lambda: {
        "169.254.169.254",
        "100.100.100.200",
        "0.0.0.0",
        "::",
    })

    def validate_port(
        self,
        port: int,
        resolved_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None,
    ) -> None:
        """Raise SSRFBlockedError if the port is not permitted."""
        from spiderforge.network.exceptions import SSRFBlockedError

        # 1) Standard permitted ports
        if port in self.allowed_ports or port in self.extra_allowed_ports:
            return

        # 2) Local-test carve-out — ONLY when we actually know the IP
        #    AND it is loopback/private/link-local.
        if resolved_ip is not None and (
            self.allow_any_port_for_local or self.allow_private_targets
        ):
            ip = resolved_ip
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
                ip = ip.ipv4_mapped
            if ip.is_loopback or ip.is_private or ip.is_link_local:
                return

        raise SSRFBlockedError(
            f"Port {port} is not permitted by DestinationSafetyPolicy."
        )

    def validate_destination_ip(
        self,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> None:
        from spiderforge.network.exceptions import SSRFBlockedError

        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped

        ip_str = str(ip)

        if ip_str in self.BLOCKED_IPS:
            raise SSRFBlockedError(
                f"Connection blocked to sensitive cloud metadata address: {ip_str}"
            )

        if ip_str in {"169.254.169.254", "fd00:ec2::254"}:
            raise SSRFBlockedError(f"Cloud metadata endpoint blocked: {ip_str}")

        # allow_any_port_for_local must NOT be used here.
        # Only an explicit allow_private_targets relaxes RFC1918/loopback blocks.
        if self.allow_private_targets:
            if ip.is_multicast:
                raise SSRFBlockedError(f"SSRF: multicast blocked: {ip_str}")
            if ip.is_unspecified:
                raise SSRFBlockedError(f"SSRF: unspecified blocked: {ip_str}")
            return

        if ip.is_loopback:
            raise SSRFBlockedError(f"SSRF: loopback blocked: {ip_str}")
        if ip.is_private:
            raise SSRFBlockedError(f"SSRF: private (RFC1918) blocked: {ip_str}")
        if ip.is_link_local:
            raise SSRFBlockedError(f"SSRF: link-local blocked: {ip_str}")
        if ip.is_multicast:
            raise SSRFBlockedError(f"SSRF: multicast blocked: {ip_str}")
        if ip.is_reserved:
            raise SSRFBlockedError(f"SSRF: reserved blocked: {ip_str}")
        if ip.is_unspecified:
            raise SSRFBlockedError(f"SSRF: unspecified blocked: {ip_str}")


# ═══════════════════════════════════════════════════════════════
#  Network Policy (aggregate)
# ═══════════════════════════════════════════════════════════════

@dataclass
class NetworkPolicy:
    scope_policy: ScopePolicy
    destination_policy: DestinationSafetyPolicy = field(
        default_factory=DestinationSafetyPolicy
    )

    verify_tls: bool = True
    connect_timeout: float = 5.0
    read_timeout: float = 10.0

    max_response_bytes: int = 5 * 1024 * 1024
    max_evidence_bytes: int = 64 * 1024
    max_redirects: int = 5
    max_concurrency: int = 10
    rate_limit_rps: float = 20.0

    trust_env_proxies: bool = False
