"""DNS-over-HTTPS resolver for privacy-preserving hostname resolution."""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field

logger = logging.getLogger("spiderforge.anonymity.doh")


class DoHUnavailableError(RuntimeError):
    """Raised when DoH cannot be performed."""


@dataclass
class DoHResult:
    hostname: str
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    source_url: str = ""

    def all_ips(self) -> list[str]:
        return list(self.ipv4) + list(self.ipv6)


class DoHResolver:
    """Async DNS-over-HTTPS resolver."""

    def __init__(self, endpoint: str, *, timeout: float = 5.0) -> None:
        self.endpoint = (endpoint or "").strip()
        self.timeout = float(timeout)
        if not self.endpoint:
            raise DoHUnavailableError("empty DoH endpoint URL")

    async def resolve(self, hostname: str) -> DoHResult:
        if not hostname:
            raise DoHUnavailableError("empty hostname")

        try:
            ipaddress.ip_address(hostname)
            return DoHResult(
                hostname=hostname,
                ipv4=[hostname] if "." in hostname else [],
                ipv6=[hostname] if ":" in hostname else [],
                source_url=self.endpoint,
            )
        except ValueError:
            pass

        try:
            import dns.asyncquery
            import dns.message
        except ImportError as exc:
            raise DoHUnavailableError(
                f"dnspython is required for DoH: {exc}"
            ) from exc

        result = DoHResult(hostname=hostname, source_url=self.endpoint)

        for rdtype_name, target_list in (("A", result.ipv4), ("AAAA", result.ipv6)):
            try:
                query = dns.message.make_query(hostname, rdtype_name)
                response = await dns.asyncquery.https(
                    query, self.endpoint, timeout=self.timeout,
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("DoH %s query for %s failed: %s", rdtype_name, hostname, exc)
                continue

            for answer in response.answer:
                for rdata in answer:
                    addr = getattr(rdata, "address", None)
                    if addr:
                        target_list.append(str(addr))

        if not result.ipv4 and not result.ipv6:
            raise DoHUnavailableError(
                f"DoH returned no records for '{hostname}' via {self.endpoint}"
            )

        return result


def cross_check(
    hostname: str,
    doh_ips: list[str],
    system_ips: list[str],
    *,
    min_overlap: int = 1,
) -> tuple[bool, str]:
    """Return ``(ok, reason)`` comparing DoH and system resolver answers."""
    if not doh_ips:
        return True, "no DoH records to compare"
    if not system_ips:
        return True, "no system records to compare"

    doh_set = {str(ip) for ip in doh_ips}
    sys_set = {str(ip) for ip in system_ips}

    overlap = doh_set & sys_set
    if len(overlap) >= min_overlap:
        return True, f"matched {len(overlap)} record(s)"

    return False, (
        f"DNS mismatch for {hostname}: "
        f"DoH={sorted(doh_set)} vs system={sorted(sys_set)}"
    )
