from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.resolver

from spiderforge.utils.logging import get_logger

log = get_logger("recon.dns")

RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")


@dataclass
class DnsRecord:
    type: str
    value: str
    ttl: int | None = None


@dataclass
class DnsResult:
    hostname: str
    records: dict[str, list[DnsRecord]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    def flat(self) -> list[dict]:
        out: list[dict] = []
        for rtype, items in self.records.items():
            for r in items:
                out.append({"type": rtype, "value": r.value, "ttl": r.ttl})
        return out


async def resolve(hostname: str, timeout: float = 5.0) -> DnsResult:
    """Resolve common DNS record types concurrently.

    Never raises: individual record-type failures are captured in ``errors``.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    result = DnsResult(hostname=hostname)

    async def _query(rtype: str) -> None:
        try:
            answer = await resolver.resolve(hostname, rtype)
            items: list[DnsRecord] = []
            ttl = getattr(answer.rrset, "ttl", None)
            for rr in answer:
                items.append(DnsRecord(type=rtype, value=str(rr).strip(), ttl=ttl))
            result.records[rtype] = items
        except dns.resolver.NoAnswer:
            result.records[rtype] = []
        except dns.resolver.NXDOMAIN:
            result.errors[rtype] = "NXDOMAIN"
        except dns.exception.Timeout:
            result.errors[rtype] = "timeout"
        except Exception as exc:  # noqa: BLE001
            result.errors[rtype] = f"{type(exc).__name__}: {exc}"

    await asyncio.gather(*(_query(t) for t in RECORD_TYPES))
    return result
