"""Recon runner — uses SafeHttpClient exclusively."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit

from spiderforge.core.events import Event, EventBus, EventType
from spiderforge.network.client import SafeHttpClient
from spiderforge.network.policies import (
    DestinationSafetyPolicy,
    NetworkPolicy,
    ScopePolicy,
)
from spiderforge.recon import dns as dns_mod
from spiderforge.recon import http_probe, robots, sitemap, technologies
from spiderforge.scope.validator import ScopeValidator
from spiderforge.utils.logging import get_logger
from spiderforge.utils.urls import normalize_url

log = get_logger("recon.runner")


@dataclass
class ReconResult:
    target: str
    final_url: str | None = None
    dns: dict = field(default_factory=dict)
    http: dict = field(default_factory=dict)
    technologies: list[dict] = field(default_factory=list)
    robots: dict = field(default_factory=dict)
    sitemaps: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _policy_from_validator(
    scope: ScopeValidator,
    *,
    target: str,
    timeout: float,
    verify_tls: bool = True,
) -> NetworkPolicy:
    """Best-effort conversion from ScopeValidator → NetworkPolicy.

    Used only when the caller does not provide a SafeHttpClient.
    """
    host = "localhost"
    allowed: set[str] = set()
    allow_private = False
    try:
        cfg = scope.config
        host = (cfg.project.name or host).strip() or host
        allowed = set(cfg.include or [])
        allow_private = bool(cfg.network.allow_private_ips)
    except Exception:
        pass

    if not allowed:
        try:
            host = (urlsplit(target).hostname or host).lower()
        except Exception:
            pass
        allowed = {host, f"*.{host}"}

    sp = ScopePolicy(target_host=host, allowed_domains=allowed)
    dp = DestinationSafetyPolicy(allow_private_targets=allow_private)
    return NetworkPolicy(
        scope_policy=sp,
        destination_policy=dp,
        verify_tls=verify_tls,
        connect_timeout=timeout,
        read_timeout=timeout,
    )


async def run(
    target: str,
    *,
    scope: ScopeValidator,
    client: SafeHttpClient | None = None,
    bus: EventBus | None = None,
    timeout: float = 20.0,
    user_agent: str = "SpiderForge/0.1",
    verify_tls: bool = True,
    fetch_sitemaps: bool = True,
    max_sitemaps: int = 5,
) -> ReconResult:
    """Run a full recon pass.

    If ``client`` is not provided, a SafeHttpClient is created internally
    with a policy derived from ``scope``. This preserves backward
    compatibility with older call sites while keeping every outbound
    request behind the safe network layer.
    """
    if client is not None:
        return await _run_impl(
            target,
            scope=scope,
            client=client,
            bus=bus,
            timeout=timeout,
            user_agent=user_agent,
            fetch_sitemaps=fetch_sitemaps,
            max_sitemaps=max_sitemaps,
        )

    policy = _policy_from_validator(
        scope,
        target=target,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    async with SafeHttpClient(policy=policy) as owned_client:
        return await _run_impl(
            target,
            scope=scope,
            client=owned_client,
            bus=bus,
            timeout=timeout,
            user_agent=user_agent,
            fetch_sitemaps=fetch_sitemaps,
            max_sitemaps=max_sitemaps,
        )


async def _run_impl(
    target: str,
    *,
    scope: ScopeValidator,
    client: SafeHttpClient,
    bus: EventBus | None,
    timeout: float,
    user_agent: str,
    fetch_sitemaps: bool,
    max_sitemaps: int,
) -> ReconResult:
    target = normalize_url(target)
    result = ReconResult(target=target)

    if not scope.is_allowed(target):
        result.errors.append(f"target out of scope: {target}")
        if bus:
            await bus.emit(Event(EventType.OUT_OF_SCOPE, message=target))
        return result

    parts = urlsplit(target)
    host = parts.hostname or ""
    origin = f"{parts.scheme}://{parts.netloc}"

    if bus:
        await bus.emit(Event(EventType.RECON_DNS, message=f"resolving {host}"))
    try:
        dns_result = await dns_mod.resolve(host, timeout=min(timeout, 10.0))
        result.dns = {
            "hostname": dns_result.hostname,
            "records": dns_result.flat(),
            "errors": dns_result.errors,
        }
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"dns: {exc}")
        result.dns = {"error": str(exc)}

    if bus:
        await bus.emit(Event(EventType.RECON_HTTP, message=f"probing {target}"))
    probe = await http_probe.probe(target, client=client, scope=scope)
    result.final_url = probe.final_url
    result.http = {
        "url": probe.url,
        "final_url": probe.final_url,
        "status_code": probe.status_code,
        "reason": probe.reason,
        "server": probe.server,
        "content_type": probe.content_type,
        "content_length": probe.content_length,
        "title": probe.title,
        "redirects": probe.redirects,
        "elapsed_ms": probe.elapsed_ms,
        "tls": probe.tls,
        "error": probe.error,
    }
    if probe.error:
        result.errors.append(f"http: {probe.error}")

    techs = technologies.detect(probe)
    result.technologies = [asdict(t) for t in techs]
    for t in techs:
        if bus:
            await bus.emit(
                Event(EventType.TECHNOLOGY_FOUND, message=t.name, data=asdict(t))
            )

    if bus:
        await bus.emit(
            Event(EventType.RECON_ROBOTS, message=f"fetching {origin}/robots.txt")
        )
    robots_result = await robots.fetch(origin, scope=scope, client=client)
    result.robots = {
        "url": robots_result.url,
        "found": robots_result.found,
        "status_code": robots_result.status_code,
        "disallow": robots_result.disallow,
        "allow": robots_result.allow,
        "sitemaps": robots_result.sitemaps,
        "crawl_delay": robots_result.crawl_delay,
        "error": robots_result.error,
    }

    sitemap_urls = list(robots_result.sitemaps)
    if not sitemap_urls:
        sitemap_urls = [f"{origin}/sitemap.xml"]

    if fetch_sitemaps:
        for sm_url in sitemap_urls[:max_sitemaps]:
            if bus:
                await bus.emit(
                    Event(EventType.RECON_SITEMAP, message=f"fetching {sm_url}")
                )
            sm = await sitemap.fetch(sm_url, scope=scope, client=client)
            result.sitemaps.append({
                "url": sm.url,
                "found": sm.found,
                "status_code": sm.status_code,
                "urls": sm.urls,
                "sub_sitemaps": sm.sub_sitemaps,
                "error": sm.error,
            })

    return result
