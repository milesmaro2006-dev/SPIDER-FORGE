from __future__ import annotations

from urllib.parse import urlsplit

from spiderforge.core.events import Event, EventBus, EventType
from spiderforge.crawler.engine import CrawlResult, crawl
from spiderforge.discovery import apis, graphql, hidden_paths, javascript, swagger
from spiderforge.discovery.endpoints import merge_endpoints
from spiderforge.discovery.models import DiscoveryResult, Endpoint, ParameterProfile
from spiderforge.discovery.parameters import profile_parameter
from spiderforge.network.client import SafeHttpClient
from spiderforge.network.policies import (
    DestinationSafetyPolicy,
    NetworkPolicy,
    ScopePolicy,
)
from spiderforge.scope.validator import ScopeValidator
from spiderforge.utils.logging import get_logger

log = get_logger("discovery.runner")


def _policy_from_validator(
    scope: ScopeValidator,
    *,
    seed: str,
    timeout: float,
    verify_tls: bool,
) -> NetworkPolicy:
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
            host = (urlsplit(seed).hostname or host).lower()
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
    seed: str,
    *,
    scope: ScopeValidator,
    bus: EventBus | None = None,
    crawl_result: CrawlResult | None = None,
    concurrency: int = 20,
    timeout: float = 20.0,
    rate_limit: float = 0.0,
    user_agent: str = "SpiderForge/0.1",
    verify_tls: bool = True,
    enable_hidden_paths: bool = True,
    enable_swagger: bool = True,
    enable_graphql: bool = True,
    enable_js: bool = True,
    max_js_files: int = 50,
) -> DiscoveryResult:
    """Run endpoint/parameter/API/JS discovery on top of (or by running) a crawl."""
    result = DiscoveryResult(seed=seed)

    if not scope.is_allowed(seed):
        result.errors.append(f"seed out of scope: {seed}")
        return result

    parts = urlsplit(seed)
    origin = f"{parts.scheme}://{parts.netloc}"

    # --- Get crawl data if not provided -------------------------------------
    if crawl_result is None:
        if bus:
            await bus.emit(
                Event(
                    EventType.SCAN_STARTED,
                    message="crawl",
                    data={"phase": "crawl"},
                )
            )
        crawl_result = await crawl(
            seed,
            scope=scope,
            bus=bus,
            concurrency=max(5, concurrency // 2),
            timeout=timeout,
            rate_limit=rate_limit,
            user_agent=user_agent,
            verify_tls=verify_tls,
        )

    # --- Collect endpoints from crawl ---------------------------------------
    endpoints: list[Endpoint] = []
    for p in crawl_result.pages:
        if p.error or not p.status_code:
            continue
        url = p.final_url or p.url
        if not scope.is_allowed(url):
            continue
        params = [
            pr.name
            for pr in crawl_result.parameters
            if pr.url == url or pr.url == p.url
        ]
        endpoints.append(
            Endpoint(
                url=url,
                method="GET",
                content_type=p.content_type,
                status_code=p.status_code,
                source="crawl",
                parameters=list(dict.fromkeys(params)),
            )
        )

    for f in crawl_result.forms:
        if not scope.is_allowed(f.action):
            continue
        endpoints.append(
            Endpoint(
                url=f.action,
                method=f.method,
                source="form",
                parameters=[field.name for field in f.fields],
            )
        )

    # --- Parameter profiling -------------------------------------------------
    params_by_key: dict[tuple[str, str, str], ParameterProfile] = {}
    for pr in crawl_result.parameters:
        key = (pr.url, pr.name, pr.method)
        if key in params_by_key:
            continue
        profile = profile_parameter(
            url=pr.url,
            name=pr.name,
            source=pr.source,
            values=[],
            method=pr.method,
        )
        params_by_key[key] = profile
    result.parameters = list(params_by_key.values())

    # --- HTTP session for the rest (SafeHttpClient) -------------------------
    policy = _policy_from_validator(
        scope, seed=seed, timeout=timeout, verify_tls=verify_tls
    )

    async with SafeHttpClient(policy=policy) as client:
        # --- JavaScript analysis --------------------------------------------
        if enable_js and crawl_result.javascript_urls:
            js_urls = crawl_result.javascript_urls[:max_js_files]
            if bus:
                await bus.emit(
                    Event(
                        EventType.SCAN_STARTED,
                        message=f"js analysis ({len(js_urls)} files)",
                        data={"phase": "js"},
                    )
                )
            for js_url in js_urls:
                finding = await javascript.fetch_and_analyze(
                    js_url, scope=scope, client=client
                )
                result.js_findings.append(finding)
                if finding.error:
                    result.errors.append(f"js: {finding.error}")
                    continue

                for ep in finding.endpoints:
                    if ep.startswith("/"):
                        abs_url = origin + ep
                    else:
                        abs_url = ep
                    if not scope.is_allowed(abs_url):
                        result.out_of_scope.append(abs_url)
                        if bus:
                            await bus.emit(
                                Event(EventType.OUT_OF_SCOPE, message=abs_url)
                            )
                        continue
                    endpoints.append(
                        Endpoint(
                            url=abs_url,
                            method="GET",
                            source="js",
                            parameters=list(finding.parameters),
                        )
                    )
                    if bus:
                        await bus.emit(
                            Event(
                                EventType.URL_DISCOVERED,
                                message=abs_url,
                                data={"source": "js"},
                            )
                        )

                for p in finding.parameters:
                    key = (finding.source_url, p, "GET")
                    if key in params_by_key:
                        continue
                    params_by_key[key] = profile_parameter(
                        url=finding.source_url, name=p, source="js", values=[]
                    )

        # --- Swagger ---------------------------------------------------------
        if enable_swagger:
            if bus:
                await bus.emit(
                    Event(
                        EventType.SCAN_STARTED,
                        message="swagger",
                        data={"phase": "swagger"},
                    )
                )
            specs = await swagger.discover_specs(origin, scope=scope, client=client)
            for spec in specs:
                result.swagger_specs.append(spec)
                for ep in spec.endpoints:
                    if scope.is_allowed(ep.url):
                        endpoints.append(ep)

        # --- GraphQL ---------------------------------------------------------
        if enable_graphql:
            if bus:
                await bus.emit(
                    Event(
                        EventType.SCAN_STARTED,
                        message="graphql",
                        data={"phase": "graphql"},
                    )
                )
            gql_infos = await graphql.detect(origin, scope=scope, client=client)
            for info in gql_infos:
                result.graphql.append(info)
                if scope.is_allowed(info.url):
                    endpoints.append(
                        Endpoint(url=info.url, method="POST", source="graphql")
                    )

        # --- Hidden paths ----------------------------------------------------
        if enable_hidden_paths:
            if bus:
                await bus.emit(
                    Event(
                        EventType.SCAN_STARTED,
                        message="hidden paths",
                        data={"phase": "hidden"},
                    )
                )
            discovered = await hidden_paths.probe_paths(
                origin,
                scope=scope,
                client=client,
                concurrency=concurrency,
                rate_limit=rate_limit,
            )
            result.hidden_paths = discovered
            for url in discovered:
                if scope.is_allowed(url):
                    endpoints.append(
                        Endpoint(url=url, method="GET", source="hidden")
                    )

    # --- Merge + dedupe endpoints -------------------------------------------
    result.endpoints = merge_endpoints(endpoints)

    # --- Recompute parameter profiles with real samples where possible ------
    from urllib.parse import parse_qsl

    for ep in result.endpoints:
        qs = urlsplit(ep.url).query
        if not qs:
            continue
        for name, value in parse_qsl(qs, keep_blank_values=True):
            key = (ep.url, name, ep.method)
            if key in params_by_key:
                if value and value not in params_by_key[key].sample_values:
                    params_by_key[key].sample_values.append(value)
                continue
            params_by_key[key] = profile_parameter(
                url=ep.url,
                name=name,
                source="url",
                values=[value],
                method=ep.method,
            )

    refreshed: list[ParameterProfile] = []
    for profile in params_by_key.values():
        if profile.sample_values:
            from spiderforge.discovery.parameters import infer_type

            t, c = infer_type(profile.sample_values)
            profile.inferred_type = t
            profile.confidence = c
        refreshed.append(profile)
    result.parameters = refreshed

    # --- API clustering -----------------------------------------------------
    result.api_clusters = apis.cluster_api_endpoints(result.endpoints)

    result.stats = {
        "endpoints": len(result.endpoints),
        "parameters": len(result.parameters),
        "api_clusters": len(result.api_clusters),
        "js_files": len(result.js_findings),
        "js_endpoints": sum(len(f.endpoints) for f in result.js_findings),
        "swagger_specs": len(result.swagger_specs),
        "graphql_endpoints": len(result.graphql),
        "hidden_paths": len(result.hidden_paths),
        "out_of_scope": len(result.out_of_scope),
        "errors": len(result.errors),
    }

    if bus:
        await bus.emit(
            Event(
                EventType.SCAN_FINISHED,
                message="discovery",
                data={"stats": result.stats},
            )
        )

    return result
