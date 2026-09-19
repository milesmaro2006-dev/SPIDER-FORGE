from __future__ import annotations

import asyncio
import time
from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qsl, urlsplit

from spiderforge.core.events import Event, EventBus, EventType
from spiderforge.core.exceptions import ScopeViolation
from spiderforge.crawler.forms import Form, ParameterRecord
from spiderforge.crawler.normalization import canonicalize
from spiderforge.crawler.parser import ParsedPage, parse_html
from spiderforge.crawler.queue import CrawlItem, Frontier
from spiderforge.crawler.rate_limit import RateLimiter
from spiderforge.network.client import SafeHttpClient
from spiderforge.network.policies import (
    DestinationSafetyPolicy,
    NetworkPolicy,
    ScopePolicy,
)
from spiderforge.scope.validator import ScopeValidator
from spiderforge.utils.logging import get_logger

log = get_logger("crawler.engine")


# ----------------------------- Result model ------------------------------- #


@dataclass
class PageRecord:
    url: str
    final_url: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    content_length: int | None = None
    title: str | None = None
    depth: int = 0
    source: str | None = None
    redirects: list[str] = field(default_factory=list)
    error: str | None = None
    link_count: int = 0
    form_count: int = 0
    script_count: int = 0


@dataclass
class CrawlResult:
    seed: str
    pages: list[PageRecord] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    parameters: list[ParameterRecord] = field(default_factory=list)
    javascript_urls: list[str] = field(default_factory=list)
    api_hints: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "seed": self.seed,
            "pages": [asdict(p) for p in self.pages],
            "forms": [asdict(f) for f in self.forms],
            "parameters": [asdict(p) for p in self.parameters],
            "javascript_urls": list(self.javascript_urls),
            "api_hints": list(self.api_hints),
            "out_of_scope": list(self.out_of_scope),
            "resources": list(self.resources),
            "errors": list(self.errors),
            "stats": dict(self.stats),
        }


# ------------------------------ Heuristics -------------------------------- #


_API_PATH_HINTS = ("/api/", "/api", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql", "/rpc")


def _looks_like_api(url: str, content_type: str) -> bool:
    if "application/json" in content_type:
        return True
    path = urlsplit(url).path.lower()
    return any(h in path for h in _API_PATH_HINTS)


def _extract_query_params(url: str) -> list[str]:
    return [name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]


def _policy_from_validator(
    scope: ScopeValidator,
    *,
    target: str,
    timeout: float,
    verify_tls: bool,
) -> NetworkPolicy:
    """Build a NetworkPolicy from a ScopeValidator (best-effort)."""
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


# -------------------------------- Engine ---------------------------------- #


async def crawl(
    seed_url: str,
    *,
    scope: ScopeValidator,
    bus: EventBus | None = None,
    concurrency: int = 10,
    max_depth: int = 5,
    max_urls: int = 5000,
    timeout: float = 20.0,
    rate_limit: float = 0.0,
    delay: float = 0.0,
    user_agent: str = "SpiderForge/0.1",
    verify_tls: bool = True,
    follow_redirects: bool = True,
) -> CrawlResult:
    seed = canonicalize(seed_url)
    if not scope.is_allowed(seed):
        raise ScopeViolation(f"seed is out of scope: {seed}")

    result = CrawlResult(seed=seed)
    frontier = Frontier(maxsize=max(max_urls * 2, 1000))

    if bus:
        await bus.emit(
            Event(EventType.SCAN_STARTED, message=seed, data={"phase": "crawl"})
        )

    await frontier.push(CrawlItem(url=seed, depth=0, key=seed, source_url=None))

    started = time.monotonic()
    rate = RateLimiter(rate_per_sec=rate_limit, delay=delay)
    sem = asyncio.Semaphore(concurrency)
    seen_js: set[str] = set()
    seen_resources: set[str] = set()
    seen_forms: set[str] = set()
    seen_params: set[tuple[str, str, str]] = set()
    seen_api: set[str] = set()
    seen_oos: set[str] = set()

    # All outbound HTTP goes through SafeHttpClient.
    policy = _policy_from_validator(
        scope, target=seed, timeout=timeout, verify_tls=verify_tls
    )

    async with SafeHttpClient(policy=policy) as client:

        async def process(item: CrawlItem) -> None:
            url = item.url
            try:
                async with sem:
                    await rate.acquire()
                    resp = await client.get(url)
            except Exception as exc:  # noqa: BLE001
                result.pages.append(
                    PageRecord(
                        url=url,
                        depth=item.depth,
                        source=item.source_url,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
                result.errors.append(f"{url}: {exc}")
                if bus:
                    await bus.emit(Event(EventType.ERROR, message=f"{url}: {exc}"))
                return

            content_type = (resp.headers.get("content-type", "") or "").lower()
            final_url = str(resp.final_url or resp.url)
            redirects = list(resp.redirect_chain or [])

            page = PageRecord(
                url=url,
                final_url=final_url,
                status_code=resp.status_code,
                content_type=content_type,
                content_length=len(resp.content),
                depth=item.depth,
                source=item.source_url,
                redirects=redirects,
            )

            if bus:
                await bus.emit(
                    Event(
                        EventType.URL_FETCHED,
                        message=url,
                        data={"status": resp.status_code},
                    )
                )

            for hop in redirects:
                if scope.is_allowed(hop) and not frontier.has_seen(canonicalize(hop)):
                    if frontier.seen_count < max_urls:
                        await frontier.push(
                            CrawlItem(
                                url=hop,
                                depth=item.depth,
                                key=canonicalize(hop),
                                source_url=url,
                            )
                        )

            if _looks_like_api(final_url, content_type) and final_url not in seen_api:
                seen_api.add(final_url)
                result.api_hints.append(final_url)
                if bus:
                    await bus.emit(Event(EventType.API_FOUND, message=final_url))

            for name in _extract_query_params(final_url):
                key = (final_url, name, "url")
                if key in seen_params:
                    continue
                seen_params.add(key)
                result.parameters.append(
                    ParameterRecord(
                        url=final_url, name=name, source="url", method="GET"
                    )
                )
                if bus:
                    await bus.emit(
                        Event(
                            EventType.PARAMETER_FOUND,
                            message=f"{name} @ {final_url}",
                        )
                    )

            if "html" in content_type:
                try:
                    html = resp.text
                except Exception:
                    html = resp.content.decode("utf-8", errors="replace")

                parsed: ParsedPage = parse_html(html, final_url)
                page.title = parsed.title
                page.link_count = len(parsed.links)
                page.form_count = len(parsed.forms)
                page.script_count = len(parsed.scripts)

                if item.depth < max_depth:
                    for link in parsed.links:
                        if frontier.seen_count >= max_urls:
                            break
                        if not scope.is_allowed(link):
                            if link not in seen_oos:
                                seen_oos.add(link)
                                result.out_of_scope.append(link)
                                if bus:
                                    await bus.emit(
                                        Event(EventType.OUT_OF_SCOPE, message=link)
                                    )
                            continue
                        key = canonicalize(link)
                        if frontier.has_seen(key):
                            continue
                        pushed = await frontier.push(
                            CrawlItem(
                                url=key,
                                depth=item.depth + 1,
                                key=key,
                                source_url=final_url,
                            )
                        )
                        if pushed and bus:
                            await bus.emit(
                                Event(EventType.URL_DISCOVERED, message=key)
                            )

                for form in parsed.forms:
                    fkey = f"{form.method} {form.action} {form.source_url}"
                    if fkey in seen_forms:
                        continue
                    seen_forms.add(fkey)
                    if scope.is_allowed(form.action):
                        result.forms.append(form)
                        for f in form.fields:
                            pkey = (form.action, f.name, f"form:{form.method}")
                            if pkey in seen_params:
                                continue
                            seen_params.add(pkey)
                            result.parameters.append(
                                ParameterRecord(
                                    url=form.action,
                                    name=f.name,
                                    source="form",
                                    method=form.method,
                                )
                            )
                        if bus:
                            await bus.emit(
                                Event(
                                    EventType.FORM_FOUND,
                                    message=form.action,
                                    data={
                                        "method": form.method,
                                        "fields": [f.name for f in form.fields],
                                    },
                                )
                            )

                for js in parsed.scripts:
                    if js in seen_js:
                        continue
                    seen_js.add(js)
                    result.javascript_urls.append(js)
                    if bus:
                        await bus.emit(Event(EventType.JS_FOUND, message=js))

                for res in parsed.resources:
                    if res in seen_resources:
                        continue
                    seen_resources.add(res)
                    result.resources.append(res)

            result.pages.append(page)

        async def worker(_wid: int) -> None:
            while True:
                item = await frontier.pop()
                if item is None:
                    return
                try:
                    await process(item)
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"worker: {type(exc).__name__}: {exc}")
                    if bus:
                        await bus.emit(Event(EventType.ERROR, message=str(exc)))
                finally:
                    await frontier.complete()

        workers = [asyncio.create_task(worker(i)) for i in range(concurrency)]
        await frontier.wait_done()
        await frontier.shutdown(concurrency)
        await asyncio.gather(*workers, return_exceptions=True)

    elapsed = time.monotonic() - started
    result.stats = {
        "elapsed_seconds": round(elapsed, 3),
        "urls_visited": len(result.pages),
        "urls_discovered": frontier.seen_count,
        "forms": len(result.forms),
        "parameters": len(result.parameters),
        "javascript": len(result.javascript_urls),
        "resources": len(result.resources),
        "api_hints": len(result.api_hints),
        "out_of_scope": len(result.out_of_scope),
        "errors": len(result.errors),
    }

    if bus:
        await bus.emit(
            Event(EventType.SCAN_FINISHED, message=seed, data={"stats": result.stats})
        )

    return result
