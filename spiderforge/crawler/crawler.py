"""Async BFS crawler for SpiderForge v3.

Design goals:
  - All HTTP traffic goes through ``SafeHttpClient`` (scope, SSRF, rate limit, size).
  - BFS traversal with bounded depth and URL count.
  - Emits canonical events via ``EventBus`` and/or an ``on_event`` callback.
  - Extracts links, forms, and JS endpoints; records them as ``DiscoveredEndpoint``.
  - Skips static resources (CSS/JS/images) from scanner targets.
  - Silently ignores out-of-scope links (they are not crawl errors).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

from spiderforge.core.events import Event, EventBus, EventType
from spiderforge.crawler.extractors import (
    extract_forms,
    extract_inline_script_sources,
    extract_js_endpoints,
    extract_links,
)
from spiderforge.crawler.frontier import Frontier, FrontierItem
from spiderforge.crawler.models import (
    CrawledPage,
    CrawlResult,
    DiscoveredEndpoint,
    DiscoveredForm,
)
from spiderforge.crawler.url_utils import (
    extract_query_params,
    normalize_and_validate,
    should_skip_by_extension,
)
from spiderforge.network.client import SafeHttpClient
from spiderforge.utils.logging import get_logger

log = get_logger("crawler")


_PARSEABLE_CONTENT_PREFIXES = (
    "text/html",
    "application/xhtml",
    "text/plain",
    "application/json",
    "application/javascript",
    "text/javascript",
    "application/xml",
    "text/xml",
)


# Scope-related errors that should not be reported as crawl errors
_SCOPE_ERROR_MARKERS = (
    "outside authorized scope",
    "ScopeViolationError",
)


class Crawler:
    """Asynchronous BFS crawler bound to a ``SafeHttpClient``."""

    def __init__(
        self,
        client: SafeHttpClient,
        *,
        max_urls: int = 500,
        max_depth: int = 3,
        max_concurrency: int = 10,
        parse_js: bool = True,
        bus: EventBus | None = None,
        on_event: Callable[[str, dict], None] | None = None,
    ) -> None:
        self.client = client
        self.max_urls = max(1, int(max_urls))
        self.max_depth = max(0, int(max_depth))
        self.max_concurrency = max(1, int(max_concurrency))
        self.parse_js = parse_js
        self.bus = bus
        self.on_event = on_event

        # Accumulated results
        self._pages: list[CrawledPage] = []
        self._forms: list[DiscoveredForm] = []
        self._endpoints: dict[str, DiscoveredEndpoint] = {}
        self._errors: list[str] = []
        self._stopped_reason: str = "completed"

    # ── Public API ─────────────────────────────────────────────

    async def crawl(self, start_url: str) -> CrawlResult:
        """Run a BFS crawl starting at ``start_url``."""
        started = time.monotonic()

        frontier = Frontier(max_urls=self.max_urls, max_depth=self.max_depth)
        frontier.add(start_url, depth=0, source="seed")
        await self._emit("crawl_started", {"start_url": start_url})

        sem = asyncio.Semaphore(self.max_concurrency)
        frontier_lock = asyncio.Lock()
        pending: set[asyncio.Task] = set()

        async def _process(item: FrontierItem) -> None:
            async with sem:
                try:
                    await self._crawl_one(item, frontier, frontier_lock)
                except Exception as exc:  # noqa: BLE001
                    log.warning("crawl error on %s: %s", item.url, exc)
                    self._errors.append(f"{item.url}: {type(exc).__name__}: {exc}")

        try:
            while True:
                async with frontier_lock:
                    item = frontier.pop()

                if item is not None:
                    task = asyncio.create_task(_process(item))
                    pending.add(task)
                    task.add_done_callback(pending.discard)
                    continue

                if not pending:
                    break

                await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)

                async with frontier_lock:
                    if frontier.is_full():
                        self._stopped_reason = "max_urls"
        finally:
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

        duration = time.monotonic() - started
        result = CrawlResult(
            start_url=start_url,
            pages=list(self._pages),
            endpoints=list(self._endpoints.values()),
            forms=list(self._forms),
            errors=list(self._errors),
            duration_seconds=duration,
            stopped_reason=self._stopped_reason,
        )
        await self._emit("crawl_completed", {
            "pages": len(self._pages),
            "endpoints": len(self._endpoints),
            "forms": len(self._forms),
            "duration": duration,
            "stopped_reason": self._stopped_reason,
        })
        return result

    # ── Internals ──────────────────────────────────────────────

    async def _crawl_one(
        self,
        item: FrontierItem,
        frontier: Frontier,
        frontier_lock: asyncio.Lock,
    ) -> None:
        url = item.url
        depth = item.depth

        try:
            resp = await self.client.get(url)
        except Exception as exc:  # noqa: BLE001
            err_str = f"{type(exc).__name__}: {exc}"

            # Out-of-scope links are expected — never report them as errors
            if any(marker in err_str for marker in _SCOPE_ERROR_MARKERS):
                log.debug("Skipping out-of-scope URL: %s", url)
                return

            self._pages.append(CrawledPage(
                url=url,
                final_url=url,
                status_code=0,
                content_type="",
                depth=depth,
                error=err_str,
            ))
            await self._emit("error", {"url": url, "error": str(exc)})
            return

        content_type = (resp.headers.get("content-type") or "").lower()
        content_type_main = content_type.split(";", 1)[0].strip()
        final_url = str(resp.final_url or url)

        page = CrawledPage(
            url=url,
            final_url=final_url,
            status_code=resp.status_code,
            content_type=content_type_main,
            depth=depth,
        )

        # Record this URL as an endpoint (skips static resources)
        self._record_endpoint(url, "GET", source="page")

        is_parseable = any(
            content_type_main.startswith(p) for p in _PARSEABLE_CONTENT_PREFIXES
        )
        if not is_parseable:
            self._pages.append(page)
            await self._emit("url_fetched", {
                "url": url,
                "status": resp.status_code,
                "content_type": content_type_main,
                "depth": depth,
            })
            return

        body = resp.safe_text()

        # ── HTML extraction ───────────────────────────────────
        new_links: set[str] = set()
        if "html" in content_type_main or "xhtml" in content_type_main:
            raw_links = extract_links(body, final_url)
            for raw in raw_links:
                candidate = normalize_and_validate(raw, base_url=final_url)
                if candidate:
                    new_links.add(candidate)
            page.links_found = len(new_links)

            # Forms
            forms = extract_forms(body, final_url)
            for form in forms:
                self._forms.append(form)
                self._record_endpoint(
                    form.action,
                    form.method,
                    source="form",
                    extra_params=[i.name for i in form.inputs],
                )
                await self._emit("form_found", {
                    "action": form.action,
                    "method": form.method,
                    "inputs": [i.name for i in form.inputs],
                    "source_url": final_url,
                })
            page.forms_found = len(forms)

        # ── JavaScript endpoint extraction ────────────────────
        if self.parse_js:
            js_endpoints: set[str] = set()

            if "javascript" in content_type_main:
                js_endpoints = extract_js_endpoints(body, final_url)
            elif "html" in content_type_main or "xhtml" in content_type_main:
                for snippet in extract_inline_script_sources(body):
                    js_endpoints |= extract_js_endpoints(snippet, final_url)

            for js_url in js_endpoints:
                candidate = normalize_and_validate(js_url, base_url=final_url)
                if not candidate:
                    continue
                self._record_endpoint(candidate, "GET", source="js")
                await self._emit("api_found", {
                    "url": candidate,
                    "source_url": final_url,
                })

            page.js_endpoints_found = len(js_endpoints)

        self._pages.append(page)

        await self._emit("url_fetched", {
            "url": url,
            "status": resp.status_code,
            "content_type": content_type_main,
            "depth": depth,
            "links_found": page.links_found,
        })

        # ── Schedule new URLs ─────────────────────────────────
        if depth < self.max_depth and new_links:
            async with frontier_lock:
                for link in new_links:
                    if frontier.is_full():
                        self._stopped_reason = "max_urls"
                        break
                    if frontier.add(link, depth=depth + 1, source="link"):
                        await self._emit("url_discovered", {
                            "url": link,
                            "depth": depth + 1,
                            "parent": final_url,
                        })

    def _record_endpoint(
        self,
        url: str,
        method: str,
        *,
        source: str = "link",
        extra_params: list[str] | None = None,
    ) -> None:
        """Register an endpoint by (path, method) with merged parameters.

        Skips static resources (CSS, JS, images, fonts).
        """
        # Skip static resources — no point scanning them
        if should_skip_by_extension(url):
            return

        try:
            normalized = normalize_and_validate(url, base_url=url) or url
        except Exception:
            normalized = url

        params = set(extract_query_params(normalized))
        if extra_params:
            params.update(p for p in extra_params if p)

        key_path = normalized.split("?", 1)[0]
        key = f"{method.upper()} {key_path}"

        existing = self._endpoints.get(key)
        if existing:
            merged = set(existing.parameters) | params
            existing.parameters = sorted(merged)
            return

        self._endpoints[key] = DiscoveredEndpoint(
            url=normalized,
            method=method.upper(),
            parameters=sorted(params),
            source=source,
        )

    async def _emit(self, event_name: str, payload: dict) -> None:
        """Emit an event through the callback and/or the EventBus."""
        if self.on_event is not None:
            try:
                self.on_event(event_name, payload)
            except Exception:
                pass

        if self.bus is not None:
            try:
                await self.bus.emit(Event(
                    type=self._map_event_type(event_name),
                    message=event_name,
                    data=payload,
                ))
            except Exception:
                pass

    @staticmethod
    def _map_event_type(name: str) -> EventType:
        mapping = {
            "crawl_started": EventType.SCAN_STARTED,
            "crawl_completed": EventType.SCAN_FINISHED,
            "url_discovered": EventType.URL_DISCOVERED,
            "url_fetched": EventType.URL_FETCHED,
            "form_found": EventType.FORM_FOUND,
            "api_found": EventType.API_FOUND,
            "error": EventType.ERROR,
        }
        return mapping.get(name, EventType.ERROR)


# ── Convenience wrapper ───────────────────────────────────────

async def crawl(
    start_url: str,
    client: SafeHttpClient,
    *,
    max_urls: int = 500,
    max_depth: int = 3,
    max_concurrency: int = 10,
    parse_js: bool = True,
    bus: EventBus | None = None,
) -> CrawlResult:
    """One-shot crawl helper."""
    crawler = Crawler(
        client=client,
        max_urls=max_urls,
        max_depth=max_depth,
        max_concurrency=max_concurrency,
        parse_js=parse_js,
        bus=bus,
    )
    return await crawler.crawl(start_url)
