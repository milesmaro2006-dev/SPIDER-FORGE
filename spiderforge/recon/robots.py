"""Robots.txt fetcher — uses SafeHttpClient (single outbound gateway)."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin

from spiderforge.network.client import SafeHttpClient
from spiderforge.scope.validator import ScopeValidator
from spiderforge.utils.urls import normalize_url


@dataclass
class RobotsResult:
    url: str
    found: bool = False
    status_code: int | None = None
    disallow: list[str] = field(default_factory=list)
    allow: list[str] = field(default_factory=list)
    sitemaps: list[str] = field(default_factory=list)
    crawl_delay: float | None = None
    error: str | None = None
    raw: str = ""


async def fetch(
    origin: str,
    *,
    scope: ScopeValidator,
    client: SafeHttpClient,
) -> RobotsResult:
    url = normalize_url(urljoin(origin.rstrip("/") + "/", "robots.txt"))

    if not scope.is_allowed(url):
        return RobotsResult(url=url, error="out_of_scope")

    try:
        resp = await client.get(url)
    except Exception as exc:  # noqa: BLE001
        return RobotsResult(url=url, error=f"{type(exc).__name__}: {exc}")

    body = resp.safe_text()

    result = RobotsResult(
        url=url,
        status_code=resp.status_code,
        raw=body[:50_000] if body else "",
    )
    if resp.status_code != 200:
        return result

    result.found = True
    for raw_line in result.raw.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "disallow" and value:
            result.disallow.append(value)
        elif key == "allow" and value:
            result.allow.append(value)
        elif key == "sitemap" and value:
            result.sitemaps.append(value)
        elif key == "crawl-delay":
            try:
                result.crawl_delay = float(value)
            except ValueError:
                pass

    return result
