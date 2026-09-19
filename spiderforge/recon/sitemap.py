"""Sitemap.xml fetcher — uses SafeHttpClient (single outbound gateway)."""

from __future__ import annotations

from dataclasses import dataclass, field

from lxml import etree

from spiderforge.network.client import SafeHttpClient
from spiderforge.scope.validator import ScopeValidator
from spiderforge.utils.urls import normalize_url

SM_NS = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}


@dataclass
class SitemapResult:
    url: str
    found: bool = False
    status_code: int | None = None
    urls: list[str] = field(default_factory=list)
    sub_sitemaps: list[str] = field(default_factory=list)
    error: str | None = None


async def fetch(
    url: str,
    *,
    scope: ScopeValidator,
    client: SafeHttpClient,
    max_urls: int = 5000,
) -> SitemapResult:
    url = normalize_url(url)
    if not scope.is_allowed(url):
        return SitemapResult(url=url, error="out_of_scope")

    try:
        resp = await client.get(url)
    except Exception as exc:  # noqa: BLE001
        return SitemapResult(url=url, error=f"{type(exc).__name__}: {exc}")

    result = SitemapResult(url=url, status_code=resp.status_code)
    if resp.status_code != 200:
        return result

    try:
        root = etree.fromstring(resp.safe_content())
    except etree.XMLSyntaxError as exc:
        result.error = f"invalid XML: {exc}"
        return result

    result.found = True

    for loc in root.findall(".//sm:sitemap/sm:loc", SM_NS):
        if loc.text:
            result.sub_sitemaps.append(loc.text.strip())

    for loc in root.findall(".//sm:url/sm:loc", SM_NS):
        if loc.text and len(result.urls) < max_urls:
            result.urls.append(loc.text.strip())

    return result
