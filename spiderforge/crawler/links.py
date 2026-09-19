from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

CRAWLABLE_TAGS: tuple[tuple[str, str], ...] = (
    ("a", "href"),
    ("area", "href"),
    ("frame", "src"),
    ("iframe", "src"),
)

_SKIP_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "blob:", "vbscript:", "file:")

_META_REFRESH_URL = re.compile(r"url\s*=\s*['\"]?([^;'\"]+)", re.IGNORECASE)


def _is_http(absolute: str) -> bool:
    return urlsplit(absolute).scheme.lower() in ("http", "https")


def _clean_href(href: str) -> str | None:
    href = href.strip()
    if not href or href.startswith("#"):
        return None
    low = href.lower()
    if low.startswith(_SKIP_SCHEMES):
        return None
    return href


def extract_links(html: str, base_url: str) -> list[str]:
    """Extract crawlable links (a/area/frame/iframe + meta-refresh)."""
    soup = BeautifulSoup(html, "lxml")
    seen: set[str] = set()
    out: list[str] = []

    for tag, attr in CRAWLABLE_TAGS:
        for el in soup.find_all(tag):
            href = _clean_href(el.get(attr) or "")
            if not href:
                continue
            absolute = urljoin(base_url, href)
            if not _is_http(absolute):
                continue
            if absolute in seen:
                continue
            seen.add(absolute)
            out.append(absolute)

    for meta in soup.find_all("meta"):
        if (meta.get("http-equiv") or "").lower() != "refresh":
            continue
        content = meta.get("content") or ""
        m = _META_REFRESH_URL.search(content)
        if not m:
            continue
        target = m.group(1).strip().strip("'\"")
        absolute = urljoin(base_url, target)
        if not _is_http(absolute) or absolute in seen:
            continue
        seen.add(absolute)
        out.append(absolute)

    return out


def extract_scripts(html: str, base_url: str) -> list[str]:
    """Extract ``<script src>`` URLs. Inline scripts are ignored here."""
    soup = BeautifulSoup(html, "lxml")
    seen: set[str] = set()
    out: list[str] = []
    for el in soup.find_all("script"):
        src = el.get("src")
        if not src:
            continue
        cleaned = _clean_href(src)
        if not cleaned:
            continue
        absolute = urljoin(base_url, cleaned)
        if not _is_http(absolute) or absolute in seen:
            continue
        seen.add(absolute)
        out.append(absolute)
    return out


def extract_resource_links(html: str, base_url: str) -> list[str]:
    """Non-crawlable resources: stylesheets, images, favicons, media, sources."""
    soup = BeautifulSoup(html, "lxml")
    seen: set[str] = set()
    out: list[str] = []
    for tag, attr in (
        ("link", "href"),
        ("img", "src"),
        ("source", "src"),
        ("track", "src"),
        ("video", "src"),
        ("audio", "src"),
    ):
        for el in soup.find_all(tag):
            val = el.get(attr)
            if not val:
                continue
            cleaned = _clean_href(val)
            if not cleaned:
                continue
            absolute = urljoin(base_url, cleaned)
            if not _is_http(absolute) or absolute in seen:
                continue
            seen.add(absolute)
            out.append(absolute)
    return out
