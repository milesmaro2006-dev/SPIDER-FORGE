"""Extractors for links, forms, and JS endpoints from HTML/JS content."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from spiderforge.crawler.models import DiscoveredForm, FormInput

_JS_PATTERNS = [
    re.compile(r"""fetch\s*\(\s*["'`]([^"'`\s]+)["'`]"""),
    re.compile(
        r"""axios\.(?:get|post|put|delete|patch|head|options)\s*\(\s*["'`]([^"'`\s]+)["'`]"""
    ),
    re.compile(r"""\$\.(?:get|post|ajax)\s*\(\s*["'`]([^"'`\s]+)["'`]"""),
    re.compile(r"""\.open\s*\(\s*["'`][A-Z]+["'`]\s*,\s*["'`]([^"'`\s]+)["'`]"""),
    re.compile(r"""\burl\s*:\s*["'`]([^"'`\s]+)["'`]"""),
    re.compile(r"""["'`](/api/[^"'`\s]+)["'`]"""),
    re.compile(r"""["'`](/v\d+/[^"'`\s]+)["'`]"""),
]


def _safe_soup(html: str):
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:
        try:
            return BeautifulSoup(html, "html.parser")
        except Exception:
            return None


def extract_links(html: str, base_url: str) -> set[str]:
    links: set[str] = set()
    soup = _safe_soup(html)
    if soup is None:
        return links

    for tag in soup.find_all(["a", "area"]):
        href = tag.get("href")
        if isinstance(href, str) and href.strip():
            links.add(href.strip())

    for tag in soup.find_all("link"):
        href = tag.get("href")
        if isinstance(href, str) and href.strip():
            links.add(href.strip())

    for tag in soup.find_all(["iframe", "frame"]):
        src = tag.get("src")
        if isinstance(src, str) and src.strip():
            links.add(src.strip())

    for tag in soup.find_all("script"):
        src = tag.get("src")
        if isinstance(src, str) and src.strip():
            links.add(src.strip())

    for tag in soup.find_all("meta"):
        if (tag.get("http-equiv") or "").lower() != "refresh":
            continue
        content = tag.get("content") or ""
        m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", content, re.IGNORECASE)
        if m:
            links.add(m.group(1).strip())

    return links


def extract_forms(html: str, base_url: str) -> list[DiscoveredForm]:
    forms: list[DiscoveredForm] = []
    soup = _safe_soup(html)
    if soup is None:
        return forms

    for form_tag in soup.find_all("form"):
        raw_action = form_tag.get("action") or ""
        method = (form_tag.get("method") or "GET").strip().upper()
        if method not in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
            method = "GET"

        if isinstance(raw_action, str) and raw_action.strip():
            try:
                action = urljoin(base_url, raw_action.strip())
            except Exception:
                action = base_url
        else:
            action = base_url

        inputs: list[FormInput] = []
        for input_tag in form_tag.find_all(["input", "textarea", "select"]):
            name = input_tag.get("name")
            if not isinstance(name, str) or not name.strip():
                continue

            input_type = input_tag.get("type") or input_tag.name or "text"
            if not isinstance(input_type, str):
                input_type = "text"

            value = input_tag.get("value")
            if value is not None and not isinstance(value, str):
                value = str(value)

            inputs.append(FormInput(
                name=name.strip(),
                type=input_type.strip().lower(),
                value=value,
                required=input_tag.has_attr("required"),
            ))

        forms.append(DiscoveredForm(
            action=action,
            method=method,
            inputs=inputs,
            source_url=base_url,
        ))

    return forms


def extract_js_endpoints(script_content: str, base_url: str) -> set[str]:
    endpoints: set[str] = set()
    if not script_content:
        return endpoints

    for pattern in _JS_PATTERNS:
        for match in pattern.finditer(script_content):
            candidate = (match.group(1) or "").strip()
            if not candidate:
                continue

            if candidate.startswith(("/", "./", "../")):
                try:
                    candidate = urljoin(base_url, candidate)
                except Exception:
                    continue

            if not candidate.lower().startswith(("http://", "https://")):
                continue

            endpoints.add(candidate)

    return endpoints


def extract_inline_script_sources(html: str) -> list[str]:
    sources: list[str] = []
    soup = _safe_soup(html)
    if soup is None:
        return sources

    for tag in soup.find_all("script"):
        if tag.get("src"):
            continue
        content = tag.string
        if content:
            sources.append(content)

    return sources
