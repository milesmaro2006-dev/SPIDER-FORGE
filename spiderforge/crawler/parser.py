from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from spiderforge.crawler.forms import Form, FormField
from spiderforge.crawler.links import (
    extract_links,
    extract_resource_links,
    extract_scripts,
)

_FORM_METHODS = {"GET", "POST"}


@dataclass
class ParsedPage:
    base_url: str
    title: str | None = None
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)


def _extract_title(soup: BeautifulSoup) -> str | None:
    tag = soup.find("title")
    if not tag:
        return None
    text = " ".join(tag.get_text().split())
    return text[:300] or None


def _extract_forms(soup: BeautifulSoup, base_url: str) -> list[Form]:
    out: list[Form] = []
    for form_el in soup.find_all("form"):
        action_raw = (form_el.get("action") or "").strip()
        action = urljoin(base_url, action_raw) if action_raw else base_url

        method = (form_el.get("method") or "GET").upper()
        if method not in _FORM_METHODS:
            method = "GET"

        enctype = form_el.get("enctype") or "application/x-www-form-urlencoded"

        fields: list[FormField] = []
        for el in form_el.find_all(["input", "textarea", "select", "button"]):
            name = el.get("name")
            if not name:
                continue
            if el.name == "input":
                ftype = (el.get("type") or "text").lower()
            elif el.name == "textarea":
                ftype = "textarea"
            elif el.name == "select":
                ftype = "select"
            else:
                ftype = (el.get("type") or "button").lower()

            fields.append(
                FormField(
                    name=name,
                    type=ftype,
                    value=el.get("value"),
                    required=el.has_attr("required"),
                    placeholder=el.get("placeholder"),
                )
            )

        out.append(
            Form(
                action=action,
                method=method,
                fields=fields,
                source_url=base_url,
                enctype=enctype,
            )
        )
    return out


def parse_html(html: str, base_url: str) -> ParsedPage:
    soup = BeautifulSoup(html, "lxml")
    return ParsedPage(
        base_url=base_url,
        title=_extract_title(soup),
        links=extract_links(html, base_url),
        scripts=extract_scripts(html, base_url),
        resources=extract_resource_links(html, base_url),
        forms=_extract_forms(soup, base_url),
    )
