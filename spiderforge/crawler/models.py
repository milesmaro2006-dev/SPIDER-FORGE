"""Data models for the SpiderForge crawler."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FormInput:
    """A single input field within an HTML form."""

    name: str
    type: str = "text"
    value: str | None = None
    required: bool = False


@dataclass
class DiscoveredForm:
    """An HTML form discovered during crawling."""

    action: str
    method: str = "GET"
    inputs: list[FormInput] = field(default_factory=list)
    source_url: str = ""


@dataclass
class DiscoveredEndpoint:
    """A distinct URL + method + parameters combination.

    Endpoints are deduplicated by ``(method, path-without-query)``.
    Parameters are merged across discoveries.
    """

    url: str
    method: str = "GET"
    parameters: list[str] = field(default_factory=list)
    source: str = "link"  # "link" | "form" | "js" | "page" | "redirect"


@dataclass
class CrawledPage:
    """Metadata about a single crawled URL."""

    url: str
    final_url: str
    status_code: int
    content_type: str
    depth: int
    links_found: int = 0
    forms_found: int = 0
    js_endpoints_found: int = 0
    error: str | None = None


@dataclass
class CrawlResult:
    """Result of a full crawl pass."""

    start_url: str
    pages: list[CrawledPage] = field(default_factory=list)
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    forms: list[DiscoveredForm] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    stopped_reason: str = "completed"  # "completed" | "max_urls" | "error"
