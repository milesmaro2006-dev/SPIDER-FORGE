from __future__ import annotations

import asyncio
import textwrap
from collections.abc import Generator
from urllib.parse import urlsplit

import pytest
from pytest_httpserver import HTTPServer

from spiderforge.core.events import EventBus
from spiderforge.crawler.engine import crawl
from spiderforge.crawler.normalization import canonicalize
from spiderforge.scope.models import ScopeConfig
from spiderforge.scope.validator import ScopeValidator


@pytest.fixture
def site() -> Generator[HTTPServer, None, None]:
    server = HTTPServer()
    server.start()

    base = server.url_for("/").rstrip("/")

    server.expect_request("/").respond_with_data(
        textwrap.dedent(
            f"""\
            <html>
              <head>
                <title>Home</title>
                <script src="/static/app.js"></script>
              </head>
              <body>
                <a href="/about">About</a>
                <a href="/search?q=hello&amp;lang=en">Search</a>
                <a href="/login">Login</a>
                <a href="https://out-of-scope.example.net/x">External</a>
                <form action="/search" method="GET">
                  <input name="q" type="text" required>
                  <input name="lang" type="text">
                </form>
                <form action="/login" method="POST">
                  <input name="username" type="text" required>
                  <input name="password" type="password" required>
                </form>
              </body>
            </html>
            """
        ),
        status=200,
        content_type="text/html",
    )

    server.expect_request("/about").respond_with_data(
        textwrap.dedent(
            """\
            <html><head><title>About</title></head>
            <body>
              <a href="/">Home</a>
              <a href="/api/v1/users">Users API</a>
            </body></html>
            """
        ),
        status=200,
        content_type="text/html",
    )

    server.expect_request("/search").respond_with_data(
        '<html><head><title>Search</title></head><body>Results</body></html>',
        status=200,
        content_type="text/html",
    )

    server.expect_request("/login").respond_with_data(
        '<html><head><title>Login</title></head><body>Please log in</body></html>',
        status=200,
        content_type="text/html",
    )

    # JSON API endpoint to test api_hints
    server.expect_request("/api/v1/users").respond_with_data(
        '{"users":[]}',
        status=200,
        content_type="application/json",
    )

    # Static JS
    server.expect_request("/static/app.js").respond_with_data(
        "console.log('ok');",
        status=200,
        content_type="application/javascript",
    )

    try:
        yield server
    finally:
        server.stop()


def _scope(url: str) -> ScopeValidator:
    host = urlsplit(url).hostname or ""

    return ScopeValidator(
        ScopeConfig(
            include=[host],
            exclude=[],
            network={"allow_private_ips": True},
        )
    )


def test_crawl_end_to_end(site: HTTPServer) -> None:
    seed = site.url_for("/")
    scope = _scope(seed)
    bus = EventBus()

    result = asyncio.run(
        crawl(
            seed,
            scope=scope,
            bus=bus,
            concurrency=4,
            max_depth=3,
            timeout=10.0,
        )
    )

    urls = {page.url for page in result.pages}

    # /, /about, /search?lang=en&q=hello, /login, /api/v1/users
    assert any(url.endswith("/about") for url in urls)
    assert any(url.endswith("/login") for url in urls)
    assert any("/search" in url for url in urls)
    assert any("/api/v1/users" in url for url in urls)

    # JS discovered
    assert any(
        url.endswith("/static/app.js")
        for url in result.javascript_urls
    )

    # API hint
    assert any(
        "/api/v1/users" in hint
        for hint in result.api_hints
    )

    # Out-of-scope recorded, not fetched
    assert any(
        "out-of-scope.example.net" in url
        for url in result.out_of_scope
    )

    assert not any(
        "out-of-scope.example.net" in (page.url or "")
        or "out-of-scope.example.net" in (page.final_url or "")
        for page in result.pages
    )

    # Forms
    form_actions = {form.action for form in result.forms}

    assert any(
        action.endswith("/search")
        for action in form_actions
    )

    assert any(
        action.endswith("/login")
        for action in form_actions
    )

    # Parameters from URL and form
    param_names = {parameter.name for parameter in result.parameters}

    assert {
        "q",
        "lang",
        "username",
        "password",
    }.issubset(param_names)

    # Event stream emitted the important types
    types = {event.type.value for event in bus.history}

    assert "URL_FETCHED" in types
    assert "URL_DISCOVERED" in types
    assert "FORM_FOUND" in types
    assert "JS_FOUND" in types
    assert "OUT_OF_SCOPE" in types


def test_crawl_respects_max_depth(site: HTTPServer) -> None:
    seed = site.url_for("/")
    scope = _scope(seed)

    result = asyncio.run(
        crawl(
            seed,
            scope=scope,
            max_depth=0,
            timeout=10.0,
            concurrency=2,
        )
    )

    # Only the seed should be visited
    assert len(result.pages) == 1
    assert result.pages[0].url.endswith("/")


def test_crawl_seed_out_of_scope(site: HTTPServer) -> None:
    from spiderforge.core.exceptions import ScopeViolation

    seed = site.url_for("/")

    scope = ScopeValidator(
        ScopeConfig(
            include=["example.com"],
            network={"allow_private_ips": True},
        )
    )

    with pytest.raises(ScopeViolation):
        asyncio.run(
            crawl(
                seed,
                scope=scope,
                timeout=5.0,
            )
        )


def test_crawl_max_urls_cap(site: HTTPServer) -> None:
    seed = site.url_for("/")
    scope = _scope(seed)

    result = asyncio.run(
        crawl(
            seed,
            scope=scope,
            max_urls=2,
            max_depth=5,
            timeout=10.0,
            concurrency=2,
        )
    )

    assert len(result.pages) <= 2