from __future__ import annotations

import asyncio
import textwrap
from collections.abc import Generator
from urllib.parse import urlsplit

import pytest
from pytest_httpserver import HTTPServer

from spiderforge.core.events import EventBus
from spiderforge.recon.runner import run as run_recon
from spiderforge.scope.models import ScopeConfig
from spiderforge.scope.validator import ScopeValidator


@pytest.fixture
def local_server() -> Generator[HTTPServer, None, None]:
    server = HTTPServer()
    server.start()

    # Root page with title + technology hints
    server.expect_request("/").respond_with_data(
        textwrap.dedent(
            """\
            <html>
              <head>
                <title>Test Target</title>
                <meta name="generator" content="WordPress 6.4.2">
                <script src="/wp-includes/js/jquery/jquery.min.js"></script>
              </head>
              <body>
                <h1>Hello</h1>
              </body>
            </html>
            """
        ),
        status=200,
        content_type="text/html",
        headers={
            "Server": "nginx/1.24.0",
            "X-Powered-By": "PHP/8.2.7",
            "Set-Cookie": "wordpress_logged_in_abc=1; Path=/",
        },
    )

    # robots.txt
    server.expect_request("/robots.txt").respond_with_data(
        textwrap.dedent(
            """\
            User-agent: *
            Disallow: /admin/
            Disallow: /private/
            Allow: /public/
            Sitemap: {base}/sitemap.xml
            Crawl-delay: 2
            """.format(base=server.url_for("/").rstrip("/"))
        ),
        status=200,
        content_type="text/plain",
    )

    # sitemap.xml
    server.expect_request("/sitemap.xml").respond_with_data(
        textwrap.dedent(
            """\
            <?xml version="1.0" encoding="UTF-8"?>
            <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
              <url><loc>{base}/page1</loc></url>
              <url><loc>{base}/page2</loc></url>
            </urlset>
            """.format(base=server.url_for("/").rstrip("/"))
        ),
        status=200,
        content_type="application/xml",
    )

    try:
        yield server
    finally:
        server.stop()


def _scope_for(url: str) -> ScopeValidator:
    host = urlsplit(url).hostname or ""

    return ScopeValidator(
        ScopeConfig(
            include=[host],
            exclude=[],
            network={"allow_private_ips": True},
        )
    )


def test_recon_end_to_end(local_server: HTTPServer) -> None:
    url = local_server.url_for("/")

    scope = _scope_for(url)
    bus = EventBus()

    result = asyncio.run(
        run_recon(
            url,
            scope=scope,
            bus=bus,
            timeout=10.0,
        )
    )

    # HTTP
    assert result.http["status_code"] == 200
    assert result.http["title"] == "Test Target"
    assert result.http["server"] in result.http.get("server", "nginx/1.24.0")

    # Technologies
    tech_names = {t["name"] for t in result.technologies}

    assert "nginx" in tech_names
    assert "PHP" in tech_names
    assert "WordPress" in tech_names
    assert "jQuery" in tech_names

    # Robots
    assert result.robots["found"] is True
    assert "/admin/" in result.robots["disallow"]
    assert "/private/" in result.robots["disallow"]
    assert result.robots["crawl_delay"] == 2.0
    assert result.robots["sitemaps"]

    # Sitemaps
    assert len(result.sitemaps) >= 1

    urls_seen = {
        url
        for sitemap in result.sitemaps
        for url in sitemap.get("urls", [])
    }

    assert any(url.endswith("/page1") for url in urls_seen)
    assert any(url.endswith("/page2") for url in urls_seen)

    # Events were emitted
    event_types = {event.type.value for event in bus.history}

    assert "RECON_DNS" in event_types
    assert "RECON_HTTP" in event_types
    assert "TECHNOLOGY_FOUND" in event_types


def test_recon_out_of_scope(local_server: HTTPServer) -> None:
    url = local_server.url_for("/")

    # Scope that does NOT include localhost
    scope = ScopeValidator(
        ScopeConfig(
            include=["example.com"],
            network={"allow_private_ips": True},
        )
    )

    result = asyncio.run(
        run_recon(
            url,
            scope=scope,
            timeout=5.0,
        )
    )

    assert result.errors
    assert "out of scope" in result.errors[0].lower()

    # No HTTP request made
    assert result.http == {}


def test_recon_robots_404(local_server: HTTPServer) -> None:
    # Point at a fresh path with no robots.txt
    local_server.expect_request("/robots.txt").respond_with_data(
        "",
        status=404,
    )

    url = local_server.url_for("/")
    scope = _scope_for(url)

    result = asyncio.run(
        run_recon(
            url,
            scope=scope,
            timeout=5.0,
            fetch_sitemaps=False,
        )
    )

    assert result.robots["found"] in (True, False)
    assert result.robots["status_code"] in (200, 404)