from __future__ import annotations

import asyncio
import json
import textwrap
from collections.abc import Generator
from urllib.parse import urlsplit

import pytest
from pytest_httpserver import HTTPServer

from spiderforge.core.events import EventBus
from spiderforge.discovery.runner import run as run_discovery
from spiderforge.scope.models import ScopeConfig
from spiderforge.scope.validator import ScopeValidator


@pytest.fixture
def api_site() -> Generator[HTTPServer, None, None]:
    server = HTTPServer()
    server.start()

    # Root page
    server.expect_request("/").respond_with_data(
        textwrap.dedent(
            """\
            <html>
              <head>
                <title>App</title>
                <script src="/static/app.js"></script>
              </head>
              <body>
                <a href="/api/v1/users/123">user</a>
                <a href="/api/v1/users/456">user</a>
                <a href="/api/v1/orders/789">order</a>
              </body>
            </html>
            """
        ),
        status=200,
        content_type="text/html",
    )

    # API endpoints
    server.expect_request("/api/v1/users/123").respond_with_data(
        '{"id":123}',
        status=200,
        content_type="application/json",
    )

    server.expect_request("/api/v1/users/456").respond_with_data(
        '{"id":456}',
        status=200,
        content_type="application/json",
    )

    server.expect_request("/api/v1/orders/789").respond_with_data(
        '{"id":789}',
        status=200,
        content_type="application/json",
    )

    # Static JavaScript
    server.expect_request("/static/app.js").respond_with_data(
        textwrap.dedent(
            """\
            fetch("/api/v2/items");
            axios.get("/api/v2/search?q=test&limit=10");
            const x = new WebSocket("wss://example.com/ws");
            const endpoint = "https://api.example.com/v3/things";
            const key = "api_key";
            //# sourceMappingURL=app.js.map
            """
        ),
        status=200,
        content_type="application/javascript",
    )

    # Swagger / OpenAPI specification
    server.expect_request("/swagger.json").respond_with_data(
        json.dumps(
            {
                "swagger": "2.0",
                "info": {
                    "title": "Test API",
                },
                "basePath": "/api/v1",
                "paths": {
                    "/users/{id}": {
                        "get": {
                            "parameters": [
                                {
                                    "name": "id",
                                }
                            ]
                        }
                    },
                    "/orders": {
                        "post": {
                            "parameters": [
                                {
                                    "name": "items",
                                }
                            ]
                        }
                    },
                },
            }
        ),
        status=200,
        content_type="application/json",
    )

    # GraphQL endpoint
    server.expect_request("/graphql").respond_with_data(
        '{"errors":[{"message":"query required"}]}',
        status=400,
        content_type="application/json",
    )

    # Hidden path hits
    for path in ("/admin", "/.env", "/config"):
        server.expect_request(path).respond_with_data(
            "ok",
            status=200,
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


def test_discovery_end_to_end(api_site: HTTPServer) -> None:
    seed = api_site.url_for("/")
    scope = _scope(seed)
    bus = EventBus()

    result = asyncio.run(
        run_discovery(
            seed,
            scope=scope,
            bus=bus,
            concurrency=4,
            timeout=10.0,
            enable_hidden_paths=True,
            enable_swagger=True,
            enable_graphql=True,
            enable_js=True,
            max_js_files=5,
        )
    )

    # Endpoint clustering:
    # /api/v1/users/123 and /api/v1/users/456 should merge.
    templates = {
        endpoint.path_template
        for endpoint in result.endpoints
    }

    assert any(
        "/api/v1/users/{id}" == template
        for template in templates
    )

    assert any(
        "/api/v1/orders/{id}" == template
        for template in templates
    )

    # API cluster
    bases = {
        cluster.base_path
        for cluster in result.api_clusters
    }

    assert any(
        "api" in base
        for base in bases
    )

    # Swagger parsed
    assert any(
        spec.title == "Test API"
        for spec in result.swagger_specs
    )

    # GraphQL detected
    assert any(
        graphql.detected
        for graphql in result.graphql
    )

    # JavaScript analysis
    assert result.js_findings

    js = result.js_findings[0]

    assert (
        "/api/v2/items" in js.fetch_calls
        or any(
            "/api/v2/items" in endpoint
            for endpoint in js.endpoints
        )
    )

    assert any(
        "wss://" in websocket
        for websocket in js.websockets
    )

    assert any(
        "app.js.map" in source_map
        for source_map in js.source_maps
    )

    assert "api_key" in js.interesting_strings

    # Hidden paths discovered
    assert any(
        path.endswith("/admin")
        for path in result.hidden_paths
    )

    assert any(
        path.endswith("/.env")
        for path in result.hidden_paths
    )

    # Parameters profiled
    names = {
        parameter.name
        for parameter in result.parameters
    }

    assert {
        "q",
        "limit",
    }.issubset(names)


def test_discovery_skips_hidden_when_disabled(
    api_site: HTTPServer,
) -> None:
    seed = api_site.url_for("/")
    scope = _scope(seed)

    result = asyncio.run(
        run_discovery(
            seed,
            scope=scope,
            timeout=10.0,
            enable_hidden_paths=False,
            enable_swagger=True,
            enable_graphql=True,
            enable_js=False,
        )
    )

    assert result.hidden_paths == []
