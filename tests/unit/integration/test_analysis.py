from __future__ import annotations

import asyncio
import textwrap
from urllib.parse import urlsplit

import httpx
import pytest
from pytest_httpserver import HTTPServer

from spiderforge.analysis.headers import HeadersModule
from spiderforge.analysis.cookies import CookiesModule
from spiderforge.analysis.cors import CorsModule
from spiderforge.analysis.xss import XssModule
from spiderforge.analysis.sqli import SqliModule
from spiderforge.analysis.path_traversal import PathTraversalModule
from spiderforge.analysis.ssti import SstiModule
from spiderforge.analysis.base import ModuleContext
from spiderforge.config.loader import load_config
from spiderforge.scope.models import ScopeConfig
from spiderforge.scope.validator import ScopeValidator


def _scope(url: str) -> ScopeValidator:
    host = urlsplit(url).hostname or ""
    return ScopeValidator(
        ScopeConfig(include=[host], network={"allow_private_ips": True})
    )


async def _ctx(url: str, **opts) -> ModuleContext:
    scope = _scope(url)
    parts = urlsplit(url)
    client = httpx.AsyncClient(follow_redirects=False, timeout=10.0, verify=False)
    return ModuleContext(
        target=url,
        origin=f"{parts.scheme}://{parts.netloc}",
        scope=scope,
        client=client,
        config=load_config(),
        options=opts,
    )


# ----------------------------- Headers ------------------------------------ #


def test_headers_missing_csp() -> None:
    server = HTTPServer()
    server.start()
    try:
        server.expect_request("/").respond_with_data(
            "<html><body>ok</body></html>",
            status=200,
            content_type="text/html",
            # deliberately NO security headers
        )
        url = server.url_for("/")

        async def go() -> list:
            ctx = await _ctx(url)
            try:
                return await HeadersModule().run(ctx)
            finally:
                await ctx.client.aclose()

        findings = asyncio.run(go())
        titles = {f.title for f in findings}
        assert any("Content-Security-Policy" in t for t in titles)
        assert any("Strict-Transport-Security" in t for t in titles)
        assert any("clickjacking" in t.lower() for t in titles)
    finally:
        server.stop()


# ----------------------------- Cookies ------------------------------------ #


def test_cookies_insecure_session() -> None:
    server = HTTPServer()
    server.start()
    try:
        server.expect_request("/").respond_with_data(
            "<html><body>ok</body></html>",
            status=200,
            content_type="text/html",
            headers={"Set-Cookie": "sessionid=abc123; Path=/"},
        )
        url = server.url_for("/")

        async def go() -> list:
            ctx = await _ctx(url)
            try:
                return await CookiesModule().run(ctx)
            finally:
                await ctx.client.aclose()

        findings = asyncio.run(go())
        cats = {f.category for f in findings}
        assert "cookies.secure" in cats
        assert "cookies.httponly" in cats
        assert "cookies.samesite" in cats
    finally:
        server.stop()


# ----------------------------- CORS --------------------------------------- #


def test_cors_origin_reflection_with_credentials() -> None:
    server = HTTPServer()
    server.start()
    try:
        def handler(request):
            from werkzeug.wrappers import Response

            origin = request.headers.get("Origin", "")
            return Response(
                "ok",
                status=200,
                headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                },
            )

        server.expect_request("/").respond_with_handler(handler)
        url = server.url_for("/")

        async def go() -> list:
            ctx = await _ctx(url)
            try:
                return await CorsModule().run(ctx)
            finally:
                await ctx.client.aclose()

        findings = asyncio.run(go())
        cats = {f.category for f in findings}
        assert "cors.origin_reflection_creds" in cats
    finally:
        server.stop()


# ----------------------------- XSS ---------------------------------------- #


def test_xss_reflected_unescaped() -> None:
    server = HTTPServer()
    server.start()
    try:
        def handler(request):
            from werkzeug.wrappers import Response

            q = request.args.get("q", "")
            # Vulnerable: raw reflection
            body = f"<html><body>You searched for: {q}</body></html>"
            return Response(body, status=200, content_type="text/html")

        server.expect_request("/search").respond_with_handler(handler)
        url = server.url_for("/search?q=hello")

        async def go() -> list:
            ctx = await _ctx(url)
            try:
                return await XssModule().run(ctx)
            finally:
                await ctx.client.aclose()

        findings = asyncio.run(go())
        assert any(f.category == "xss.reflected" for f in findings)
        assert findings[0].severity.value in ("high", "HIGH")
    finally:
        server.stop()


def test_xss_escaped_no_finding() -> None:
    server = HTTPServer()
    server.start()
    try:
        def handler(request):
            from html import escape

            from werkzeug.wrappers import Response

            q = escape(request.args.get("q", ""))
            body = f"<html><body>You searched for: {q}</body></html>"
            return Response(body, status=200, content_type="text/html")

        server.expect_request("/search").respond_with_handler(handler)
        url = server.url_for("/search?q=hello")

        async def go() -> list:
            ctx = await _ctx(url)
            try:
                return await XssModule().run(ctx)
            finally:
                await ctx.client.aclose()

        findings = asyncio.run(go())
        assert not any(f.category == "xss.reflected" for f in findings)
    finally:
        server.stop()


# ----------------------------- SQLi --------------------------------------- #


def test_sqli_error_based() -> None:
    server = HTTPServer()
    server.start()
    try:
        def handler(request):
            from werkzeug.wrappers import Response

            v = request.args.get("id", "")
            if "'" in v:
                return Response(
                    "You have an error in your SQL syntax near '''' at line 1",
                    status=500,
                    content_type="text/html",
                )
            return Response("ok", status=200, content_type="text/html")

        server.expect_request("/item").respond_with_handler(handler)
        url = server.url_for("/item?id=1")

        async def go() -> list:
            ctx = await _ctx(url)
            try:
                return await SqliModule().run(ctx)
            finally:
                await ctx.client.aclose()

        findings = asyncio.run(go())
        assert any(f.category == "sqli.error" for f in findings)
    finally:
        server.stop()


# ----------------------------- SSTI --------------------------------------- #


def test_ssti_jinja_eval() -> None:
    server = HTTPServer()
    server.start()
    try:
        def handler(request):
            from werkzeug.wrappers import Response

            v = request.args.get("name", "")
            # Vulnerable: naive eval of {{7*7}}
            if "{{7*7}}" in v:
                v = v.replace("{{7*7}}", "49")
            if "{{7*'7'}}" in v:
                v = v.replace("{{7*'7'}}", "7777777")
            return Response(
                f"<html><body>Hi {v}</body></html>",
                status=200,
                content_type="text/html",
            )

        server.expect_request("/greet").respond_with_handler(handler)
        url = server.url_for("/greet?name=alice")

        async def go() -> list:
            ctx = await _ctx(url)
            try:
                return await SstiModule().run(ctx)
            finally:
                await ctx.client.aclose()

        findings = asyncio.run(go())
        assert any(f.category == "ssti.evaluated" for f in findings)
    finally:
        server.stop()


# ----------------------------- Path Traversal ----------------------------- #


def test_path_traversal_passwd() -> None:
    server = HTTPServer()
    server.start()
    try:
        def handler(request):
            from werkzeug.wrappers import Response

            f = request.args.get("file", "")
            if "etc/passwd" in f or "passwd" in f:
                return Response(
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
                    status=200,
                    content_type="text/plain",
                )
            return Response("not found", status=404, content_type="text/plain")

        server.expect_request("/read").respond_with_handler(handler)
        url = server.url_for("/read?file=readme.txt")

        async def go() -> list:
            ctx = await _ctx(url)
            try:
                return await PathTraversalModule().run(ctx)
            finally:
                await ctx.client.aclose()

        findings = asyncio.run(go())
        assert any(f.category == "path_traversal" for f in findings)
    finally:
        server.stop()