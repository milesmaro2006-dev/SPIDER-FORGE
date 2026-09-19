"""Tests for all unified canonical scanners."""

import asyncio
from unittest.mock import AsyncMock
import httpx

from spiderforge.network.client import SafeResponse
from spiderforge.scanners.cors import CORSScanner
from spiderforge.scanners.headers import HeadersScanner
from spiderforge.scanners.open_redirect import OpenRedirectScanner
from spiderforge.scanners.sqli import SQLiScanner
from spiderforge.scanners.xss import XSSScanner


def create_mock_client(response: SafeResponse):
    client = AsyncMock()
    client.get.return_value = response
    return client


def test_headers_scanner():
    async def run_test():
        resp = SafeResponse(
            status_code=200,
            headers=httpx.Headers({"server": "test"}),
            url="http://target.example.com",
            content=b"ok",
            text="ok",
            http_version="HTTP/1.1",
        )
        scanner = HeadersScanner(client=create_mock_client(resp))
        findings = await scanner.scan("http://target.example.com")
        assert len(findings) == 4  # 4 missing security headers
        assert all(f.category == "security_headers" for f in findings)

    asyncio.run(run_test())


def test_cors_origin_reflection():
    async def run_test():
        resp = SafeResponse(
            status_code=200,
            headers=httpx.Headers({
                "Access-Control-Allow-Origin": "https://spiderforge-attacker.com",
                "Access-Control-Allow-Credentials": "true",
            }),
            url="http://target.example.com",
            content=b"ok",
            text="ok",
            http_version="HTTP/1.1",
        )
        scanner = CORSScanner(client=create_mock_client(resp))
        findings = await scanner.scan("http://target.example.com")
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"
        assert findings[0].category == "cors"

    asyncio.run(run_test())


def test_open_redirect_scanner():
    async def run_test():
        resp = SafeResponse(
            status_code=302,
            headers=httpx.Headers({
                "Location": "https://example.com/spiderforge_verify",
            }),
            url="http://target.example.com/login?redirect=test",
            content=b"",
            text="",
            http_version="HTTP/1.1",
        )
        scanner = OpenRedirectScanner(client=create_mock_client(resp))
        findings = await scanner.scan("http://target.example.com/login?redirect=test")
        assert len(findings) == 1
        assert findings[0].category == "open_redirect"
        assert findings[0].parameter == "redirect"

    asyncio.run(run_test())