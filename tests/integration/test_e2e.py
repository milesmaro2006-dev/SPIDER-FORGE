from __future__ import annotations

import asyncio
import json
import textwrap
from collections.abc import Generator
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pytest
from pytest_httpserver import HTTPServer

from spiderforge.analysis.loader import load_builtin_modules
from spiderforge.analysis.registry import registry
from spiderforge.analysis.runner import make_context, run_modules
from spiderforge.config.loader import load_config
from spiderforge.crawler.engine import crawl
from spiderforge.evidence.collector import EvidenceCollector
from spiderforge.findings.cvss import score_for
from spiderforge.recon.runner import run as run_recon
from spiderforge.reporting import html_report, json_report, markdown_report
from spiderforge.reporting.models import ReportContext, ReportMeta
from spiderforge.scope.models import ScopeConfig
from spiderforge.scope.validator import ScopeValidator


@pytest.fixture
def vulnerable_site() -> Generator[HTTPServer, None, None]:
    server = HTTPServer()
    server.start()
    base = server.url_for("/").rstrip("/")

    # Home page — links to a reflected-XSS endpoint
    server.expect_request("/").respond_with_data(
        textwrap.dedent(
            f"""\
            <html><head><title>Vuln App</title></head><body>
              <a href="{base}/search?q=hello">Search</a>
              <a href="{base}/item?id=1">Item</a>
            </body></html>
            """
        ),
        status=200,
        content_type="text/html",
        # no security headers on purpose
        headers={"Set-Cookie": "sessionid=abcdef; Path=/"},
    )

    # Reflected XSS endpoint
    def search(request):
        from werkzeug.wrappers import Response

        q = request.args.get("q", "")
        return Response(
            f"<html><body>You searched for: {q}</body></html>",
            status=200,
            content_type="text/html",
        )

    server.expect_request("/search").respond_with_handler(search)

    # SQLi-error endpoint
    def item(request):
        from werkzeug.wrappers import Response

        v = request.args.get("id", "")
        if "'" in v:
            return Response(
                "You have an error in your SQL syntax near ''''",
                status=500,
                content_type="text/html",
            )
        return Response("<html><body>Item</body></html>", status=200, content_type="text/html")

    server.expect_request("/item").respond_with_handler(item)

    try:
        yield server
    finally:
        server.stop()


def _scope(url: str) -> ScopeValidator:
    host = urlsplit(url).hostname or ""
    return ScopeValidator(
        ScopeConfig(
            project={"name": "e2e"},
            include=[host],
            exclude=[],
            network={"allow_private_ips": True},
        )
    )


def test_full_pipeline(vulnerable_site: HTTPServer, tmp_path: Path) -> None:
    seed = vulnerable_site.url_for("/")
    scope = _scope(seed)
    cfg = load_config()

    async def pipeline():
        recon = await run_recon(seed, scope=scope, timeout=10.0)
        crawl_result = await crawl(seed, scope=scope, concurrency=3, max_depth=2, timeout=10.0)
        load_builtin_modules()
        # Exclude slow/noisy modules from e2e; keep the deterministic ones.
        modules = registry.select(
            include=["headers", "cookies", "xss", "sqli"],
        )
        async with httpx.AsyncClient(
            follow_redirects=False, timeout=10.0, verify=False
        ) as client:
            ctx = make_context(
                target=seed,
                scope=scope,
                client=client,
                config=cfg,
                crawl_result=crawl_result,
                recon_result=recon,
            )
            analysis = await run_modules(modules, ctx=ctx)
        return recon, crawl_result, analysis

    recon, crawl_result, analysis = asyncio.run(pipeline())

    # Recon worked
    assert recon.http.get("status_code") == 200

    # Crawl found pages + params
    assert len(crawl_result.pages) >= 1
    param_names = {p.name for p in crawl_result.parameters}
    assert {"q", "id"}.issubset(param_names)

    # Analysis produced findings
    cats = {f.category for f in analysis.findings}
    assert "xss.reflected" in cats
    assert "sqli.error" in cats
    assert "cookies.secure" in cats
    assert any(c.startswith("headers.") for c in cats)

    # Enrich with CVSS
    for f in analysis.findings:
        if f.cvss_score is None:
            scored = score_for(f.category)
            if scored:
                f.cvss_score, f.cvss_vector = scored

    # Evidence collector writes bundles
    collector = EvidenceCollector(tmp_path)
    for f in analysis.findings:
        collector.capture_text(f, name="ev.txt", content=f.title)
    collector.export_findings(analysis.findings)

    # Reports render
    ctx = ReportContext(
        meta=ReportMeta(
            project_name="e2e",
            scan_id="scan-e2e-01",
            target=seed,
            started_at="2026-09-12T00:00:00Z",
            finished_at="2026-09-12T00:05:00Z",
        ),
        scope_include=list(scope.config.include),
        scope_exclude=list(scope.config.exclude),
        findings=analysis.findings,
        stats=analysis.stats,
    )
    json_report.render(ctx, tmp_path / "r.json")
    markdown_report.render(ctx, tmp_path / "r.md")
    html_report.render(ctx, tmp_path / "r.html")

    data = json.loads((tmp_path / "r.json").read_text())
    assert data["severity_counts"]["high"] >= 1
    assert any(f["category"] == "xss.reflected" for f in data["findings"])
    assert (tmp_path / "r.md").read_text().startswith("# SpiderForge")
    assert "<!DOCTYPE html>" in (tmp_path / "r.html").read_text()


@pytest.mark.browser
def test_browser_screenshot(vulnerable_site: HTTPServer, tmp_path: Path) -> None:
    """Requires `spiderforge browser install` and --run-browser."""
    from spiderforge.browser.manager import is_chromium_installed

    if not is_chromium_installed():
        pytest.skip("Chromium not installed")

    from spiderforge.browser.screenshots import capture

    url = vulnerable_site.url_for("/")
    out = tmp_path / "shot.png"
    ok, err = asyncio.run(capture(url, out))
    assert ok, err
    assert out.exists() and out.stat().st_size > 0