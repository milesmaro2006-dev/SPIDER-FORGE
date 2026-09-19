from __future__ import annotations

from typing import Any

from spiderforge.browser.manager import BrowserManager


async def crawl_spa(
    url: str,
    *,
    mgr: BrowserManager,
    wait_until: str = "networkidle",
    settle_ms: int = 800,
) -> dict:
    """Load a URL in the browser and return extracted links + title.

    Extracts all anchor hrefs from the rendered DOM (SPA-safe).
    """
    import asyncio

    result: dict[str, Any] = {"url": url, "title": "", "links": [], "html_size": 0}
    try:
        await mgr.goto(url, wait_until=wait_until)
        if settle_ms > 0:
            await asyncio.sleep(settle_ms / 1000)
        result["title"] = await mgr.title()
        links = await mgr.page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.href)"
        )
        result["links"] = [l for l in links if isinstance(l, str) and l]
        html = await mgr.content()
        result["html_size"] = len(html)
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result
