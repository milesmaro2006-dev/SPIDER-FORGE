from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def is_playwright_available() -> bool:
    try:
        import playwright  # type: ignore # noqa: F401
        return True
    except Exception:
        return False


def is_chromium_installed() -> bool:
    """Check if Playwright's Chromium binary is present."""
    if not is_playwright_available():
        return False
    import os
    from pathlib import Path

    cache = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    roots = [Path(cache)] if cache else [
        Path.home() / ".cache" / "ms-playwright",
        Path.home() / "Library" / "Caches" / "ms-playwright",
    ]
    return any(root.exists() and any(root.glob("chromium-*")) for root in roots)


@dataclass
class BrowserOptions:
    headless: bool = True
    viewport: dict[str, int] = field(default_factory=lambda: {"width": 1280, "height": 800})
    user_agent: str | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)
    ignore_https_errors: bool = False
    timeout_ms: int = 30_000


class BrowserManager:
    """Async context manager wrapping a Playwright Chromium session.

    Usage::

        async with BrowserManager(opts) as mgr:
            await mgr.goto("https://example.com")
            await mgr.screenshot("out.png")
    """

    def __init__(self, options: BrowserOptions | None = None) -> None:
        self.options = options or BrowserOptions()
        self._pw: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None

    async def __aenter__(self) -> BrowserManager:
        if not is_playwright_available():
            raise RuntimeError(
                "Playwright not installed. Run `pip install 'spiderforge[browser]'` "
                "then `spiderforge browser install`."
            )
        from playwright.async_api import async_playwright  # type: ignore

        self._pw = await async_playwright().start()
        self._browser = await self._pw.chromium.launch(headless=self.options.headless)
        self._context = await self._browser.new_context(
            viewport=self.options.viewport,
            user_agent=self.options.user_agent,
            ignore_https_errors=self.options.ignore_https_errors,
            extra_http_headers=self.options.extra_headers or None,
        )
        self._context.set_default_timeout(self.options.timeout_ms)
        self._page = await self._context.new_page()
        return self

    async def __aexit__(self, *_: Any) -> None:
        for closer in (self._context, self._browser):
            if closer is not None:
                try:
                    await closer.close()
                except Exception:
                    pass
        if self._pw is not None:
            try:
                await self._pw.stop()
            except Exception:
                pass

    @property
    def page(self) -> Any:
        return self._page

    async def goto(self, url: str, *, wait_until: str = "networkidle") -> Any:
        return await self._page.goto(url, wait_until=wait_until)

    async def screenshot(self, out_path: str, *, full_page: bool = True) -> bool:
        try:
            await self._page.screenshot(path=out_path, full_page=full_page)
            return True
        except Exception:
            return False

    async def content(self) -> str:
        try:
            return await self._page.content()
        except Exception:
            return ""

    async def title(self) -> str:
        try:
            return await self._page.title()
        except Exception:
            return ""
