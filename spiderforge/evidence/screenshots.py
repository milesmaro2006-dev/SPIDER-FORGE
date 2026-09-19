from __future__ import annotations

from pathlib import Path

# Screenshots are wired to Playwright in Phase 12. This module exposes the
# interface now so that collectors can call it and gracefully no-op when the
# browser backend is not installed.


async def capture_screenshot(
    url: str, *, out_path: Path, timeout: float = 20.0
) -> bool:
    """Attempt to capture a screenshot. Returns True on success.

    In Phase 12 this becomes a real Playwright call. Until then it returns
    False so the caller skips the artifact cleanly.
    """
    try:
        from playwright.async_api import async_playwright  # type: ignore
    except Exception:
        return False

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page(viewport={"width": 1280, "height": 800})
                await page.goto(url, timeout=int(timeout * 1000), wait_until="networkidle")
                out_path.parent.mkdir(parents=True, exist_ok=True)
                await page.screenshot(path=str(out_path), full_page=True)
                return True
            finally:
                await browser.close()
    except Exception:
        return False
