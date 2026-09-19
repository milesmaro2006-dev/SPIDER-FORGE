from __future__ import annotations

from pathlib import Path

from spiderforge.browser.manager import BrowserManager, BrowserOptions


async def capture(
    url: str,
    out_path: Path,
    *,
    options: BrowserOptions | None = None,
) -> tuple[bool, str | None]:
    """Capture a full-page screenshot. Returns (ok, error)."""
    opts = options or BrowserOptions()
    try:
        async with BrowserManager(opts) as mgr:
            await mgr.goto(url)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            ok = await mgr.screenshot(str(out_path), full_page=True)
            return ok, None if ok else "screenshot call failed"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
