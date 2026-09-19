from __future__ import annotations

import typer
from rich.console import Console

from spiderforge.browser.chromium import install_chromium
from spiderforge.browser.manager import is_chromium_installed, is_playwright_available

app = typer.Typer(name="browser", help="Playwright/Chromium management.")
console = Console()


@app.command("status")
def status() -> None:
    """Show Playwright + Chromium availability."""
    pw = is_playwright_available()
    ch = is_chromium_installed()
    console.print(f"Playwright:  {'[green]installed[/green]' if pw else '[red]not installed[/red]'}")
    console.print(f"Chromium:    {'[green]installed[/green]' if ch else '[red]not installed[/red]'}")
    if not pw:
        console.print(
            "[dim]Install with: pip install 'spiderforge[browser]'[/dim]"
        )
    if pw and not ch:
        console.print("[dim]Install Chromium with: spiderforge browser install[/dim]")


@app.command("install")
def install(
    with_deps: bool = typer.Option(
        False, "--with-deps", help="Also install system dependencies (needs root)."
    ),
) -> None:
    """Install Chromium via Playwright's official installer."""
    if not is_playwright_available():
        console.print(
            "[red]Playwright is not installed.[/red] Run:\n"
            "  pip install 'spiderforge[browser]'"
        )
        raise typer.Exit(code=1)
    console.print("[cyan]Installing Chromium...[/cyan]")
    rc, output = install_chromium(with_deps=with_deps)
    if rc == 0:
        console.print("[green]Chromium installed successfully.[/green]")
    else:
        console.print(f"[red]install failed (rc={rc})[/red]")
        console.print(output[-2000:])
        raise typer.Exit(code=rc or 1)
