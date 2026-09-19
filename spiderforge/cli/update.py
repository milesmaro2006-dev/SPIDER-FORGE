from __future__ import annotations

import json
import urllib.request

import typer
from rich.console import Console

from spiderforge import __version__
from spiderforge.utils.logging import setup_logging

app = typer.Typer(name="update", help="Check for updates.")
console = Console()

PYPI_URL = "https://pypi.org/pypi/spiderforge/json"


def _fetch_latest() -> str | None:
    try:
        with urllib.request.urlopen(PYPI_URL, timeout=5) as resp:
            data = json.loads(resp.read())
            return data.get("info", {}).get("version")
    except Exception:
        return None


@app.callback(invoke_without_command=True)
def update() -> None:
    """Check PyPI for a newer SpiderForge release."""
    setup_logging()
    console.print(f"Installed: [cyan]{__version__}[/cyan]")
    latest = _fetch_latest()
    if latest is None:
        console.print("[yellow]could not reach PyPI[/yellow]")
        raise typer.Exit(code=0)
    console.print(f"Latest:    [cyan]{latest}[/cyan]")
    if latest == __version__:
        console.print("[green]up to date[/green]")
        return
    console.print(
        "\n[yellow]A newer version is available.[/yellow] Upgrade with:\n"
        "  pipx upgrade spiderforge\n"
        "or from source:\n"
        "  git pull && pipx install --force ."
    )
