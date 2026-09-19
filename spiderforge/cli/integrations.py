from __future__ import annotations

import asyncio

import typer
from rich.console import Console
from rich.table import Table

from spiderforge.integrations import TOOLS

app = typer.Typer(name="integrations", help="Check external tool availability.")
console = Console()


@app.command("check")
def check() -> None:
    """Verify optional external tools (nmap, httpx, nuclei, ffuf)."""
    t = Table(title="External tools")
    t.add_column("Tool", style="cyan")
    t.add_column("Status")
    t.add_column("Path", style="dim")
    t.add_column("Version", style="dim")

    async def _versions() -> dict[str, str | None]:
        out: dict[str, str | None] = {}
        for name, tool in TOOLS.items():
            out[name] = await tool.version()
        return out

    versions = asyncio.run(_versions())

    for name, tool in TOOLS.items():
        st = tool.status()
        status = "[green]✓ available[/green]" if st.available else "[red]✗ missing[/red]"
        t.add_row(name, status, st.path or "—", (versions.get(name) or "—")[:40])
    console.print(t)
