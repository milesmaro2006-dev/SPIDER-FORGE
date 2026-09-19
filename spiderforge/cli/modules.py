from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from spiderforge.analysis.loader import load_builtin_modules
from spiderforge.analysis.registry import registry

app = typer.Typer(name="modules", help="List and inspect security modules.")
console = Console()


@app.command("list")
def list_modules() -> None:
    """List every registered analysis module."""
    load_builtin_modules()
    by_cat = registry.by_category()
    for category, mods in by_cat.items():
        t = Table(title=f"[bold]{category}[/bold]", show_lines=False)
        t.add_column("Name", style="cyan", no_wrap=True)
        t.add_column("Description")
        for m in mods:
            t.add_row(m.name, m.description)
        console.print(t)


@app.command("show")
def show(name: str = typer.Argument(..., help="Module name.")) -> None:
    """Show details for one module."""
    load_builtin_modules()
    mod = registry.get(name)
    if mod is None:
        console.print(f"[red]no such module:[/red] {name}")
        raise typer.Exit(code=1)
    console.print(f"[bold cyan]{mod.name}[/bold cyan]  [dim]({mod.category})[/dim]")
    console.print(mod.description)
