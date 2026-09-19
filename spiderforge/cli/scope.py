from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from spiderforge.scope.parser import load_scope
from spiderforge.scope.validator import ScopeValidator

app = typer.Typer(name="scope", help="Scope management.")
console = Console()


@app.command("show")
def show(path: Path = typer.Argument(..., exists=True, readable=True)) -> None:
    """Show a parsed scope file."""
    sc = load_scope(path)
    table = Table(title=f"Scope: {path}")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Project", sc.project.name)
    table.add_row("Include", "\n".join(sc.include) or "(none)")
    table.add_row("Exclude", "\n".join(sc.exclude) or "(none)")
    table.add_row("Allow private IPs", str(sc.network.allow_private_ips))
    table.add_row("Allow public IPs", str(sc.network.allow_public_ips))
    console.print(table)


@app.command("check")
def check(
    path: Path = typer.Argument(..., exists=True, readable=True),
    target: str = typer.Argument(..., help="Host or URL to test against the scope."),
) -> None:
    """Check whether a target is allowed by a scope file."""
    sc = load_scope(path)
    v = ScopeValidator(sc)
    decision = v.check(target)
    style = "green" if decision.allowed else "red"
    verdict = "ALLOWED" if decision.allowed else "DENIED"
    console.print(
        f"[{style}]{verdict}[/{style}] {target}  "
        f"[dim](reason={decision.reason}, pattern={decision.matched_pattern})[/dim]"
    )
