from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

from spiderforge.database.engine import init_db, session_scope
from spiderforge.database.models import FindingRow
from spiderforge.findings.lifecycle import can_transition
from spiderforge.findings.models import FindingStatus
from spiderforge.utils.logging import setup_logging

app = typer.Typer(name="findings", help="Inspect and manage findings.")
console = Console()

_SEV_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


@app.command("list")
def list_findings(
    severity: str | None = typer.Option(None, "--severity", "-s"),
    status: str | None = typer.Option(None, "--status"),
    scan: str | None = typer.Option(None, "--scan", help="Filter by scan UID."),
) -> None:
    """List findings from the local database."""
    setup_logging()
    init_db()
    with session_scope() as session:
        q = session.query(FindingRow)
        if severity:
            q = q.filter(FindingRow.severity == severity.lower())
        if status:
            q = q.filter(FindingRow.status == status.lower())
        rows = q.order_by(FindingRow.created_at.desc()).all()

    if not rows:
        console.print("[dim]no findings[/dim]")
        return

    t = Table()
    t.add_column("UID", style="cyan", no_wrap=True)
    t.add_column("Sev", no_wrap=True)
    t.add_column("Conf", justify="right")
    t.add_column("Category", style="dim")
    t.add_column("Status", style="dim")
    t.add_column("Title")
    for r in rows:
        color = _SEV_COLORS.get(r.severity, "white")
        t.add_row(
            r.finding_uid,
            f"[{color}]{r.severity.upper()}[/{color}]",
            f"{r.confidence:.2f}",
            r.category,
            r.status,
            r.title,
        )
    console.print(t)


@app.command("show")
def show(finding_uid: str = typer.Argument(...)) -> None:
    """Show one finding in detail."""
    setup_logging()
    init_db()
    with session_scope() as session:
        row = (
            session.query(FindingRow)
            .filter(FindingRow.finding_uid == finding_uid)
            .one_or_none()
        )
    if row is None:
        console.print(f"[red]no such finding:[/red] {finding_uid}")
        raise typer.Exit(code=1)

    console.print(f"[bold cyan]{row.finding_uid}[/bold cyan] — {row.title}")
    console.print(f"Severity: [bold]{row.severity.upper()}[/bold]  "
                  f"Confidence: {row.confidence:.2f}")
    if row.cvss_score is not None:
        console.print(f"CVSS: {row.cvss_score} ({row.cvss_vector})")
    console.print(f"Category: {row.category}")
    console.print(f"URL: {row.url}")
    console.print(f"Method: {row.method}" + (f"  Parameter: {row.parameter}" if row.parameter else ""))
    console.print(f"Status: {row.status}")
    console.print()
    console.print("[bold]Description[/bold]")
    console.print(row.description or "—")
    console.print()
    console.print("[bold]Impact[/bold]")
    console.print(row.impact or "—")
    console.print()
    console.print("[bold]Remediation[/bold]")
    console.print(row.remediation or "—")
    console.print()
    console.print("[bold]Evidence[/bold]")
    try:
        ev = json.loads(row.evidence)
    except Exception:
        ev = {}
    for k, v in ev.items():
        if v:
            console.print(f"  [dim]{k}:[/dim] {str(v)[:400]}")


def _set_status(finding_uid: str, target: FindingStatus) -> None:
    setup_logging()
    init_db()
    with session_scope() as session:
        row = (
            session.query(FindingRow)
            .filter(FindingRow.finding_uid == finding_uid)
            .one_or_none()
        )
        if row is None:
            console.print(f"[red]no such finding:[/red] {finding_uid}")
            raise typer.Exit(code=1)
        try:
            current = FindingStatus(row.status)
        except ValueError:
            current = FindingStatus.UNCONFIRMED
        if not can_transition(current, target):
            console.print(
                f"[red]invalid transition:[/red] {current.value} → {target.value}"
            )
            raise typer.Exit(code=1)
        row.status = target.value
    console.print(f"[green]{finding_uid}[/green]: {current.value} → {target.value}")


@app.command("confirm")
def confirm(finding_uid: str = typer.Argument(...)) -> None:
    _set_status(finding_uid, FindingStatus.CONFIRMED)


@app.command("false-positive")
def false_positive(finding_uid: str = typer.Argument(...)) -> None:
    _set_status(finding_uid, FindingStatus.FALSE_POSITIVE)


@app.command("retest")
def retest(finding_uid: str = typer.Argument(...)) -> None:
    """Move a finding to RETEST_PENDING. Actual retest arrives in Phase 16."""
    _set_status(finding_uid, FindingStatus.RETEST_PENDING)
