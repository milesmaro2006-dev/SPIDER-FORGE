"""CLI commands: spiderforge scans — inspect persisted scan history."""

from __future__ import annotations

import json
from datetime import datetime

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from spiderforge.database.repositories import (
    FindingRepository,
    ScanRepository,
)

app = typer.Typer(
    name="scans",
    help="Inspect persisted scan history and findings.",
)
console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


def _fmt_time(dt: datetime | None) -> str:
    if dt is None:
        return "—"
    try:
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(dt)


def _fmt_duration(started: datetime | None, finished: datetime | None) -> str:
    if started is None or finished is None:
        return "—"
    try:
        return f"{(finished - started).total_seconds():.1f}s"
    except Exception:
        return "—"


@app.command("list")
def list_scans(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of scans to show."),
) -> None:
    """List recent scans."""
    scans = ScanRepository().list_recent(limit=limit)
    if not scans:
        console.print("[yellow]No scans in the database yet.[/yellow]")
        console.print("[dim]Run: spiderforge scan run <target>[/dim]")
        return

    table = Table(
        title=f"Recent Scans (last {len(scans)})",
        header_style="bold cyan",
        show_lines=False,
    )
    table.add_column("ID", style="bold", no_wrap=True)
    table.add_column("Target", overflow="fold")
    table.add_column("Status", no_wrap=True)
    table.add_column("Findings", justify="right", no_wrap=True)
    table.add_column("Started", no_wrap=True)
    table.add_column("Duration", justify="right", no_wrap=True)

    status_style = {
        "completed": "green",
        "running": "yellow",
        "failed": "red",
        "created": "dim",
    }

    for s in scans:
        st = s.status
        color = status_style.get(st, "white")
        table.add_row(
            str(s.id),
            s.target,
            f"[{color}]{st}[/{color}]",
            str(s.finding_count),
            _fmt_time(s.started_at),
            _fmt_duration(s.started_at, s.finished_at),
        )

    console.print(table)


@app.command("show")
def show_scan(
    scan_id: int = typer.Argument(..., help="Scan ID (from `scans list`)."),
    raw: bool = typer.Option(False, "--raw", help="Print raw JSON of the scan row."),
) -> None:
    """Show detailed metadata about a single scan."""
    scan = ScanRepository().get_by_id(scan_id)
    if scan is None:
        console.print(f"[red]Scan #{scan_id} not found.[/red]")
        raise typer.Exit(code=1)

    if raw:
        data = {
            "id": scan.id,
            "scan_uid": scan.scan_uid,
            "project_id": scan.project_id,
            "target": scan.target,
            "status": scan.status,
            "profile": scan.profile,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "finding_count": scan.finding_count,
            "discovered_urls_count": scan.discovered_urls_count,
            "error": scan.error,
        }
        console.print_json(json.dumps(data, indent=2))
        return

    body = (
        f"[white]Scan UID:[/white]            {scan.scan_uid}\n"
        f"[white]Project ID:[/white]          {scan.project_id}\n"
        f"[white]Target:[/white]              {scan.target}\n"
        f"[white]Profile:[/white]             {scan.profile}\n"
        f"[white]Status:[/white]              {scan.status}\n"
        f"[white]Started:[/white]             {_fmt_time(scan.started_at)}\n"
        f"[white]Finished:[/white]            {_fmt_time(scan.finished_at)}\n"
        f"[white]Duration:[/white]            "
        f"{_fmt_duration(scan.started_at, scan.finished_at)}\n"
        f"[white]Discovered URLs:[/white]     {scan.discovered_urls_count}\n"
        f"[white]Total Findings:[/white]      {scan.finding_count}"
    )

    if scan.error:
        body += f"\n[red]Error:[/red] {scan.error}"

    console.print(Panel.fit(body, title=f"[b]Scan #{scan.id}[/b]", border_style="cyan"))

    # Config summary
    if scan.configuration and scan.configuration != "{}":
        console.print("\n[bold cyan]Configuration:[/bold cyan]")
        try:
            console.print_json(scan.configuration)
        except Exception:
            console.print(f"[dim]{scan.configuration}[/dim]")


@app.command("findings")
def list_findings(
    scan_id: int = typer.Argument(..., help="Scan ID."),
) -> None:
    """List findings for a scan."""
    scan = ScanRepository().get_by_id(scan_id)
    if scan is None:
        console.print(f"[red]Scan #{scan_id} not found.[/red]")
        raise typer.Exit(code=1)

    rows = FindingRepository().list_for_scan(scan_id)
    if not rows:
        console.print(f"[green]Scan #{scan_id} has no persisted findings.[/green]")
        return

    table = Table(
        title=f"Findings for Scan #{scan_id}",
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Severity", justify="center", no_wrap=True)
    table.add_column("Confidence", no_wrap=True)
    table.add_column("Title", overflow="fold")
    table.add_column("URL", overflow="fold", style="dim")
    table.add_column("Param", no_wrap=True)

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    rows_sorted = sorted(rows, key=lambda r: order.get(r.severity, 99))

    for r in rows_sorted:
        color = SEVERITY_COLORS.get(r.severity, "white")
        table.add_row(
            f"[{color}]{r.severity}[/{color}]",
            r.confidence,
            r.title,
            r.url,
            r.parameter or "—",
        )

    console.print(table)


if __name__ == "__main__":
    app()
