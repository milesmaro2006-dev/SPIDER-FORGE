from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from spiderforge.database.engine import init_db, session_scope
from spiderforge.database.models import FindingRow, Scan
from spiderforge.utils.logging import setup_logging

app = typer.Typer(name="history", help="Scan history and diffs.")
console = Console()


@app.command("list")
def list_scans() -> None:
    setup_logging()
    init_db()
    with session_scope() as session:
        rows = session.query(Scan).order_by(Scan.started_at.desc()).all()

    if not rows:
        console.print("[dim]no scans[/dim]")
        return

    t = Table()
    t.add_column("Scan UID", style="cyan")
    t.add_column("Target")
    t.add_column("Profile")
    t.add_column("Status")
    t.add_column("Started")
    t.add_column("Findings", justify="right")
    with session_scope() as session:
        for s in rows:
            n = session.query(FindingRow).filter(FindingRow.scan_id == s.id).count()
            t.add_row(
                s.scan_uid,
                s.target[:60],
                s.profile,
                s.status,
                s.started_at.isoformat() if s.started_at else "—",
                str(n),
            )
    console.print(t)


@app.command("show")
def show(scan_uid: str = typer.Argument(...)) -> None:
    setup_logging()
    init_db()
    with session_scope() as session:
        s = session.query(Scan).filter(Scan.scan_uid == scan_uid).one_or_none()
        if s is None:
            console.print(f"[red]no such scan:[/red] {scan_uid}")
            raise typer.Exit(code=1)
        findings = (
            session.query(FindingRow).filter(FindingRow.scan_id == s.id).all()
        )

    console.print(f"[bold cyan]{s.scan_uid}[/bold cyan]")
    console.print(f"Target:  {s.target}")
    console.print(f"Profile: {s.profile}")
    console.print(f"Status:  {s.status}")
    console.print(f"Started: {s.started_at}")
    console.print(f"Finished: {s.finished_at or '—'}")
    console.print(f"Workspace: {s.workspace_path}")
    console.print()
    console.print(f"[bold]Findings:[/bold] {len(findings)}")
    t = Table()
    t.add_column("UID", style="cyan")
    t.add_column("Sev")
    t.add_column("Title")
    for f in findings:
        t.add_row(f.finding_uid, f.severity.upper(), f.title)
    console.print(t)


@app.command("diff")
def diff(
    old_uid: str = typer.Argument(...),
    new_uid: str = typer.Argument(...),
) -> None:
    """Compare two scans by finding fingerprints."""
    setup_logging()
    init_db()
    with session_scope() as session:
        old = session.query(Scan).filter(Scan.scan_uid == old_uid).one_or_none()
        new = session.query(Scan).filter(Scan.scan_uid == new_uid).one_or_none()
        if old is None or new is None:
            console.print("[red]one or both scans not found[/red]")
            raise typer.Exit(code=1)
        old_fps = {
            f.fingerprint: f
            for f in session.query(FindingRow).filter(FindingRow.scan_id == old.id).all()
        }
        new_fps = {
            f.fingerprint: f
            for f in session.query(FindingRow).filter(FindingRow.scan_id == new.id).all()
        }

    new_keys = set(new_fps) - set(old_fps)
    gone_keys = set(old_fps) - set(new_fps)
    common = set(old_fps) & set(new_fps)

    console.rule(f"[bold]{old_uid} → {new_uid}")

    if new_keys:
        console.print(f"\n[green]New findings ({len(new_keys)})[/green]")
        t = Table()
        t.add_column("Sev")
        t.add_column("Title")
        t.add_column("URL", style="dim")
        for k in new_keys:
            f = new_fps[k]
            t.add_row(f.severity.upper(), f.title, f.url[-70:])
        console.print(t)

    if gone_keys:
        console.print(f"\n[red]Resolved / removed findings ({len(gone_keys)})[/red]")
        t = Table()
        t.add_column("Sev")
        t.add_column("Title")
        for k in gone_keys:
            f = old_fps[k]
            t.add_row(f.severity.upper(), f.title)
        console.print(t)

    if not new_keys and not gone_keys:
        console.print("[dim]no changes in finding set[/dim]")

    # Severity drift on common findings
    drifted = [
        (old_fps[k], new_fps[k])
        for k in common
        if old_fps[k].severity != new_fps[k].severity
    ]
    if drifted:
        console.print(f"\n[yellow]Severity changed ({len(drifted)})[/yellow]")
        t = Table()
        t.add_column("Title")
        t.add_column("Old")
        t.add_column("New")
        for o, n in drifted:
            t.add_row(o.title, o.severity, n.severity)
        console.print(t)
