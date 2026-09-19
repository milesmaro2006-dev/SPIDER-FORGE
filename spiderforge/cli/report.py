"""CLI: spiderforge report — generate reports from DB (recommended) or workspace.

Two data sources:

1. **Database (recommended)** — pass ``--id <scan_id>`` or run interactively
   to pick a scan. Uses ``backend.reporting`` — the same canonical renderers
   as the Web API, so CLI + HTTP output are always identical.

2. **Workspace (legacy)** — pass ``--workspace <path>`` to read from an
   on-disk ``scan.json`` + ``findings.json`` folder.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

# Legacy workspace-based imports (kept for backward compatibility)
from spiderforge.findings.models import Finding
from spiderforge.reporting import html_report, json_report, markdown_report, pdf_report
from spiderforge.reporting.models import ReportContext, ReportMeta
from spiderforge.utils.logging import setup_logging
from spiderforge.utils.timestamps import isoformat

app = typer.Typer(name="report", help="Generate reports from a scan.")
console = Console()

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


# ═══════════════════════════════════════════════════════════════
#  DB-based generation (recommended)
# ═══════════════════════════════════════════════════════════════

def list_recent_scans(limit: int = 20) -> list:
    """Return the most recent scan rows from the DB. Returns [] on error."""
    try:
        from spiderforge.database.repositories import ScanRepository
        return ScanRepository().list_recent(limit=limit)
    except Exception:
        return []


def show_scan_picker(limit: int = 20) -> int | None:
    """Show a table of recent scans from the DB and ask for a scan ID."""
    scans = list_recent_scans(limit=limit)
    if not scans:
        console.print("[yellow]No scans found in the database.[/yellow]")
        console.print("[dim]Run a scan first (spiderforge → [1]).[/dim]")
        return None

    table = Table(
        title="Recent Scans (from database)",
        title_style="bold cyan",
        header_style="bold cyan",
        show_lines=False,
    )
    table.add_column("ID", justify="right", style="bold yellow", no_wrap=True)
    table.add_column("Target", style="white", overflow="fold")
    table.add_column("Status", no_wrap=True)
    table.add_column("Findings", justify="right", no_wrap=True)
    table.add_column("Started", style="dim", no_wrap=True)

    for s in scans:
        started = s.started_at.strftime("%Y-%m-%d %H:%M") if s.started_at else "—"
        table.add_row(
            str(s.id),
            s.target or "—",
            s.status or "—",
            str(s.finding_count or 0),
            started,
        )
    console.print(table)

    raw = typer.prompt("Scan ID (or 'q' to cancel)", default=str(scans[0].id))
    if raw.strip().lower() in {"q", "quit", "cancel", ""}:
        return None
    try:
        scan_id = int(raw)
    except ValueError:
        console.print(f"[red]invalid scan ID: {raw}[/red]")
        return None

    if not any(s.id == scan_id for s in scans):
        console.print(f"[yellow]scan #{scan_id} is not in the recent list.[/yellow]")
        return None
    return scan_id


def generate_for_scan_id(
    scan_id: int,
    *,
    formats: str = "json,md,html,pdf",
    output_dir: Path | None = None,
) -> list[Path]:
    """Generate reports for a DB scan using the canonical renderers.

    Uses ``backend.reporting`` (same as the Web API) so CLI reports and
    HTTP reports are byte-identical.
    """
    try:
        from backend import reporting as rpt
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]reporting module unavailable:[/red] {exc}")
        return []

    try:
        from spiderforge.database.repositories import FindingRepository, ScanRepository
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]database unavailable:[/red] {exc}")
        return []

    scan = ScanRepository().get_by_id(scan_id)
    if scan is None:
        console.print(f"[red]scan #{scan_id} not found in database.[/red]")
        return []

    rows = FindingRepository().list_for_scan(scan_id)
    report = rpt.build_canonical_report(scan, rows)

    if output_dir is None:
        output_dir = Path.home() / ".spiderforge" / "reports" / report.report_id
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    wanted = {f.strip().lower() for f in formats.split(",") if f.strip()}
    written: list[Path] = []

    if "json" in wanted:
        try:
            (output_dir / "report.json").write_bytes(rpt.render_json(report))
            written.append(output_dir / "report.json")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]json failed:[/yellow] {type(exc).__name__}: {exc}")

    if "md" in wanted or "markdown" in wanted:
        try:
            (output_dir / "report.md").write_bytes(rpt.render_markdown(report))
            written.append(output_dir / "report.md")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]markdown failed:[/yellow] {type(exc).__name__}: {exc}")

    if "html" in wanted:
        try:
            (output_dir / "report.html").write_bytes(rpt.render_html(report))
            written.append(output_dir / "report.html")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]html failed:[/yellow] {type(exc).__name__}: {exc}")

    if "pdf" in wanted:
        try:
            (output_dir / "report.pdf").write_bytes(rpt.render_pdf(report))
            written.append(output_dir / "report.pdf")
        except rpt.PDFUnavailableError as exc:
            console.print(f"[yellow]pdf skipped:[/yellow] {exc}")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]pdf skipped:[/yellow] {type(exc).__name__}: {exc}")

    if not written:
        console.print("[red]No reports were generated.[/red]")
        return []

    for p in written:
        console.print(f"[green]wrote[/green] {p}")

    console.print(f"[dim]Output directory: {output_dir}[/dim]")
    return written


# ═══════════════════════════════════════════════════════════════
#  Workspace-based generation (legacy)
# ═══════════════════════════════════════════════════════════════

def _infer_category(title: str) -> str:
    t = (title or "").lower()
    if "sql" in t:
        return "injection"
    if "xss" in t or "cross-site" in t:
        return "xss"
    if "header" in t:
        return "headers"
    if "csrf" in t:
        return "csrf"
    if "redirect" in t:
        return "redirect"
    if "disclosure" in t or "exposure" in t or "leak" in t:
        return "disclosure"
    if "clickjack" in t or "frame" in t:
        return "clickjacking"
    return "general"


def _coerce_severity(value: Any) -> str:
    s = str(value or "info").strip().lower()
    if s in VALID_SEVERITIES:
        return s
    aliases = {
        "moderate": "medium",
        "informational": "info",
        "none": "info",
    }
    return aliases.get(s, "info")


def _coerce_evidence(value: Any, payload: str = "") -> dict:
    if isinstance(value, dict):
        ev = dict(value)
    else:
        text = "" if value is None else str(value)
        ev = {"summary": text}

    ev.setdefault("summary", "")
    ev.setdefault("payload", payload or "")
    ev.setdefault("request", "")
    ev.setdefault("response", "")
    return ev


def _make_fingerprint(title: str, param: str, url: str) -> str:
    raw = f"{title}|{param}|{url}".encode("utf-8", errors="ignore")
    return hashlib.sha1(raw).hexdigest()[:16]


def _normalize_finding(raw: dict, index: int, default_url: str) -> dict:
    if not isinstance(raw, dict):
        raw = {"title": str(raw), "severity": "info"}

    required = {"id", "fingerprint", "category", "severity", "url", "evidence"}
    has_canonical = required.issubset(raw.keys())

    if has_canonical:
        out = dict(raw)
        out["severity"] = _coerce_severity(out.get("severity"))
        out["evidence"] = _coerce_evidence(out.get("evidence"), out.get("payload", ""))
        return out

    title = raw.get("title") or raw.get("type") or raw.get("name") or f"Finding #{index + 1}"
    param = str(raw.get("param") or raw.get("parameter") or "")
    url = str(raw.get("url") or raw.get("target") or default_url or "")
    payload = str(raw.get("payload") or "")
    severity = _coerce_severity(raw.get("severity"))

    return {
        "id": raw.get("id") or f"F-{index + 1:04d}",
        "fingerprint": raw.get("fingerprint") or _make_fingerprint(title, param, url),
        "category": raw.get("category") or _infer_category(title),
        "severity": severity,
        "url": url,
        "title": title,
        "description": raw.get("description") or raw.get("desc") or "",
        "param": param,
        "payload": payload,
        "evidence": _coerce_evidence(raw.get("evidence"), payload),
        "remediation": raw.get("remediation") or "",
        "cwe": raw.get("cwe") or "",
        "owasp": raw.get("owasp") or "",
        "tags": raw.get("tags") or [],
    }


def _load_workspace(workspace: Path) -> ReportContext:
    if not workspace.exists():
        raise typer.BadParameter(f"workspace not found: {workspace}")

    scan_json = workspace / "scan.json"
    findings_json = workspace / "findings.json"
    if not scan_json.exists():
        raise typer.BadParameter(f"scan.json not found in {workspace}")

    try:
        data = json.loads(scan_json.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"scan.json is not valid JSON: {exc}") from exc

    findings_data: list[dict] = []
    if findings_json.exists():
        try:
            findings_data = json.loads(findings_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            findings_data = []
    else:
        findings_data = data.get("findings", []) or []

    default_url = str(data.get("target") or data.get("final_url") or "")

    findings: list[Finding] = []
    skipped: list[str] = []
    for i, raw in enumerate(findings_data):
        normalized = _normalize_finding(raw, i, default_url)
        try:
            findings.append(Finding.model_validate(normalized))
        except Exception as exc:  # noqa: BLE001
            skipped.append(f"#{i + 1} ({normalized.get('title', '?')}): {exc}")

    if skipped:
        console.print(
            f"[yellow][!] Skipped {len(skipped)} malformed finding(s):[/yellow]"
        )
        for line in skipped[:5]:
            console.print(f"    [dim]{line}[/dim]")
        if len(skipped) > 5:
            console.print(f"    [dim]... {len(skipped) - 5} more[/dim]")

    scope = data.get("scope") or {}
    meta = ReportMeta(
        project_name=data.get("project") or workspace.parent.name,
        scan_id=data.get("scan_id", workspace.name),
        target=data.get("target", "—"),
        started_at=data.get("started_at", "—"),
        finished_at=data.get("finished_at") or isoformat(),
    )

    return ReportContext(
        meta=meta,
        scope_include=scope.get("include", []),
        scope_exclude=scope.get("exclude", []),
        findings=findings,
        recon=data.get("recon") or {},
        discovery=data.get("discovery_stats") or data.get("discovery") or {},
        stats=data.get("analysis") or data.get("stats") or {},
        module_errors=data.get("module_errors") or {},
    )


def _generate_from_workspace(
    workspace: Path,
    formats: str,
    output_dir: Path | None,
) -> list[Path]:
    ctx = _load_workspace(workspace)
    target_dir = output_dir or (workspace / "reports")
    target_dir.mkdir(parents=True, exist_ok=True)

    wanted = {f.strip().lower() for f in formats.split(",") if f.strip()}
    written: list[Path] = []

    if "json" in wanted:
        written.append(json_report.render(ctx, target_dir / "report.json"))
    if "md" in wanted or "markdown" in wanted:
        written.append(markdown_report.render(ctx, target_dir / "report.md"))
    if "html" in wanted:
        written.append(html_report.render(ctx, target_dir / "report.html"))
    if "pdf" in wanted:
        try:
            written.append(pdf_report.render(ctx, target_dir / "report.pdf"))
        except RuntimeError as exc:
            console.print(f"[yellow]pdf skipped:[/yellow] {exc}")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]pdf skipped:[/yellow] {type(exc).__name__}: {exc}")

    if not written:
        console.print("[yellow][!] No reports were generated (empty format list?).[/yellow]")
        return []

    for p in written:
        console.print(f"[green]wrote[/green] {p}")

    return written


# ═══════════════════════════════════════════════════════════════
#  CLI command
# ═══════════════════════════════════════════════════════════════

@app.command("generate", help="Generate reports from DB or workspace.")
def generate(
    scan_id: int | None = typer.Option(
        None, "--id", "-i",
        help="Scan ID from database (recommended). If omitted, a picker appears.",
    ),
    workspace: Path | None = typer.Option(
        None, "--workspace", "-w",
        help="Legacy: filesystem workspace directory containing scan.json.",
    ),
    formats: str = typer.Option(
        "json,md,html,pdf",
        "--format", "-f",
        help="Comma-separated: json, md, html, pdf.",
    ),
    output_dir: Path | None = typer.Option(
        None, "--out",
        help="Output directory. Defaults to ~/.spiderforge/reports/<id>/.",
    ),
) -> None:
    setup_logging()

    # 1) Explicit scan_id
    if scan_id is not None:
        generate_for_scan_id(scan_id, formats=formats, output_dir=output_dir)
        return

    # 2) Explicit workspace (legacy)
    if workspace is not None:
        _generate_from_workspace(workspace, formats, output_dir)
        return

    # 3) No args → interactive picker (DB)
    picked = show_scan_picker()
    if picked is not None:
        generate_for_scan_id(picked, formats=formats, output_dir=output_dir)
        return

    console.print("[yellow]No scan selected.[/yellow]")
    raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
