# spiderforge/cli/main.py
"""SpiderForge interactive CLI."""

from __future__ import annotations

import webbrowser
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from spiderforge.cli import (
    anonymity,
    browser,
    crawl,
    discover,
    doctor,
    findings,
    history,
    integrations,
    modules,
    recon,
    report,
    scan,
    scans,
    scope,
    update,
    web,
)
from spiderforge.cli import config as config_cli

app = typer.Typer(
    name="spiderforge",
    help="Advanced Web Reconnaissance & Security Assessment Framework",
    add_completion=False,
)

app.add_typer(recon.app, name="recon")
app.add_typer(scan.app, name="scan")
app.add_typer(report.app, name="report")
app.add_typer(scans.app, name="scans")
app.add_typer(doctor.app, name="doctor")
app.add_typer(web.app, name="web")
app.add_typer(anonymity.app, name="anonymity")
app.add_typer(config_cli.app, name="config")
app.add_typer(crawl.app, name="crawl")
app.add_typer(discover.app, name="discover")
app.add_typer(browser.app, name="browser")
app.add_typer(findings.app, name="findings")
app.add_typer(history.app, name="history")
app.add_typer(integrations.app, name="integrations")
app.add_typer(modules.app, name="modules")
app.add_typer(scope.app, name="scope")
app.add_typer(update.app, name="update")

console = Console()


SCAN_DEFAULTS: dict = {
    "max_urls": 200,
    "max_depth": 3,
    "concurrency": 10,
    "rate_limit": 20.0,
    "allow_private": False,
    "no_verify_tls": False,
    "scope_free": True,
    "verbose": False,
    # ``None`` → resolve from the saved anonymity config at call time.
    "anonymity": None,
}


BANNER = """
[bold red]    ███████╗██████╗ ██╗██████╗ ███████╗██████╗ ███████╗██████╗ ██████╗  ██████╗ ███████╗
    ██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
    ███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
    ╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗██╔══╝  ██║   ██║██╔══██║██║   ██║██╔══╝
    ███████║██║     ██║██████╔╝███████╗██║  ██║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
    ╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝[/bold red]
[dim white]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim white]
[bold cyan]  [+] Framework:[/bold cyan] SpiderForge v3.0.0    [bold cyan]• Author:[/bold cyan] Spidey (@redteam)
[bold cyan]  [+] Core Engine:[/bold cyan] Async / Modular       [bold cyan]• Web Platform:[/bold cyan] http://127.0.0.1:8000
[dim white]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim white]
"""


# ═══════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════

def _normalize_target(target: str) -> str:
    target = (target or "").strip()
    if target and not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    return target


def _safe_call(fn, **kwargs) -> None:
    try:
        fn(**kwargs)
    except (typer.Exit, SystemExit):
        pass
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrupted by user.[/yellow]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red][!] {type(exc).__name__}: {exc}[/bold red]")


def _open_in_browser(target_file: Path) -> None:
    try:
        uri = target_file.as_uri()
    except ValueError:
        console.print(f"[yellow][!] Cannot build URI for: {target_file}[/yellow]")
        return
    try:
        opened = webbrowser.open(uri, new=2)
        if not opened:
            console.print("[yellow][!] No browser accepted the request.[/yellow]")
            console.print(f"[dim]Open manually: {target_file}[/dim]")
            return
        console.print(f"[green][OK] Opened:[/green] {target_file}")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow][!] Could not open browser: {exc}[/yellow]")
        console.print(f"[dim]Open manually: {target_file}[/dim]")


def _offer_open_reports(files: list) -> None:
    """Offer to open generated reports (PDF / HTML / both)."""
    if not files:
        return

    pdf = next((f for f in files if f.suffix.lower() == ".pdf"), None)
    html = next((f for f in files if f.suffix.lower() == ".html"), None)

    if not pdf and not html:
        return

    console.print("\n[bold cyan]Open report in browser?[/bold cyan]")
    if pdf:
        console.print("  [P] PDF")
    if html:
        console.print("  [H] HTML")
    if pdf and html:
        console.print("  [B] Both")
    console.print("  [N] Skip")

    valid = []
    if pdf:
        valid.append("p")
    if html:
        valid.append("h")
    if pdf and html:
        valid.append("b")
    valid.append("n")

    default = valid[0]
    choice = Prompt.ask("Choice", choices=valid, default=default).lower()

    if choice == "n":
        return
    if choice == "b" and pdf and html:
        _open_in_browser(pdf)
        _open_in_browser(html)
        return
    target = pdf if choice == "p" else html
    if target:
        _open_in_browser(target)


# ═══════════════════════════════════════════════════════════════
#  Interactive menu
# ═══════════════════════════════════════════════════════════════

def _version_callback(value: bool) -> None:
    """Print the SpiderForge version and exit."""
    if not value:
        return
    try:
        from spiderforge import __version__ as _v
    except ImportError:
        _v = "3.0.0"
    console.print(f"[bold cyan]SpiderForge[/bold cyan] v{_v}")
    raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        None,
        "--version", "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
):
    if ctx.invoked_subcommand is not None:
        return

    while True:
        console.clear()
        console.print(BANNER)
        console.print(
            Panel(
                "[bold green]Welcome to SpiderForge Interactive Control Center[/bold green]\n"
                "[dim]Choose an operation. Each option is explained below.[/dim]",
                title="[b]Interactive Mode[/b]",
                border_style="red",
            )
        )

        console.print("[bold cyan][1][/bold cyan] 🎯 [white]Run Full Assessment (Scan)[/white]")
        console.print("    [dim]→ Crawl the target, run every scanner, and save the report.[/dim]")

        console.print("[bold cyan][2][/bold cyan] 🌐 [white]Launch Web Dashboard (GUI - Persistent)[/white]")
        console.print("    [dim]→ Start the web UI at http://127.0.0.1:8000 (keeps running).[/dim]")

        console.print("[bold cyan][3][/bold cyan] 🔍 [white]Run Reconnaissance Only[/white]")
        console.print("    [dim]→ DNS, HTTP headers, technologies, robots.txt, sitemap (no scan).[/dim]")

        console.print("[bold cyan][4][/bold cyan] 📊 [white]Generate Reports[/white]")
        console.print("    [dim]→ Build JSON / Markdown / HTML / PDF reports from a previous scan.[/dim]")

        console.print("[bold cyan][5][/bold cyan] 🩺 [white]Run System Diagnostics (Doctor)[/white]")
        console.print("    [dim]→ Verify Python, libraries, tools, storage, and network.[/dim]")

        console.print("[bold cyan][6][/bold cyan] 🚪 [white]Exit[/white]")
        console.print("    [dim]→ Leave the interactive menu.[/dim]")

        console.print()
        choice = Prompt.ask(
            "[bold yellow]Select an option[/bold yellow]",
            choices=["1", "2", "3", "4", "5", "6"],
            default="1",
        )

        # ── 1) Full Assessment ───────────────────────────────────
        if choice == "1":
            target = Prompt.ask("[bold cyan]Enter target URL (e.g., http://example.com)[/bold cyan]")
            target = _normalize_target(target)
            if target:
                console.print(f"[bold green][*] Launching full assessment on {target}...[/bold green]")
                _safe_call(scan.run_command, target=target, **SCAN_DEFAULTS)
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        # ── 2) Web Dashboard (delegated to spiderforge.cli.web) ──
        elif choice == "2":
            _safe_call(web.launch_web)
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        # ── 3) Recon ─────────────────────────────────────────────
        elif choice == "3":
            target = Prompt.ask("[bold cyan]Enter target URL for recon[/bold cyan]")
            target = _normalize_target(target)
            if target:
                console.print(f"[bold green][*] Running reconnaissance on {target}...[/bold green]")
                _safe_call(
                    recon.recon_run,
                    target=target,
                    profile="balanced",
                    scope_file=None,
                    timeout=20.0,
                    user_agent=None,
                    verify_tls=True,
                    no_sitemaps=False,
                    json_out=None,
                    quiet=False,
                    debug=False,
                )
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        # ── 4) Reports ───────────────────────────────────────────
        elif choice == "4":
            console.rule("[bold cyan]Report Generator[/bold cyan]")

            scan_id = report.show_scan_picker(limit=20)
            if scan_id is None:
                console.print("[yellow][!] No scan selected — returning to menu.[/yellow]")
                Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")
                continue

            console.print(f"[bold green][*] Generating reports for scan #{scan_id}...[/bold green]")
            try:
                written = report.generate_for_scan_id(
                    scan_id,
                    formats="json,md,html,pdf",
                    output_dir=None,
                )
            except Exception as exc:  # noqa: BLE001
                console.print(f"[bold red][!] Report failed: {type(exc).__name__}: {exc}[/bold red]")
                written = []

            if written:
                _offer_open_reports(written)
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        # ── 5) Doctor ────────────────────────────────────────────
        elif choice == "5":
            console.rule("[bold cyan]System Health Check[/bold cyan]")
            try:
                code = doctor.doctor_run()
                if code == 0:
                    console.print("[bold green][OK] System is ready for scanning.[/bold green]")
                elif code == 1:
                    console.print("[bold yellow][!] System is functional but degraded — review warnings above.[/bold yellow]")
                else:
                    console.print("[bold red][!] Action required — fix FAIL items before scanning.[/bold red]")
            except Exception as exc:  # noqa: BLE001
                console.print(f"[bold red][!] Doctor crashed: {type(exc).__name__}: {exc}[/bold red]")
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        # ── 6) Exit ──────────────────────────────────────────────
        elif choice == "6":
            console.print("[bold red][!] Exiting SpiderForge CLI. (Web server stays active if running)[/bold red]")
            raise typer.Exit()


if __name__ == "__main__":
    app()
