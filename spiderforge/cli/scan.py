"""CLI command: spiderforge scan

Run a full security assessment against a target using the v3 AssessmentEngine.
"""

from __future__ import annotations

import asyncio

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from spiderforge.core.engine import AssessmentEngine

app = typer.Typer(
    name="scan",
    help="Run a full security assessment against a target.",
    invoke_without_command=True,
)
console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


def _normalize_target(target: str) -> str:
    target = (target or "").strip()
    if target and not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    return target


def _make_event_printer(verbose: bool = False):
    """Return an event callback that prints progress in real time."""

    def on_event(name: str, data: dict) -> None:
        if name == "scan_started":
            console.print(f"[bold yellow][*] Scan started:[/bold yellow] {data.get('target')}")
        elif name == "recon_started":
            if verbose:
                console.print(r"[dim]\[*] Recon...[/dim]")
        elif name == "tech_detected":
            if verbose:
                console.print(
                    rf"    [dim]\[tech] {data.get('name')} {data.get('version', '')}[/dim]"
                )
        elif name == "crawl_started":
            console.print(r"[dim]\[*] Crawling...[/dim]")
        elif name == "crawl_completed":
            console.print(
                rf"    [dim]\[crawl] pages={data.get('pages')} "
                rf"endpoints={data.get('endpoints')} "
                rf"forms={data.get('forms')} "
                rf"duration={data.get('duration', 0):.1f}s[/dim]"
            )
        elif name == "crawl_failed":
            console.print(
                rf"    [bold red]\[!] Crawl failed:[/bold red] {data.get('reason')}"
            )
        elif name == "scanners_started":
            console.print(
                rf"[dim]\[*] Running scanners on {data.get('endpoints_count')} URLs...[/dim]"
            )
        elif name == "finding_created":
            sev = data.get("severity", "INFO")
            color = SEVERITY_COLORS.get(sev, "white")
            console.print(
                f"    [{color}][{sev:6s}][/{color}] {data.get('title')} — "
                f"[dim]{data.get('url')}[/dim]"
            )
        elif name in ("error", "recon_error") and verbose:
            console.print(rf"    [dim red]\[!] {data}[/dim red]")

    return on_event


def _render_report(result) -> None:
    """Print the final assessment report to the console."""
    duration = (result.end_time - result.start_time).total_seconds()

    console.print()
    console.print(Panel.fit(
        f"[bold cyan]SPIDERFORGE SCAN REPORT[/bold cyan]\n"
        f"[white]Target:[/white]           {result.target}\n"
        f"[white]Duration:[/white]         {duration:.1f}s\n"
        f"[white]Discovered URLs:[/white]  {len(result.discovered_urls)}\n"
        f"[white]Technologies:[/white]     {len(result.technologies)}\n"
        f"[white]Total Findings:[/white]   {result.summary.get('total', 0)}",
        border_style="cyan",
    ))

    # Severity summary
    if result.summary.get("total", 0) > 0:
        summary_line = "  ".join(
            f"[{SEVERITY_COLORS.get(k, 'white')}]{k}: {result.summary.get(k, 0)}[/{SEVERITY_COLORS.get(k, 'white')}]"
            for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        )
        console.print(summary_line)
        console.print()

    # Findings table
    if not result.findings:
        console.print("[green][+] No findings — target looks clean for tested payloads.[/green]")
        return

    table = Table(title="Findings", show_lines=True, header_style="bold cyan")
    table.add_column("Severity", justify="center", no_wrap=True)
    table.add_column("CVSS", justify="center", no_wrap=True)
    table.add_column("Title", overflow="fold")
    table.add_column("URL", overflow="fold", style="dim")
    table.add_column("Param", no_wrap=True)

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings = sorted(result.findings, key=lambda f: order.get(f.severity.value, 99))

    for f in findings:
        color = SEVERITY_COLORS.get(f.severity.value, "white")
        cvss = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "—"
        table.add_row(
            f"[{color}]{f.severity.value}[/{color}]",
            cvss,
            f.title,
            f.url,
            f.parameter or "-",
        )

    console.print(table)


def _render_fatal_error(result) -> None:
    """Render a clear, actionable error when the scan aborted."""
    console.print()
    console.print(Panel.fit(
        f"[bold red][!] SCAN ABORTED[/bold red]\n\n"
        f"[white]Target:[/white]  {result.target}\n"
        f"[white]Reason:[/white]  {result.error_msg}",
        border_style="red",
        title="[b]Failure[/b]",
    ))
    console.print()
    console.print("[bold yellow]Common causes:[/bold yellow]")
    console.print("  [dim]•[/dim] Proxy / Tor is not running  →  [cyan]spiderforge anonymity status[/cyan]")
    console.print("  [dim]•[/dim] Target is unreachable        →  [cyan]ping <host>[/cyan] / [cyan]curl -I <url>[/cyan]")
    console.print("  [dim]•[/dim] DNS is failing               →  [cyan]spiderforge doctor[/cyan]")
    console.print("  [dim]•[/dim] Scope rejects the target     →  [cyan]spiderforge scan run <url> --strict-scope[/cyan] (if appropriate)")
    console.print()
    console.print("[dim]No report was generated — the scan did not complete.[/dim]")


@app.command("run")
def run_command(
    target: str = typer.Argument(..., help="Target URL to assess."),
    max_urls: int = typer.Option(200, "--max-urls", help="Maximum URLs to crawl."),
    max_depth: int = typer.Option(3, "--max-depth", help="Maximum crawl depth."),
    concurrency: int = typer.Option(10, "--concurrency", help="Max concurrent HTTP requests."),
    rate_limit: float = typer.Option(20.0, "--rate", help="Max requests per second."),
    allow_private: bool = typer.Option(
        False, "--allow-private",
        help="Allow scanning private/loopback IPs (for lab targets).",
    ),
    no_verify_tls: bool = typer.Option(
        False, "--no-verify-tls",
        help="Skip TLS certificate verification (lab use only).",
    ),
    scope_free: bool = typer.Option(
        True, "--scope-free/--strict-scope",
        help=(
            "Skip hostname scope validation (default: on). "
            "SSRF / loopback / cloud-metadata protection still applies. "
            "Use --strict-scope to enforce the previous behavior."
        ),
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output."),
    anonymity: bool | None = typer.Option(
        None, "--anonymity/--no-anonymity",
        help=(
            "Force enable/disable anonymity. "
            "Default: use the saved config (if anonymity is enabled via "
            "`spiderforge anonymity enable`)."
        ),
    ),
) -> None:
    """Run a full security assessment against a target URL."""

    # Enable tracebacks on stderr only when the user asks for them.
    # By default we print a clean one-line error via the engine logger,
    # so end users see the red panel without a wall of Python internals.
    import logging
    import os as _os

    if _os.environ.get("SPIDERFORGE_DEBUG", "").strip() in {"1", "true", "yes"}:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(levelname)s %(name)s: %(message)s",
            force=True,
        )

    target = _normalize_target(target)

    # ── Anonymity: auto-load from saved config unless overridden ──
    anonymity_mgr = None
    try:
        from spiderforge.anonymity.manager import AnonymityManager
        from spiderforge.config.anonymity_config import load_anonymity_config

        cfg = load_anonymity_config()

        # CLI flag wins over config; None means "use config".
        use_anonymity = anonymity if anonymity is not None else cfg.enabled

        if use_anonymity and cfg.enabled:
            anonymity_mgr = AnonymityManager(cfg)
            console.print(
                f"[dim]→ Anonymity: proxy={anonymity_mgr.proxy_url or '—'} "
                f"ua_rotation={anonymity_mgr._ua_rotator is not None} "
                f"cookie_isolation={anonymity_mgr.cookie_isolation_enabled}[/dim]"
            )
        elif use_anonymity and not cfg.enabled:
            console.print(
                "[yellow][!] Anonymity requested but not enabled in config.[/yellow]\n"
                "[dim]Run: [cyan]spiderforge anonymity enable[/cyan][/dim]"
            )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow][!] Could not load anonymity config: {exc}[/yellow]")

    engine = AssessmentEngine(
        target_url=target,
        allow_private_targets=allow_private,
        verify_tls=not no_verify_tls,
        max_concurrency=concurrency,
        rate_limit_rps=rate_limit,
        max_urls=max_urls,
        max_depth=max_depth,
        scope_free=scope_free,
        on_event=_make_event_printer(verbose),
        anonymity=anonymity_mgr,
    )

    try:
        result = asyncio.run(engine.run())
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Scan interrupted by user.[/yellow]")
        raise typer.Exit(code=130)
    except Exception as exc:  # noqa: BLE001
        console.print(f"\n[bold red][!] Scan failed: {type(exc).__name__}: {exc}[/bold red]")
        raise typer.Exit(code=1)

    # Engine reported a fatal error — do NOT pretend everything is fine.
    if not result.success:
        _render_fatal_error(result)
        raise typer.Exit(code=1)

    _render_report(result)


@app.callback(invoke_without_command=True)
def main_callback(ctx: typer.Context) -> None:
    """Allow `spiderforge scan <url>` or `spiderforge scan run <url>`."""
    if ctx.invoked_subcommand is None:
        console.print(
            "[bold cyan]Usage:[/bold cyan] spiderforge scan run <target-url>\n"
            "[dim]Example: spiderforge scan run http://demo.testfire.net/[/dim]"
        )


if __name__ == "__main__":
    app()
