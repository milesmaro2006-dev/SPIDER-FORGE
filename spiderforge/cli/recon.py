from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from spiderforge.cli._utils import resolve
from spiderforge.config.loader import load_config
from spiderforge.core.events import Event, EventBus, EventType
from spiderforge.recon.runner import ReconResult
from spiderforge.recon.runner import run as run_recon
from spiderforge.scope.parser import default_scope_for, load_scope
from spiderforge.scope.validator import ScopeValidator
from spiderforge.utils.logging import get_logger, setup_logging
from spiderforge.utils.timestamps import isoformat

app = typer.Typer(name="recon", help="Reconnaissance: DNS, HTTP, tech, robots, sitemap.")
console = Console()
log = get_logger("cli.recon")


@app.command("run", help="Run reconnaissance against a target.")
def recon_run(
    target: str = typer.Argument(..., help="Target URL or host (http/https)."),
    scope_file: Path | None = typer.Option(
        None, "--scope", help="Scope YAML file. If omitted, a scope is derived from the target host."
    ),
    profile: str = typer.Option("balanced", "--profile", help="Config profile."),
    timeout: float = typer.Option(20.0, "--timeout", help="Request timeout (seconds)."),
    user_agent: str | None = typer.Option(None, "--user-agent", help="Override User-Agent."),
    verify_tls: bool = typer.Option(
        True, "--verify-tls/--no-verify-tls", help="Verify TLS certificates."
    ),
    no_sitemaps: bool = typer.Option(False, "--no-sitemaps", help="Skip sitemap fetching."),
    json_out: Path | None = typer.Option(None, "--json", help="Write raw results to JSON."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only show errors."),
    debug: bool = typer.Option(False, "--debug", help="Verbose logging."),
) -> None:
    """Run the full recon pipeline and print a report."""

    # ── Defuse Typer OptionInfo/ArgumentInfo when called programmatically ──
    target      = resolve(target, "") or ""
    scope_file  = resolve(scope_file)
    profile     = resolve(profile, "balanced")
    timeout     = float(resolve(timeout, 20.0))
    user_agent  = resolve(user_agent)
    verify_tls  = bool(resolve(verify_tls, True))
    no_sitemaps = bool(resolve(no_sitemaps, False))
    json_out    = resolve(json_out)
    quiet       = bool(resolve(quiet, False))
    debug       = bool(resolve(debug, False))

    # ── URL normalization ──
    if not target:
        console.print("[red]error[/red] target URL is required.")
        raise typer.Exit(code=2)
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    setup_logging(level="DEBUG" if debug else "INFO", quiet=quiet)
    cfg = load_config(profile=profile)

    # ---------- Scope ----------
    if scope_file:
        scope_cfg = load_scope(scope_file)
    else:
        host = target.split("://")[-1].split("/")[0].split(":")[0]
        scope_cfg = default_scope_for(host)
        if not quiet:
            console.print(
                f"[yellow]note[/yellow] no --scope provided; auto-scope for [bold]{host}[/bold]"
            )

    scope = ScopeValidator(scope_cfg)

    # ---------- Event stream ----------
    bus = EventBus()
    if not quiet:
        def _on_event(ev: Event) -> None:
            if ev.type == EventType.TECHNOLOGY_FOUND:
                return  # printed later in a table
            if ev.type == EventType.OUT_OF_SCOPE:
                console.print(f"[yellow]OUT_OF_SCOPE[/yellow] {ev.message}")
            elif ev.type == EventType.ERROR:
                console.print(f"[red]ERROR[/red] {ev.message}")
            else:
                console.print(f"[dim]{ev.type.value:14s}[/dim] {ev.message}")
        bus.subscribe(_on_event)

    if not quiet:
        console.print(
            Panel.fit(
                f"[bold cyan]SpiderForge Recon[/bold cyan]\n"
                f"Target:   {target}\n"
                f"Project:  {scope_cfg.project.name}\n"
                f"Include:  {', '.join(scope_cfg.include) or '(none)'}\n"
                f"Exclude:  {', '.join(scope_cfg.exclude) or '(none)'}\n"
                f"Profile:  {profile}",
                border_style="cyan",
            )
        )

    # ── Resolve UA safety net ──
    ua = user_agent or getattr(cfg.scanner, "user_agent", None) or "SpiderForge/2.0"
    if not isinstance(ua, str):
        ua = str(ua)

    try:
        result = asyncio.run(
            run_recon(
                target,
                scope=scope,
                bus=bus,
                timeout=timeout,
                user_agent=ua,
                verify_tls=verify_tls,
                fetch_sitemaps=not no_sitemaps,
            )
        )
    except KeyboardInterrupt:
        console.print("[red]aborted[/red]")
        raise typer.Exit(code=130) from None
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]error[/red] {type(exc).__name__}: {exc}")
        raise typer.Exit(code=1) from exc

    _print_summary(result)

    if json_out:
        payload = {
            "generated_at": isoformat(),
            "target": result.target,
            "final_url": result.final_url,
            "dns": result.dns,
            "http": result.http,
            "technologies": result.technologies,
            "robots": result.robots,
            "sitemaps": result.sitemaps,
            "errors": result.errors,
            "events": [
                {
                    "type": e.type.value,
                    "message": e.message,
                    "timestamp": e.timestamp.isoformat(),
                }
                for e in bus.history
            ],
        }
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(
            json.dumps(payload, indent=2, default=str), encoding="utf-8"
        )
        console.print(f"[green]wrote[/green] {json_out}")


def _print_summary(result: ReconResult) -> None:
    # HTTP
    console.rule("[bold]HTTP")
    http = result.http or {}
    if http.get("error"):
        console.print(f"[red]error:[/red] {http['error']}")
    else:
        t = Table(show_header=False, box=None)
        t.add_row("URL", str(http.get("final_url") or result.target))
        t.add_row("Status", str(http.get("status_code")))
        t.add_row("Server", str(http.get("server") or "-"))
        t.add_row("Title", str(http.get("title") or "-"))
        t.add_row("Content-Type", str(http.get("content_type") or "-"))
        t.add_row("Size", str(http.get("content_length") or "-"))
        t.add_row("Redirects", str(len(http.get("redirects") or [])))
        tls = http.get("tls") or {}
        if tls:
            t.add_row(
                "TLS",
                f"{tls.get('version', '?')} — "
                f"{tls.get('issuer', {}).get('commonName') or tls.get('issuer', {}).get('organizationName') or '?'}",
            )
            if tls.get("notAfter"):
                t.add_row("Cert Expires", tls["notAfter"])
        console.print(t)

    # DNS
    console.rule("[bold]DNS")
    records = (result.dns or {}).get("records") or []
    if records:
        t = Table()
        t.add_column("Type", style="cyan", no_wrap=True)
        t.add_column("Value")
        for r in records[:50]:
            t.add_row(str(r.get("type", "")), str(r.get("value", "")))
        console.print(t)
        if len(records) > 50:
            console.print(f"[dim]... {len(records) - 50} more[/dim]")
    else:
        console.print("[dim]no DNS records collected[/dim]")

    # Technologies
    console.rule("[bold]Technologies")
    if result.technologies:
        t = Table()
        t.add_column("Name", style="cyan")
        t.add_column("Version")
        t.add_column("Category")
        t.add_column("Confidence", justify="right")
        t.add_column("Evidence", style="dim")
        for tech in result.technologies:
            t.add_row(
                str(tech.get("name", "")),
                str(tech.get("version") or "-"),
                str(tech.get("category", "")),
                f"{tech.get('confidence', 0):.2f}",
                str(tech.get("evidence") or "")[:60],
            )
        console.print(t)
    else:
        console.print("[dim]no technologies detected[/dim]")

    # Robots
    console.rule("[bold]Robots.txt")
    rob = result.robots or {}
    if rob.get("found"):
        console.print(f"[green]found[/green] {rob.get('url')}")
        if rob.get("disallow"):
            console.print(f"  Disallow: {len(rob['disallow'])} entries")
            for d in rob["disallow"][:10]:
                console.print(f"    [dim]{d}[/dim]")
        if rob.get("sitemaps"):
            console.print(f"  Sitemaps: {', '.join(rob['sitemaps'])}")
        if rob.get("crawl_delay") is not None:
            console.print(f"  Crawl-delay: {rob['crawl_delay']}")
    else:
        msg = rob.get("error") or f"status {rob.get('status_code')}"
        console.print(f"[dim]not found ({msg})[/dim]")

    # Sitemaps
    console.rule("[bold]Sitemaps")
    if result.sitemaps:
        for sm in result.sitemaps:
            state = (
                f"[green]{len(sm.get('urls') or [])} URLs[/green]"
                if sm.get("found")
                else "[dim]not found[/dim]"
            )
            console.print(f"  {sm.get('url')} — {state}")
            for sub in (sm.get("sub_sitemaps") or [])[:5]:
                console.print(f"    [dim]↳ sub-sitemap: {sub}[/dim]")
    else:
        console.print("[dim]none fetched[/dim]")

    # Errors
    if result.errors:
        console.rule("[bold red]Errors")
        for e in result.errors:
            console.print(f"[red]•[/red] {e}")
