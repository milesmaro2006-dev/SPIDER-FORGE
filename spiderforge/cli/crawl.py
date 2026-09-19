from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from spiderforge.config.loader import load_config
from spiderforge.core.events import Event, EventBus, EventType
from spiderforge.crawler.engine import CrawlResult, crawl
from spiderforge.scope.parser import default_scope_for, load_scope
from spiderforge.scope.validator import ScopeValidator
from spiderforge.utils.logging import get_logger, setup_logging
from spiderforge.utils.timestamps import isoformat

app = typer.Typer(name="crawl", help="Async crawler: links, forms, params, JS, API hints.")
console = Console()
log = get_logger("cli.crawl")


@app.command("run", help="Crawl a target and report the discovered attack surface.")
def crawl_run(
    target: str = typer.Argument(..., help="Seed URL (http/https)."),
    scope_file: Path | None = typer.Option(
        None, "--scope", help="Scope YAML. If omitted, derived from target host."
    ),
    profile: str = typer.Option("balanced", "--profile", help="Config profile."),
    depth: int | None = typer.Option(None, "--depth", help="Max crawl depth."),
    concurrency: int | None = typer.Option(None, "--concurrency", help="Worker count."),
    timeout: float | None = typer.Option(None, "--timeout", help="Request timeout (s)."),
    max_urls: int | None = typer.Option(None, "--max-urls", help="Max URLs to visit."),
    rate_limit: float | None = typer.Option(
        None, "--rate-limit", help="Max requests per second (0 = unlimited)."
    ),
    delay: float = typer.Option(0.0, "--delay", help="Fixed delay between requests (s)."),
    user_agent: str | None = typer.Option(None, "--user-agent", help="Override User-Agent."),
    verify_tls: bool = typer.Option(
        True, "--verify-tls/--no-verify-tls", help="Verify TLS certificates."
    ),
    no_redirects: bool = typer.Option(
        False, "--no-redirects", help="Do not follow redirects."
    ),
    json_out: Path | None = typer.Option(None, "--json", help="Write results to JSON."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress events."),
    debug: bool = typer.Option(False, "--debug", help="Verbose logging."),
) -> None:
    """Run the crawler end-to-end."""
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

    # ---------- Effective options ----------
    eff_depth = depth if depth is not None else cfg.scanner.max_depth
    eff_conc = concurrency if concurrency is not None else cfg.scanner.concurrency
    eff_timeout = timeout if timeout is not None else cfg.scanner.timeout
    eff_max_urls = max_urls if max_urls is not None else cfg.scanner.max_urls
    eff_rate = rate_limit if rate_limit is not None else cfg.scanner.rate_limit
    eff_ua = user_agent or cfg.scanner.user_agent

    # ---------- Event stream ----------
    bus = EventBus()
    counter = {"fetched": 0, "discovered": 0, "oos": 0}

    if not quiet:
        def _on_event(ev: Event) -> None:
            if ev.type == EventType.URL_FETCHED:
                counter["fetched"] += 1
                if counter["fetched"] % 25 == 0:
                    console.print(
                        f"[dim]fetched {counter['fetched']} pages "
                        f"(discovered {counter['discovered']}, oos {counter['oos']})[/dim]"
                    )
            elif ev.type == EventType.URL_DISCOVERED:
                counter["discovered"] += 1
            elif ev.type == EventType.OUT_OF_SCOPE:
                counter["oos"] += 1
            elif ev.type == EventType.ERROR:
                console.print(f"[red]ERROR[/red] {ev.message}")

        bus.subscribe(_on_event)

    if not quiet:
        console.print(
            Panel.fit(
                f"[bold cyan]SpiderForge Crawl[/bold cyan]\n"
                f"Seed:        {target}\n"
                f"Project:     {scope_cfg.project.name}\n"
                f"Depth:       {eff_depth}\n"
                f"Concurrency: {eff_conc}\n"
                f"Max URLs:    {eff_max_urls}\n"
                f"Profile:     {profile}",
                border_style="cyan",
            )
        )

    try:
        result = asyncio.run(
            crawl(
                target,
                scope=scope,
                bus=bus,
                concurrency=eff_conc,
                max_depth=eff_depth,
                max_urls=eff_max_urls,
                timeout=eff_timeout,
                rate_limit=eff_rate,
                delay=delay,
                user_agent=eff_ua,
                verify_tls=verify_tls,
                follow_redirects=not no_redirects,
            )
        )
    except KeyboardInterrupt:
        console.print("[red]aborted[/red]")
        raise typer.Exit(code=130) from None
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]fatal:[/red] {exc}")
        raise typer.Exit(code=1) from None

    _print_summary(result)

    if json_out:
        payload = {
            "generated_at": isoformat(),
            **result.to_dict(),
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
        json_out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        console.print(f"[green]wrote[/green] {json_out}")


def _print_summary(result: CrawlResult) -> None:
    stats = result.stats or {}

    console.rule("[bold]Crawl summary")
    t = Table(show_header=False, box=None)
    t.add_row("URLs visited", str(stats.get("urls_visited", 0)))
    t.add_row("URLs discovered", str(stats.get("urls_discovered", 0)))
    t.add_row("Forms", str(stats.get("forms", 0)))
    t.add_row("Parameters", str(stats.get("parameters", 0)))
    t.add_row("JavaScript files", str(stats.get("javascript", 0)))
    t.add_row("API hints", str(stats.get("api_hints", 0)))
    t.add_row("Out-of-scope", str(stats.get("out_of_scope", 0)))
    t.add_row("Errors", str(stats.get("errors", 0)))
    t.add_row("Elapsed (s)", str(stats.get("elapsed_seconds", 0)))
    console.print(t)

    # API hints
    if result.api_hints:
        console.rule("[bold]API hints")
        for h in result.api_hints[:30]:
            console.print(f"  [cyan]•[/cyan] {h}")
        if len(result.api_hints) > 30:
            console.print(f"  [dim]... {len(result.api_hints) - 30} more[/dim]")

    # Forms
    if result.forms:
        console.rule("[bold]Forms")
        t = Table()
        t.add_column("Method", style="cyan", no_wrap=True)
        t.add_column("Action")
        t.add_column("Fields", justify="right")
        t.add_column("Source", style="dim")
        for form in result.forms[:30]:
            t.add_row(form.method, form.action, str(len(form.fields)), form.source_url)
        console.print(t)
        if len(result.forms) > 30:
            console.print(f"[dim]... {len(result.forms) - 30} more[/dim]")

    # Parameters
    if result.parameters:
        console.rule("[bold]Parameters")
        t = Table()
        t.add_column("Name", style="cyan", no_wrap=True)
        t.add_column("Source", no_wrap=True)
        t.add_column("Method", no_wrap=True)
        t.add_column("URL", style="dim")
        for p in result.parameters[:40]:
            t.add_row(p.name, p.source, p.method, p.url)
        console.print(t)
        if len(result.parameters) > 40:
            console.print(f"[dim]... {len(result.parameters) - 40} more[/dim]")

    # JavaScript
    if result.javascript_urls:
        console.rule("[bold]JavaScript files")
        for js in result.javascript_urls[:30]:
            console.print(f"  [magenta]•[/magenta] {js}")
        if len(result.javascript_urls) > 30:
            console.print(f"  [dim]... {len(result.javascript_urls) - 30} more[/dim]")

    # Out-of-scope
    if result.out_of_scope:
        console.rule("[bold yellow]Out-of-scope (recorded, not fetched)")
        for oos in result.out_of_scope[:20]:
            console.print(f"  [yellow]•[/yellow] {oos}")
        if len(result.out_of_scope) > 20:
            console.print(f"  [dim]... {len(result.out_of_scope) - 20} more[/dim]")

    if result.errors:
        console.rule("[bold red]Errors")
        for e in result.errors[:20]:
            console.print(f"[red]•[/red] {e}")
