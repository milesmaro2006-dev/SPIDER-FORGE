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
from spiderforge.discovery.models import DiscoveryResult
from spiderforge.discovery.runner import run as run_discovery
from spiderforge.scope.parser import default_scope_for, load_scope
from spiderforge.scope.validator import ScopeValidator
from spiderforge.utils.logging import get_logger, setup_logging
from spiderforge.utils.timestamps import isoformat

app = typer.Typer(name="discover", help="Discovery: endpoints, params, APIs, JS, Swagger, GraphQL.")
console = Console()
log = get_logger("cli.discover")


@app.command("run", help="Run discovery on a target.")
def discover_run(
    target: str = typer.Argument(..., help="Seed URL."),
    scope_file: Path | None = typer.Option(None, "--scope", help="Scope YAML."),
    profile: str = typer.Option("balanced", "--profile", help="Config profile."),
    concurrency: int | None = typer.Option(None, "--concurrency"),
    timeout: float | None = typer.Option(None, "--timeout"),
    rate_limit: float | None = typer.Option(None, "--rate-limit"),
    user_agent: str | None = typer.Option(None, "--user-agent"),
    verify_tls: bool = typer.Option(True, "--verify-tls/--no-verify-tls"),
    no_hidden: bool = typer.Option(False, "--no-hidden", help="Skip hidden path probing."),
    no_swagger: bool = typer.Option(False, "--no-swagger"),
    no_graphql: bool = typer.Option(False, "--no-graphql"),
    no_js: bool = typer.Option(False, "--no-js"),
    max_js_files: int = typer.Option(50, "--max-js-files"),
    json_out: Path | None = typer.Option(None, "--json"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    debug: bool = typer.Option(False, "--debug"),
) -> None:
    """Run the full discovery pipeline."""
    setup_logging(level="DEBUG" if debug else "INFO", quiet=quiet)
    cfg = load_config(profile=profile)

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

    eff_conc = concurrency if concurrency is not None else cfg.scanner.concurrency
    eff_timeout = timeout if timeout is not None else cfg.scanner.timeout
    eff_rate = rate_limit if rate_limit is not None else cfg.scanner.rate_limit
    eff_ua = user_agent or cfg.scanner.user_agent

    bus = EventBus()
    if not quiet:
        def _on_event(ev: Event) -> None:
            if ev.type == EventType.SCAN_STARTED:
                console.print(f"[cyan]→[/cyan] {ev.message}")
            elif ev.type == EventType.SCAN_FINISHED:
                pass
            elif ev.type == EventType.OUT_OF_SCOPE:
                console.print(f"[yellow]OUT_OF_SCOPE[/yellow] {ev.message}")
            elif ev.type == EventType.ERROR:
                console.print(f"[red]ERROR[/red] {ev.message}")
        bus.subscribe(_on_event)

    if not quiet:
        console.print(
            Panel.fit(
                f"[bold cyan]SpiderForge Discovery[/bold cyan]\n"
                f"Target:       {target}\n"
                f"Project:      {scope_cfg.project.name}\n"
                f"Concurrency:  {eff_conc}\n"
                f"Profile:      {profile}",
                border_style="cyan",
            )
        )

    try:
        result = asyncio.run(
            run_discovery(
                target,
                scope=scope,
                bus=bus,
                concurrency=eff_conc,
                timeout=eff_timeout,
                rate_limit=eff_rate,
                user_agent=eff_ua,
                verify_tls=verify_tls,
                enable_hidden_paths=not no_hidden,
                enable_swagger=not no_swagger,
                enable_graphql=not no_graphql,
                enable_js=not no_js,
                max_js_files=max_js_files,
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
                {"type": e.type.value, "message": e.message, "timestamp": e.timestamp.isoformat()}
                for e in bus.history
            ],
        }
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        console.print(f"[green]wrote[/green] {json_out}")


def _print_summary(result: DiscoveryResult) -> None:
    stats = result.stats or {}
    console.rule("[bold]Discovery summary")
    t = Table(show_header=False, box=None)
    for k, v in stats.items():
        t.add_row(k.replace("_", " ").title(), str(v))
    console.print(t)

    if result.api_clusters:
        console.rule("[bold]API clusters")
        t = Table()
        t.add_column("Base Path", style="cyan")
        t.add_column("Kind", no_wrap=True)
        t.add_column("Endpoints", justify="right")
        t.add_column("Methods", style="dim")
        t.add_column("Auth", style="dim")
        for c in result.api_clusters[:30]:
            t.add_row(
                c.base_path,
                c.api_kind,
                str(len(c.endpoints)),
                ",".join(c.methods)[:40],
                c.auth_hint or "-",
            )
        console.print(t)

    if result.swagger_specs:
        console.rule("[bold]Swagger / OpenAPI")
        for s in result.swagger_specs:
            console.print(
                f"  [green]•[/green] {s.url} "
                f"[dim]({s.title or 'untitled'}, v{s.version}, {len(s.endpoints)} endpoints)[/dim]"
            )

    if result.graphql:
        console.rule("[bold]GraphQL")
        for g in result.graphql:
            state = "[green]introspection enabled[/green]" if g.introspection_enabled else "[dim]detected[/dim]"
            console.print(f"  • {g.url} — {state}")
            if g.schema_types:
                console.print(f"    [dim]types: {len(g.schema_types)}[/dim]")

    if result.js_findings:
        console.rule("[bold]JavaScript analysis")
        t = Table()
        t.add_column("Source", style="dim")
        t.add_column("Endpoints", justify="right")
        t.add_column("Params", justify="right")
        t.add_column("WS", justify="right")
        t.add_column("Maps", justify="right")
        t.add_column("Conf", justify="right")
        for f in result.js_findings[:30]:
            t.add_row(
                f.source_url[-60:],
                str(len(f.endpoints)),
                str(len(f.parameters)),
                str(len(f.websockets)),
                str(len(f.source_maps)),
                f"{f.confidence:.2f}",
            )
        console.print(t)

    if result.hidden_paths:
        console.rule("[bold]Hidden paths discovered")
        for p in result.hidden_paths[:40]:
            console.print(f"  [cyan]•[/cyan] {p}")
        if len(result.hidden_paths) > 40:
            console.print(f"  [dim]... {len(result.hidden_paths) - 40} more[/dim]")

    if result.parameters:
        interesting = [p for p in result.parameters if p.inferred_type not in ("string", "unknown", "empty")]
        if interesting:
            console.rule("[bold]Typed parameters")
            t = Table()
            t.add_column("Name", style="cyan")
            t.add_column("Type", no_wrap=True)
            t.add_column("Source", no_wrap=True)
            t.add_column("Conf", justify="right")
            t.add_column("URL", style="dim")
            for p in interesting[:30]:
                t.add_row(
                    p.name, p.inferred_type, p.source, f"{p.confidence:.2f}", p.url[-60:]
                )
            console.print(t)

    if result.out_of_scope:
        console.rule("[bold yellow]Out-of-scope (recorded, not fetched)")
        for o in result.out_of_scope[:20]:
            console.print(f"  [yellow]•[/yellow] {o}")

    if result.errors:
        console.rule("[bold red]Errors")
        for e in result.errors[:15]:
            console.print(f"[red]•[/red] {e}")
