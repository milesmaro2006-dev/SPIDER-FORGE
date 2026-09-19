"""CLI: spiderforge anonymity — manage anonymity/privacy features."""

from __future__ import annotations

import json
from dataclasses import asdict

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from spiderforge.anonymity.fingerprint import (
    tls_fingerprint_capability,
)
from spiderforge.anonymity.proxy import validate_proxy_url
from spiderforge.config.anonymity_config import (
    ANONYMITY_CONFIG_PATH,
    AnonymityConfig,
    load_anonymity_config,
    reset_anonymity_config,
    save_anonymity_config,
)

app = typer.Typer(
    name="anonymity",
    help="Manage anonymity/privacy features (proxy, Tor, UA, DoH, ...).",
    add_completion=False,
)
console = Console()


def _print_config(cfg: AnonymityConfig) -> None:
    table = Table(
        title="Anonymity Configuration",
        title_style="bold cyan",
        header_style="bold cyan",
        show_lines=False,
    )
    table.add_column("Setting", style="white")
    table.add_column("Value", style="dim")
    table.add_column("On", justify="center")

    def _yn(value: bool) -> str:
        return "[green]✓[/green]" if value else "[red]·[/red]"

    table.add_row("enabled", str(cfg.enabled), _yn(cfg.enabled))
    table.add_row("proxy_url", cfg.proxy_url or "—", _yn(bool(cfg.proxy_url)))
    table.add_row("socks5_url", cfg.socks5_url or "—", _yn(bool(cfg.socks5_url)))
    table.add_row("tor", "on" if cfg.tor else "off", _yn(cfg.tor))
    table.add_row("rotate_user_agent", str(cfg.rotate_user_agent), _yn(cfg.rotate_user_agent))
    table.add_row("user_agent", cfg.user_agent or "—", _yn(bool(cfg.user_agent)))
    table.add_row("ua_pool_size", str(len(cfg.user_agent_pool)), _yn(bool(cfg.user_agent_pool)))
    table.add_row("strip_identity_headers", str(cfg.strip_identity_headers), _yn(cfg.strip_identity_headers))
    table.add_row("stripped_headers", str(len(cfg.stripped_headers)), _yn(bool(cfg.stripped_headers)))
    table.add_row("strip_referrer", str(cfg.strip_referrer), _yn(cfg.strip_referrer))
    table.add_row("referrer_policy", cfg.referrer_policy, _yn(True))
    table.add_row("doh_enabled", str(cfg.doh_enabled), _yn(cfg.doh_enabled))
    table.add_row("doh_url", cfg.doh_url, _yn(bool(cfg.doh_url)))
    table.add_row("pacing_enabled", str(cfg.pacing_enabled), _yn(cfg.pacing_enabled))
    table.add_row("pacing_min/max", f"{cfg.pacing_min}/{cfg.pacing_max}", _yn(cfg.pacing_enabled))
    table.add_row("cookie_isolation", str(cfg.cookie_isolation), _yn(cfg.cookie_isolation))
    table.add_row("tls_fingerprint", cfg.tls_fingerprint or "—", _yn(bool(cfg.tls_fingerprint)))

    console.print(table)
    console.print(f"[dim]Config file: {ANONYMITY_CONFIG_PATH}[/dim]")


@app.command("show", help="Show the current anonymity configuration.")
def show(json_out: bool = typer.Option(False, "--json", help="Emit JSON.")) -> None:
    cfg = load_anonymity_config()
    if json_out:
        print(json.dumps(asdict(cfg), indent=2, default=str))
    else:
        _print_config(cfg)


@app.command("enable", help="Enable anonymity features (uses saved config).")
def enable() -> None:
    cfg = load_anonymity_config()
    if not (cfg.proxy_url or cfg.socks5_url or cfg.tor):
        console.print(
            "[yellow][!] No proxy / SOCKS5 / Tor configured.[/yellow]\n"
            "[dim]Set one first:[/dim]\n"
            "  [cyan]spiderforge anonymity set-proxy <url>[/cyan]\n"
            "  [cyan]spiderforge anonymity set-tor[/cyan]"
        )
        raise typer.Exit(code=1)
    cfg.enabled = True
    save_anonymity_config(cfg)
    console.print(f"[green][OK][/green] Anonymity enabled → {ANONYMITY_CONFIG_PATH}")


@app.command("disable", help="Disable anonymity (config is preserved).")
def disable() -> None:
    cfg = load_anonymity_config()
    cfg.enabled = False
    save_anonymity_config(cfg)
    console.print("[green][OK][/green] Anonymity disabled.")


@app.command("set-proxy", help="Set an HTTP/HTTPS proxy URL.")
def set_proxy(url: str = typer.Argument(..., help="e.g. http://127.0.0.1:8080")) -> None:
    ok, reason = validate_proxy_url(url)
    if not ok:
        console.print(f"[red][!] Invalid proxy URL:[/red] {reason}")
        raise typer.Exit(code=2)
    cfg = load_anonymity_config()
    cfg.proxy_url = url
    # Mutual exclusion — a specific proxy overrides Tor / SOCKS5.
    cfg.socks5_url = ""
    cfg.tor = False
    cfg.enabled = True
    save_anonymity_config(cfg)
    console.print(
        f"[green][OK][/green] proxy_url = {url}\n"
        "[dim]Cleared socks5_url and tor (they take priority otherwise).[/dim]"
    )


@app.command("set-socks5", help="Set a SOCKS5 proxy URL.")
def set_socks5(url: str = typer.Argument(..., help="e.g. socks5://127.0.0.1:1080")) -> None:
    ok, reason = validate_proxy_url(url)
    if not ok:
        console.print(f"[red][!] Invalid SOCKS5 URL:[/red] {reason}")
        raise typer.Exit(code=2)
    if not url.startswith("socks5"):
        console.print("[red][!] Expected socks5:// or socks5h://[/red]")
        raise typer.Exit(code=2)
    cfg = load_anonymity_config()
    cfg.socks5_url = url
    cfg.proxy_url = ""
    cfg.tor = False
    cfg.enabled = True
    save_anonymity_config(cfg)
    console.print(
        f"[green][OK][/green] socks5_url = {url}\n"
        "[dim]Cleared proxy_url and tor (they take priority otherwise).[/dim]"
    )


@app.command("set-tor", help="Route all traffic through a local Tor SOCKS5 proxy.")
def set_tor(
    clear_others: bool = typer.Option(
        True, "--clear/--keep",
        help="Clear other proxy URLs (recommended).",
    ),
) -> None:
    cfg = load_anonymity_config()
    if clear_others:
        cfg.proxy_url = ""
        cfg.socks5_url = ""
    cfg.tor = True
    cfg.enabled = True
    save_anonymity_config(cfg)
    console.print(
        "[green][OK][/green] Tor enabled (socks5://127.0.0.1:9050)\n"
        "[dim]Ensure Tor is running:[/dim] [cyan]sudo systemctl start tor[/cyan]"
    )


@app.command("set-ua", help="Configure User-Agent rotation.")
def set_ua(
    rotate: bool = typer.Option(True, "--rotate/--no-rotate"),
    fixed: str | None = typer.Option(
        None, "--fixed", help="Use a single fixed UA instead of rotation."
    ),
) -> None:
    cfg = load_anonymity_config()
    if fixed:
        cfg.user_agent = fixed
        cfg.rotate_user_agent = False
        console.print(f"[green][OK][/green] User-Agent fixed: {fixed}")
    else:
        cfg.rotate_user_agent = rotate
        cfg.user_agent = ""
        console.print(
            f"[green][OK][/green] User-Agent rotation: {'on' if rotate else 'off'}"
        )
    save_anonymity_config(cfg)


@app.command("set-doh", help="Enable/disable DNS-over-HTTPS.")
def set_doh(
    enable: bool = typer.Option(True, "--enable/--disable"),
    url: str = typer.Option(
        "https://cloudflare-dns.com/dns-query", "--url",
        help="DoH endpoint URL.",
    ),
) -> None:
    cfg = load_anonymity_config()
    cfg.doh_enabled = enable
    cfg.doh_url = url
    save_anonymity_config(cfg)
    console.print(
        f"[green][OK][/green] DoH {'enabled' if enable else 'disabled'} → {url}"
    )


@app.command("set-pacing", help="Random delay between requests.")
def set_pacing(
    enable: bool = typer.Option(True, "--enable/--disable"),
    minimum: float = typer.Option(0.5, "--min"),
    maximum: float = typer.Option(2.0, "--max"),
) -> None:
    if minimum < 0 or maximum < minimum:
        console.print("[red][!] Invalid range: need 0 ≤ min ≤ max[/red]")
        raise typer.Exit(code=2)
    cfg = load_anonymity_config()
    cfg.pacing_enabled = enable
    cfg.pacing_min = minimum
    cfg.pacing_max = maximum
    save_anonymity_config(cfg)
    console.print(
        f"[green][OK][/green] Pacing {'on' if enable else 'off'} "
        f"({minimum}–{maximum}s)"
    )


@app.command("set-cookie-isolation", help="Enable/disable per-origin cookie isolation.")
def set_cookie_isolation(
    enable: bool = typer.Option(True, "--enable/--disable"),
) -> None:
    cfg = load_anonymity_config()
    cfg.cookie_isolation = enable
    save_anonymity_config(cfg)
    console.print(
        f"[green][OK][/green] Cookie isolation {'on' if enable else 'off'}"
    )


@app.command("set-fingerprint", help="Configure TLS fingerprint impersonation.")
def set_fingerprint(
    profile: str = typer.Argument(..., help="Profile name (see `list-profiles`)."),
) -> None:
    cap = tls_fingerprint_capability(profile, force=True)
    if not cap.available:
        console.print(
            f"[red][!] TLS fingerprint unavailable:[/red] {cap.reason}"
        )
        raise typer.Exit(code=2)
    cfg = load_anonymity_config()
    cfg.tls_fingerprint = profile
    save_anonymity_config(cfg)
    console.print(f"[green][OK][/green] tls_fingerprint = {profile}")


@app.command("list-profiles", help="Show known TLS impersonation profiles.")
def list_profiles() -> None:
    cap = tls_fingerprint_capability(force=True)
    if not cap.available:
        console.print(f"[yellow][!] curl_cffi unavailable:[/yellow] {cap.reason}")
        console.print("[dim]Install: pipx inject spiderforge curl_cffi[/dim]")
        return
    t = Table(title=f"Known profiles ({cap.engine} v{cap.version})")
    t.add_column("Profile", style="cyan")
    for p in cap.profiles:
        t.add_row(p)
    console.print(t)


@app.command("status", help="Show what the manager would actually enable.")
def status() -> None:
    from spiderforge.anonymity.manager import AnonymityManager

    cfg = load_anonymity_config()
    mgr = AnonymityManager(cfg)
    s = mgr.status()
    d = s.to_dict()
    print(json.dumps(d, indent=2, default=str))


@app.command("reset", help="Reset anonymity config to defaults.")
def reset(yes: bool = typer.Option(False, "--yes", "-y")) -> None:
    if not yes:
        confirm = typer.confirm("Delete the anonymity config file?")
        if not confirm:
            console.print("[dim]Cancelled.[/dim]")
            return
    reset_anonymity_config()
    console.print("[green][OK][/green] Anonymity config reset.")


@app.command("test", help="Quick self-test of the anonymity pipeline.")
def test_anonymity() -> None:
    """Run a fast self-test without making network requests."""
    import asyncio

    from spiderforge.anonymity.manager import AnonymityManager
    from spiderforge.anonymity.user_agents import UserAgentRotator

    cfg = load_anonymity_config()
    mgr = AnonymityManager(cfg)

    console.print(Panel("[bold cyan]Anonymity Self-Test[/bold cyan]", border_style="cyan"))
    console.print(f"enabled:              {mgr.is_active}")
    console.print(f"proxy_url:            {mgr.proxy_url or '—'}")
    console.print(f"skip_peer_ip_check:   {mgr.should_skip_peer_ip_check()}")
    console.print(f"cookie_isolation:     {mgr.cookie_isolation_enabled}")

    if cfg.rotate_user_agent:
        rot = UserAgentRotator()
        samples = [rot.next() for _ in range(3)]
        console.print("UA rotation samples:")
        for s in samples:
            console.print(f"  [dim]{s[:80]}...[/dim]")

    if mgr.is_active and mgr._pacing is not None:
        delay = asyncio.new_event_loop().run_until_complete(mgr.apply_pacing())
        console.print(f"pacing sample delay:  {delay:.3f}s")

    headers = {
        "User-Agent": "x",
        "X-Forwarded-For": "1.2.3.4",
        "Via": "1.1 proxy",
        "Referer": "https://attacker.example/",
    }
    cleaned = mgr.prepare_headers("https://target.example/", headers)
    console.print("headers after sanitization:")
    for k, v in cleaned.items():
        console.print(f"  [cyan]{k}[/cyan]: {v}")

    console.print("[green][OK][/green] Self-test complete.")


if __name__ == "__main__":
    app()
