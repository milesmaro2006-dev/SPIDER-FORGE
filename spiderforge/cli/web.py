"""Standalone ``spiderforge web`` launcher.

Works both from a source checkout and from a pipx-installed wheel:

- Discovers the backend package via ``importlib`` (wheel) or the CWD
  (checkout), then locates ``backend/static/frontend/index.html``.
- First-run wizard writes ``~/.spiderforge/web.toml``.
- Runs uvicorn either in the current process (``--foreground``) or as
  a detached background process (default).
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt

from spiderforge.config.web_config import (
    WEB_CONFIG_PATH,
    WebConfig,
    is_first_run,
    load_web_config,
    reset_web_config,
    save_web_config,
)

app = typer.Typer(
    name="web",
    help="Launch the SpiderForge web dashboard.",
    add_completion=False,
)

console = Console()


# ═══════════════════════════════════════════════════════════════
#  Discovery helpers
# ═══════════════════════════════════════════════════════════════

def _find_backend_root() -> Path | None:
    """Locate the directory that contains ``backend/main.py``.

    Search order:
      1. Current working directory.
      2. ``$SPIDERFORGE_ROOT``.
      3. Installed package (``importlib`` — works under pipx).
      4. Climbing up from this file (source checkout).
    """
    cwd = Path.cwd()
    if (cwd / "backend" / "main.py").is_file():
        return cwd

    env_root = os.environ.get("SPIDERFORGE_ROOT")
    if env_root:
        candidate = Path(env_root).expanduser().resolve()
        if (candidate / "backend" / "main.py").is_file():
            return candidate

    try:
        spec = importlib.util.find_spec("backend")
        if spec is not None and spec.origin:
            backend_pkg = Path(spec.origin).resolve().parent
            if (backend_pkg / "main.py").is_file():
                return backend_pkg.parent
    except Exception:
        pass

    cur = Path(__file__).resolve().parent
    for _ in range(12):
        if (cur / "backend" / "main.py").is_file():
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent

    return None


def _find_frontend_index(backend_root: Path | None) -> Path | None:
    """Locate ``index.html`` for the web UI.

    Search order:
      1. ``$SPIDERFORGE_FRONTEND_DIR``.
      2. ``<backend_root>/backend/static/frontend/index.html`` (packaged).
      3. ``<backend_root>/frontend/index.html`` (dev checkout).
      4. Installed package via ``importlib``.
    """
    env_dir = os.environ.get("SPIDERFORGE_FRONTEND_DIR")
    if env_dir:
        candidate = Path(env_dir).expanduser().resolve() / "index.html"
        if candidate.is_file():
            return candidate

    if backend_root is not None:
        for rel in (
            Path("backend") / "static" / "frontend" / "index.html",
            Path("frontend") / "index.html",
        ):
            candidate = backend_root / rel
            if candidate.is_file():
                return candidate

    try:
        spec = importlib.util.find_spec("backend")
        if spec is not None and spec.origin:
            backend_pkg = Path(spec.origin).resolve().parent
            candidate = backend_pkg / "static" / "frontend" / "index.html"
            if candidate.is_file():
                return candidate
    except Exception:
        pass

    return None


def _pick_log_path(backend_root: Path) -> Path:
    """Choose a writable log file location.

    Prefers ``<backend_root>/server.log`` (dev mode). Falls back to
    ``~/.spiderforge/web.log`` when the backend root is read-only
    (e.g. site-packages under pipx).
    """
    primary = backend_root / "server.log"
    try:
        with primary.open("a"):
            pass
        return primary
    except OSError:
        fallback_dir = Path.home() / ".spiderforge"
        fallback_dir.mkdir(parents=True, exist_ok=True)
        return fallback_dir / "web.log"


# ═══════════════════════════════════════════════════════════════
#  Health probes
# ═══════════════════════════════════════════════════════════════

def _health_ok(host: str, port: int, timeout: float = 0.7) -> bool:
    try:
        import httpx
    except ImportError:
        return False
    try:
        r = httpx.get(f"http://{host}:{port}/api/health", timeout=timeout)
        return r.status_code == 200
    except Exception:
        return False


def _wait_for_health(host: str, port: int, attempts: int = 24) -> bool:
    for _ in range(attempts):
        if _health_ok(host, port):
            return True
        time.sleep(0.5)
    return False


# ═══════════════════════════════════════════════════════════════
#  First-run wizard
# ═══════════════════════════════════════════════════════════════

def _first_run_wizard() -> WebConfig:
    """Prompt the user for their initial web preferences."""
    console.print(
        Panel(
            "[bold cyan]Welcome to the SpiderForge Web Dashboard[/bold cyan]\n\n"
            "Let's set a few preferences before we start.\n"
            f"[dim]Saved to: {WEB_CONFIG_PATH}[/dim]",
            border_style="cyan",
            title="First-run setup",
        )
    )

    port = IntPrompt.ask("[cyan]Port[/cyan]", default=8000)
    while not (1 <= port <= 65535):
        console.print("[red]Port must be between 1 and 65535.[/red]")
        port = IntPrompt.ask("[cyan]Port[/cyan]", default=8000)

    auto_open = Confirm.ask(
        "[cyan]Open the browser automatically?[/cyan]",
        default=True,
    )

    cfg = WebConfig(
        host="127.0.0.1",
        port=port,
        auto_open_browser=auto_open,
        theme="dark",
        accent="blue",
        first_run_done=True,
    )
    path = save_web_config(cfg)
    console.print(f"[green][OK][/green] Config saved → {path}")
    return cfg


# ═══════════════════════════════════════════════════════════════
#  Runtime
# ═══════════════════════════════════════════════════════════════

def _open_when_ready(url: str, host: str, port: int) -> None:
    """Open the browser once ``/api/health`` responds (background thread)."""
    import threading

    def _worker() -> None:
        if _wait_for_health(host, port):
            webbrowser.open(url)

    threading.Thread(target=_worker, daemon=True).start()


def _run_foreground(host: str, port: int) -> None:
    """Run uvicorn in the current process (Ctrl+C to stop)."""
    try:
        from backend.main import app as backend_app  # type: ignore
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red][!] Cannot import backend.main: {exc}[/bold red]")
        raise typer.Exit(code=1)

    try:
        import uvicorn  # type: ignore
    except ImportError:
        console.print(
            "[bold red][!] uvicorn is not installed.[/bold red]\n"
            "[dim]Install web extras: pipx inject spiderforge "
            'fastapi "uvicorn[standard]"[/dim]'
        )
        raise typer.Exit(code=1)

    console.print(f"[bold green][*] Serving SpiderForge on http://{host}:{port}[/bold green]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]")
    try:
        uvicorn.run(backend_app, host=host, port=port, log_level="info")
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Web server stopped.[/yellow]")


def _run_background(host: str, port: int, backend_root: Path, log_path: Path) -> bool:
    """Start uvicorn as a detached background process.

    Returns ``True`` when the server responds to ``/api/health``.
    """
    py_bin = sys.executable

    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_file = log_path.open("a", encoding="utf-8")

    env = os.environ.copy()
    env["SPIDERFORGE_ROOT"] = str(backend_root)
    env["PYTHONPATH"] = str(backend_root) + os.pathsep + env.get("PYTHONPATH", "")

    popen_kwargs: dict = {
        "env": env,
        "stdout": log_file,
        "stderr": log_file,
    }
    if os.name == "posix":
        popen_kwargs["start_new_session"] = True

    try:
        subprocess.Popen(
            [
                py_bin, "-m", "uvicorn", "backend.main:app",
                "--host", host, "--port", str(port),
            ],
            **popen_kwargs,
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red][!] Failed to start server: {exc}[/bold red]")
        return False

    console.print("[bold yellow][*] Starting SpiderForge Web Engine...[/bold yellow]")
    console.print(f"[dim]Log: {log_path}[/dim]")

    return _wait_for_health(host, port)


# ═══════════════════════════════════════════════════════════════
#  Public entry point
# ═══════════════════════════════════════════════════════════════

def launch_web(
    host: str | None = None,
    port: int | None = None,
    *,
    open_browser: bool | None = None,
    foreground: bool = False,
    reset_config: bool = False,
) -> None:
    """Launch the SpiderForge web dashboard.

    Parameters
    ----------
    host, port
        Optional overrides. Defaults come from the saved config.
    open_browser
        Override the ``auto_open_browser`` preference.
    foreground
        Run uvicorn in the current process.
    reset_config
        Delete the saved config and re-run the first-run wizard.
    """
    # 0) Optional reset
    if reset_config:
        reset_web_config()
        console.print("[yellow][!] Web config reset.[/yellow]")

    # 1) Config — with first-run wizard when needed
    if is_first_run():
        # If the user already provided --port, skip the wizard.
        if port is not None:
            cfg = WebConfig(port=int(port), first_run_done=True)
            save_web_config(cfg)
        else:
            cfg = _first_run_wizard()
    else:
        cfg = load_web_config()

    host = host or cfg.host
    port = int(port) if port else cfg.port
    if open_browser is None:
        open_browser = cfg.auto_open_browser

    # 2) Locate backend
    backend_root = _find_backend_root()
    if backend_root is None:
        console.print(
            "[bold red][!] Could not find the SpiderForge backend.[/bold red]\n"
            "[dim]Run from the project root or set SPIDERFORGE_ROOT.[/dim]"
        )
        raise typer.Exit(code=1)

    # 3) Locate frontend (best-effort)
    frontend_index = _find_frontend_index(backend_root)
    if frontend_index is None:
        console.print(
            "[bold yellow][!] Web UI bundle not found.[/bold yellow]\n"
            "[dim]Expected at backend/static/frontend/index.html.[/dim]\n"
            "[dim]The API will still work, but the browser UI will be missing.[/dim]"
        )
    else:
        console.print(f"[dim]UI: {frontend_index}[/dim]")

    console.print(f"[dim]Backend root: {backend_root}[/dim]")

    url = f"http://{host}:{port}"

    # 4) Already running?
    if _health_ok(host, port):
        console.print(f"[green][OK] Web console is already active at {url}[/green]")
        if open_browser:
            webbrowser.open(url)
        return

    # 5) Foreground or background
    if foreground:
        if open_browser:
            _open_when_ready(url, host, port)
        _run_foreground(host, port)
        return

    log_path = _pick_log_path(backend_root)
    started = _run_background(host, port, backend_root, log_path)

    if started:
        console.print(f"[bold green][OK] Web platform running at {url}[/bold green]")
        if open_browser:
            webbrowser.open(url)
    else:
        console.print(
            f"[bold red][!] Server initialization timed out.[/bold red]\n"
            f"[dim]Check {log_path}[/dim]"
        )
        console.print("[dim]Try running in the foreground:[/dim]")
        console.print("[dim]  spiderforge web --foreground[/dim]")


# ═══════════════════════════════════════════════════════════════
#  Typer command
# ═══════════════════════════════════════════════════════════════

@app.callback(invoke_without_command=True)
def web_command(
    ctx: typer.Context,
    host: str | None = typer.Option(
        None, "--host", "-h",
        help="Bind address (default: 127.0.0.1).",
    ),
    port: int | None = typer.Option(
        None, "--port", "-p",
        help="Port (default: 8000).",
    ),
    no_browser: bool = typer.Option(
        False, "--no-browser",
        help="Do not open the browser.",
    ),
    foreground: bool = typer.Option(
        False, "--foreground",
        help="Run in the foreground (Ctrl+C to stop).",
    ),
    reset_config: bool = typer.Option(
        False, "--reset-config",
        help="Delete the saved web config and re-run setup.",
    ),
) -> None:
    """Launch the SpiderForge web dashboard."""
    if ctx.invoked_subcommand is not None:
        return
    launch_web(
        host=host,
        port=port,
        open_browser=(False if no_browser else None),
        foreground=foreground,
        reset_config=reset_config,
    )


if __name__ == "__main__":
    app()
