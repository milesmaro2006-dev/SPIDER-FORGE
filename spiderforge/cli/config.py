from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from spiderforge.config.defaults import DEFAULT_CONFIG_FILE
from spiderforge.config.loader import load_config

app = typer.Typer(name="config", help="Configuration inspection.")
console = Console()


@app.command("show")
def show(
    path: Path | None = typer.Option(None, "--path", help="Config file to load."),
    profile: str | None = typer.Option(None, "--profile", help="Profile override."),
) -> None:
    """Print the effective configuration (after profile merge)."""
    cfg = load_config(path=path, profile=profile)
    console.print_json(json.dumps(cfg.model_dump(mode="json"), indent=2))


@app.command("path")
def show_path() -> None:
    """Print the default config file path."""
    console.print(str(DEFAULT_CONFIG_FILE))
