"""Web dashboard configuration for the ``spiderforge web`` command.

Stores user preferences (host, port, browser auto-open) in a small TOML
file at ``~/.spiderforge/web.toml``.

Uses the standard library ``tomllib`` on Python 3.11+, falling back to
``tomli`` on Python 3.10. Writing uses ``tomli_w`` when available,
otherwise a tiny built-in serializer kicks in.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

# ─── TOML readers / writers ─────────────────────────────────────
try:  # Python 3.11+
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover — Python 3.10
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

try:
    import tomli_w  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover
    tomli_w = None  # type: ignore[assignment]


WEB_CONFIG_DIR = Path.home() / ".spiderforge"
WEB_CONFIG_PATH = WEB_CONFIG_DIR / "web.toml"


@dataclass
class WebConfig:
    """User-facing preferences for the web dashboard."""

    host: str = "127.0.0.1"
    port: int = 8000
    auto_open_browser: bool = True
    theme: str = "dark"
    accent: str = "blue"
    first_run_done: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def is_first_run() -> bool:
    """Return ``True`` when no web config file exists yet."""
    return not WEB_CONFIG_PATH.exists()


def _ensure_dir() -> None:
    WEB_CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(value, (int, float)):
        return bool(value)
    return default


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def load_web_config() -> WebConfig:
    """Load web config from disk, returning defaults on any error."""
    if not WEB_CONFIG_PATH.exists() or tomllib is None:
        return WebConfig()

    try:
        with WEB_CONFIG_PATH.open("rb") as fh:
            data = tomllib.load(fh)
    except Exception:
        return WebConfig()

    if not isinstance(data, dict):
        return WebConfig()

    # Accept either a [web] table or a flat layout (backward-compatible).
    root: dict[str, Any] = data.get("web") if isinstance(data.get("web"), dict) else data

    return WebConfig(
        host=str(root.get("host", "127.0.0.1")) or "127.0.0.1",
        port=_as_int(root.get("port", 8000), 8000),
        auto_open_browser=_as_bool(root.get("auto_open_browser", True), True),
        theme=str(root.get("theme", "dark")) or "dark",
        accent=str(root.get("accent", "blue")) or "blue",
        first_run_done=_as_bool(root.get("first_run_done", False), False),
    )


def _dump_toml_fallback(cfg: WebConfig) -> str:
    """Minimal TOML serializer for environments without ``tomli_w``."""
    lines: list[str] = ["[web]"]
    for key, value in cfg.to_dict().items():
        if isinstance(value, bool):
            lines.append(f"{key} = {'true' if value else 'false'}")
        elif isinstance(value, int):
            lines.append(f"{key} = {value}")
        else:
            escaped = str(value).replace('"', '\\"')
            lines.append(f'{key} = "{escaped}"')
    lines.append("")
    return "\n".join(lines)


def save_web_config(cfg: WebConfig) -> Path:
    """Persist the config to disk and return the written path."""
    _ensure_dir()
    payload = {"web": cfg.to_dict()}

    if tomli_w is not None:
        with WEB_CONFIG_PATH.open("wb") as fh:
            tomli_w.dump(payload, fh)
    else:
        WEB_CONFIG_PATH.write_text(_dump_toml_fallback(cfg), encoding="utf-8")

    return WEB_CONFIG_PATH


def reset_web_config() -> None:
    """Delete the config file so the next run triggers the wizard again."""
    try:
        WEB_CONFIG_PATH.unlink()
    except FileNotFoundError:
        pass
