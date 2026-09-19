"""Anonymity configuration — dataclass + TOML persistence.

Stored at ``~/.spiderforge/anonymity.toml``. Mirrors the pattern used by
:mod:`spiderforge.config.web_config`.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

try:  # Python 3.11+
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

try:
    import tomli_w  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover
    tomli_w = None  # type: ignore[assignment]


ANONYMITY_CONFIG_PATH = Path.home() / ".spiderforge" / "anonymity.toml"


DEFAULT_STRIPPED_HEADERS: tuple[str, ...] = (
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "x-client-ip",
    "x-originating-ip",
    "x-remote-ip",
    "x-remote-addr",
    "forwarded",
    "via",
    "client-ip",
    "true-client-ip",
    "cf-connecting-ip",
)


@dataclass
class AnonymityConfig:
    """User preferences for anonymity / privacy features."""

    enabled: bool = False

    # ─── Proxy / tunneling ─────────────────────────────
    proxy_url: str = ""
    socks5_url: str = ""
    tor: bool = False

    # ─── User-Agent ────────────────────────────────────
    rotate_user_agent: bool = False
    user_agent: str = ""
    user_agent_pool: list[str] = field(default_factory=list)

    # ─── Header sanitization ───────────────────────────
    strip_identity_headers: bool = True
    stripped_headers: list[str] = field(
        default_factory=lambda: list(DEFAULT_STRIPPED_HEADERS)
    )

    # ─── Referrer ──────────────────────────────────────
    strip_referrer: bool = False
    referrer_policy: str = "same-origin"  # none | same-origin | custom
    custom_referrer: str = ""

    # ─── DNS-over-HTTPS ────────────────────────────────
    doh_enabled: bool = False
    doh_url: str = "https://cloudflare-dns.com/dns-query"

    # ─── Pacing ────────────────────────────────────────
    pacing_enabled: bool = False
    pacing_min: float = 0.5
    pacing_max: float = 2.0

    # ─── Cookies ───────────────────────────────────────
    cookie_isolation: bool = False

    # ─── TLS fingerprint ───────────────────────────────
    tls_fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _ensure_dir() -> None:
    ANONYMITY_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)


def is_first_run() -> bool:
    return not ANONYMITY_CONFIG_PATH.exists()


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(value, (int, float)):
        return bool(value)
    return default


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_list_of_str(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, (str, int, float))]


def _escape_toml_string(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def load_anonymity_config() -> AnonymityConfig:
    """Load anonymity config from disk, returning defaults on any error."""
    if not ANONYMITY_CONFIG_PATH.exists() or tomllib is None:
        return AnonymityConfig()

    try:
        with ANONYMITY_CONFIG_PATH.open("rb") as fh:
            data = tomllib.load(fh)
    except Exception:
        return AnonymityConfig()

    if not isinstance(data, dict):
        return AnonymityConfig()

    root: dict[str, Any] = (
        data.get("anonymity") if isinstance(data.get("anonymity"), dict) else data
    )

    default_cfg = AnonymityConfig()
    stripped = _as_list_of_str(root.get("stripped_headers"))
    if not stripped:
        stripped = list(DEFAULT_STRIPPED_HEADERS)

    return AnonymityConfig(
        enabled=_as_bool(root.get("enabled", False), False),
        proxy_url=str(root.get("proxy_url", "") or ""),
        socks5_url=str(root.get("socks5_url", "") or ""),
        tor=_as_bool(root.get("tor", False), False),
        rotate_user_agent=_as_bool(root.get("rotate_user_agent", False), False),
        user_agent=str(root.get("user_agent", "") or ""),
        user_agent_pool=_as_list_of_str(root.get("user_agent_pool")),
        strip_identity_headers=_as_bool(root.get("strip_identity_headers", True), True),
        stripped_headers=stripped,
        strip_referrer=_as_bool(root.get("strip_referrer", False), False),
        referrer_policy=str(root.get("referrer_policy", "same-origin") or "same-origin"),
        custom_referrer=str(root.get("custom_referrer", "") or ""),
        doh_enabled=_as_bool(root.get("doh_enabled", False), False),
        doh_url=str(root.get("doh_url", default_cfg.doh_url) or default_cfg.doh_url),
        pacing_enabled=_as_bool(root.get("pacing_enabled", False), False),
        pacing_min=_as_float(
            root.get("pacing_min", default_cfg.pacing_min), default_cfg.pacing_min
        ),
        pacing_max=_as_float(
            root.get("pacing_max", default_cfg.pacing_max), default_cfg.pacing_max
        ),
        cookie_isolation=_as_bool(root.get("cookie_isolation", False), False),
        tls_fingerprint=str(root.get("tls_fingerprint", "") or ""),
    )


def _dump_toml_fallback(cfg: AnonymityConfig) -> str:
    """Minimal TOML serializer for environments without ``tomli_w``."""
    lines: list[str] = ["[anonymity]"]
    for key, value in cfg.to_dict().items():
        if isinstance(value, bool):
            lines.append(f"{key} = {'true' if value else 'false'}")
        elif isinstance(value, (int, float)):
            lines.append(f"{key} = {value}")
        elif isinstance(value, list):
            items = ", ".join(f'"{_escape_toml_string(str(item))}"' for item in value)
            lines.append(f"{key} = [{items}]")
        else:
            lines.append(f'{key} = "{_escape_toml_string(str(value))}"')
    lines.append("")
    return "\n".join(lines)


def save_anonymity_config(cfg: AnonymityConfig) -> Path:
    """Persist the config and return the written path."""
    _ensure_dir()
    payload = {"anonymity": cfg.to_dict()}
    if tomli_w is not None:
        with ANONYMITY_CONFIG_PATH.open("wb") as fh:
            tomli_w.dump(payload, fh)
    else:
        ANONYMITY_CONFIG_PATH.write_text(_dump_toml_fallback(cfg), encoding="utf-8")
    return ANONYMITY_CONFIG_PATH


def reset_anonymity_config() -> None:
    """Delete the config file, restoring defaults."""
    try:
        ANONYMITY_CONFIG_PATH.unlink()
    except FileNotFoundError:
        pass
