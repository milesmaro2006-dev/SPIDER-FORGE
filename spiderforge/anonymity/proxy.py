"""Proxy / SOCKS5 / Tor URL resolution and validation."""

from __future__ import annotations

from urllib.parse import urlparse

from spiderforge.config.anonymity_config import AnonymityConfig

TOR_DEFAULT_SOCKS5 = "socks5://127.0.0.1:9050"

SUPPORTED_SCHEMES = ("http", "https", "socks5", "socks5h")


def build_proxy_url(cfg: AnonymityConfig) -> str | None:
    """Resolve the effective proxy URL for a config.

    Priority: tor > socks5_url > proxy_url.
    Returns ``None`` when no proxy is configured.
    """
    if cfg.tor:
        return TOR_DEFAULT_SOCKS5
    if cfg.socks5_url:
        return cfg.socks5_url
    if cfg.proxy_url:
        return cfg.proxy_url
    return None


def validate_proxy_url(url: str) -> tuple[bool, str]:
    """Validate a proxy URL. Returns ``(ok, reason)``."""
    if not url or not url.strip():
        return False, "empty URL"

    try:
        parsed = urlparse(url.strip())
    except Exception as exc:
        return False, f"cannot parse: {exc}"

    if not parsed.scheme:
        return False, "missing scheme (expected http://, https://, socks5://, or socks5h://)"
    if parsed.scheme.lower() not in SUPPORTED_SCHEMES:
        return False, (
            f"unsupported scheme {parsed.scheme!r}; use one of {SUPPORTED_SCHEMES}"
        )
    if not parsed.hostname:
        return False, "missing host"
    try:
        port = parsed.port
    except ValueError as exc:
        return False, f"invalid port: {exc}"
    if port is None:
        return False, "missing port"
    if not (1 <= port <= 65535):
        return False, f"port out of range: {port}"

    return True, ""
