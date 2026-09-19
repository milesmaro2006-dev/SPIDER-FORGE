"""Orchestrator that ties together all anonymity/privacy features."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from spiderforge.anonymity.cookies import CookieJarManager
from spiderforge.anonymity.doh import (
    DoHResolver,
    DoHUnavailableError,
    cross_check,
)
from spiderforge.anonymity.fingerprint import (
    TLSFingerprint,
    tls_fingerprint_capability,
)
from spiderforge.anonymity.headers import sanitize_headers
from spiderforge.anonymity.pacing import PacingController
from spiderforge.anonymity.proxy import build_proxy_url, validate_proxy_url
from spiderforge.anonymity.user_agents import UserAgentRotator
from spiderforge.config.anonymity_config import AnonymityConfig

logger = logging.getLogger("spiderforge.anonymity")


@dataclass
class AnonymityStatus:
    enabled: bool
    proxy_url: str | None
    ua_rotation: bool
    header_sanitization: bool
    referrer_stripped: bool
    pacing: bool
    cookie_isolation: bool
    doh: bool
    tls_fingerprint: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "proxy_url": self.proxy_url,
            "ua_rotation": self.ua_rotation,
            "header_sanitization": self.header_sanitization,
            "referrer_stripped": self.referrer_stripped,
            "pacing": self.pacing,
            "cookie_isolation": self.cookie_isolation,
            "doh": self.doh,
            "tls_fingerprint": self.tls_fingerprint,
        }


class AnonymityManager:
    """Combine every privacy feature into a single request-aware object."""

    def __init__(
        self,
        config: AnonymityConfig,
        *,
        logger_: logging.Logger | None = None,
    ) -> None:
        self.config = config
        self._log = logger_ or logger

        self._ua_rotator: UserAgentRotator | None = None
        self._pacing: PacingController | None = None
        self._cookies: CookieJarManager | None = None
        self._doh: DoHResolver | None = None
        self._tls_fp: TLSFingerprint | None = None
        self._proxy_url: str | None = None
        self._dependency_error: str | None = None

        if config.enabled:
            self._init_components()

    def _init_components(self) -> None:
        cfg = self.config

        proxy_url = build_proxy_url(cfg)
        if proxy_url:
            ok, reason = validate_proxy_url(proxy_url)
            if not ok:
                self._log.warning(
                    "Anonymity: proxy %r rejected (%s) — proxy disabled",
                    proxy_url, reason,
                )
            else:
                self._proxy_url = proxy_url
                if proxy_url.startswith("socks5"):
                    ok, reason = self._check_socks_dependency()
                    if not ok:
                        self._dependency_error = (
                            f"SOCKS5/Tor proxy {proxy_url!r} requires the "
                            f"'socksio' package: {reason}"
                        )
                        self._log.warning("Anonymity: %s", self._dependency_error)

        if cfg.rotate_user_agent:
            pool = cfg.user_agent_pool or None
            self._ua_rotator = UserAgentRotator(pool=pool)
            if len(self._ua_rotator) == 0:
                self._log.warning("Anonymity: empty UA pool — rotation disabled")
                self._ua_rotator = None

        if cfg.pacing_enabled:
            self._pacing = PacingController(
                min_delay=cfg.pacing_min,
                max_delay=cfg.pacing_max,
            )

        if cfg.cookie_isolation:
            self._cookies = CookieJarManager()

        if cfg.doh_enabled:
            try:
                self._doh = DoHResolver(cfg.doh_url)
            except DoHUnavailableError as exc:
                self._log.warning("Anonymity: DoH disabled (%s)", exc)
                self._doh = None

        if cfg.tls_fingerprint:
            self._tls_fp = tls_fingerprint_capability(cfg.tls_fingerprint)
            if not self._tls_fp.available:
                self._log.warning(
                    "Anonymity: TLS fingerprint unavailable (%s)",
                    self._tls_fp.reason,
                )

    def _check_socks_dependency(self) -> tuple[bool, str]:
        """Return ``(ok, reason)`` — True when socksio is importable."""
        try:
            import socksio  # noqa: F401
        except ImportError:
            return (
                False,
                "install with: pipx inject spiderforge socksio "
                "(or: pip install 'httpx[socks]')",
            )
        return True, ""

    @property
    def is_active(self) -> bool:
        return bool(self.config.enabled)

    @property
    def proxy_url(self) -> str | None:
        return self._proxy_url if self.is_active else None

    @property
    def cookie_isolation_enabled(self) -> bool:
        return self._cookies is not None and self.is_active

    @property
    def cookies(self) -> CookieJarManager | None:
        return self._cookies if self.is_active else None

    def should_skip_peer_ip_check(self) -> bool:
        return self.proxy_url is not None

    @property
    def has_dependency_error(self) -> bool:
        """``True`` when a feature is enabled but its Python dependency is missing."""
        return self._dependency_error is not None

    def dependency_error(self) -> str | None:
        """Human-readable explanation of the missing dependency, or ``None``."""
        return self._dependency_error

    async def health_check(self, timeout: float = 3.0) -> tuple[bool, str]:
        """Verify the configured proxy is reachable.

        Performs a bare TCP connect to the proxy's host:port. Returns
        ``(ok, reason)``. Never raises.

        A ``False`` result means every subsequent HTTP request through
        this proxy will fail — the caller should abort before starting.
        """
        if not self.is_active:
            return True, "anonymity disabled"

        proxy_url = self.proxy_url
        if not proxy_url:
            return True, "no proxy configured"

        try:
            parsed = urlparse(proxy_url)
            host = parsed.hostname
            port = parsed.port
        except Exception as exc:  # noqa: BLE001
            return False, f"cannot parse proxy URL {proxy_url!r}: {exc}"

        if not host or not port:
            return False, f"invalid proxy URL {proxy_url!r} (missing host/port)"

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            return True, f"{host}:{port} reachable"
        except asyncio.TimeoutError:
            return False, (
                f"proxy {host}:{port} did not respond within {timeout:.1f}s — "
                f"is the service running?"
            )
        except ConnectionRefusedError:
            return False, (
                f"proxy {host}:{port} refused the connection — "
                f"is the service started? (e.g. `sudo systemctl start tor@default`)"
            )
        except OSError as exc:
            return False, f"proxy {host}:{port} unreachable: {exc}"
        except Exception as exc:  # noqa: BLE001
            return False, f"proxy {host}:{port} error: {type(exc).__name__}: {exc}"

    async def apply_pacing(self) -> float:
        if not self.is_active or self._pacing is None:
            return 0.0
        return await self._pacing.wait()

    def prepare_headers(
        self,
        url: str,
        headers: dict[str, str] | None,
    ) -> dict[str, str]:
        if not self.is_active:
            return dict(headers or {})

        cfg = self.config
        current = dict(headers or {})

        if self._ua_rotator is not None:
            current["User-Agent"] = self._ua_rotator.next()
        elif cfg.user_agent:
            current["User-Agent"] = cfg.user_agent

        current = sanitize_headers(
            current,
            target_url=url,
            strip_identity=cfg.strip_identity_headers,
            stripped_names=cfg.stripped_headers,
            strip_referrer=cfg.strip_referrer,
            referrer_policy=cfg.referrer_policy,
            custom_referrer=cfg.custom_referrer,
        )

        if self._cookies is not None:
            current = self._cookies.apply_to_headers(url, current)

        return current

    def on_response(self, url: str, response: Any) -> None:
        if not self.is_active or self._cookies is None:
            return
        try:
            set_cookies: list[str] = response.headers.get_list("set-cookie")
        except Exception:
            return
        if set_cookies:
            self._cookies.store_from_response(url, set_cookies)

    async def verify_dns(
        self,
        hostname: str,
        system_ips: list[str],
    ) -> tuple[bool, str]:
        if not self.is_active or self._doh is None:
            return True, "DoH not enabled"

        try:
            result = await self._doh.resolve(hostname)
        except DoHUnavailableError as exc:
            return True, f"DoH unavailable: {exc}"

        return cross_check(hostname, result.all_ips(), system_ips)

    def status(self) -> AnonymityStatus:
        cfg = self.config
        tls_dict: dict[str, Any] | None = None
        if self._tls_fp is not None:
            tls_dict = self._tls_fp.to_dict()

        return AnonymityStatus(
            enabled=self.is_active,
            proxy_url=self.proxy_url,
            ua_rotation=self._ua_rotator is not None,
            header_sanitization=cfg.strip_identity_headers,
            referrer_stripped=cfg.strip_referrer,
            pacing=self._pacing is not None and self._pacing.enabled,
            cookie_isolation=self._cookies is not None,
            doh=self._doh is not None,
            tls_fingerprint=tls_dict,
        )
