"""Safe HTTP Client for SpiderForge v3.

Optionally integrates with :class:`~spiderforge.anonymity.manager.AnonymityManager`
for proxy routing, UA rotation, header sanitization, per-origin cookie
isolation, pacing, and DNS-over-HTTPS validation.

The anonymity layer is entirely **opt-in**. When ``anonymity=None``
(the default), behavior is byte-identical to the previous version.
"""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

import httpx

from spiderforge.network.exceptions import (
    DNSRebindingDetectedError,
    ProxyConnectionError,
    RedirectLimitExceededError,
    ResponseSizeExceededError,
    ScopeViolationError,
)
from spiderforge.network.policies import NetworkPolicy
from spiderforge.network.rate_limiter import AsyncRateLimiter
from spiderforge.network.resolver import SafeResolver

if TYPE_CHECKING:
    from spiderforge.anonymity.manager import AnonymityManager


_SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
}


def _as_str(value) -> str:
    """Safely convert httpx.URL / None / anything to a plain str."""
    return "" if value is None else str(value)


@dataclass
class SafeResponse:
    status_code: int
    headers: httpx.Headers
    url: str
    final_url: str | None = None
    content: bytes = b""
    text: str = ""
    http_version: str = "HTTP/1.1"
    redirect_chain: list[str] = field(default_factory=list)
    cookies: httpx.Cookies = field(default_factory=httpx.Cookies)

    def __post_init__(self) -> None:
        self.url = _as_str(self.url)
        if not self.final_url:
            self.final_url = self.url
        else:
            self.final_url = _as_str(self.final_url)

    def safe_content(self) -> bytes:
        return self.content

    def safe_text(self) -> str:
        return self.text


class SafeHttpClient:
    """Unified security-enforced HTTP client.

    Parameters
    ----------
    policy
        Network policy (timeouts, scope, SSRF protection, ...).
    anonymity
        Optional :class:`AnonymityManager`. When provided and enabled,
        the client routes through the configured proxy, rotates UAs,
        sanitizes headers, paces requests, and isolates cookies.
    """

    def __init__(
        self,
        policy: NetworkPolicy,
        anonymity: AnonymityManager | None = None,
    ) -> None:
        self.policy = policy
        self.anonymity = anonymity
        self.resolver = SafeResolver(policy.destination_policy)
        self._rate_limiter = AsyncRateLimiter(rate=policy.rate_limit_rps)
        self._semaphore: asyncio.Semaphore | None = None

        proxy_url: str | None = None
        if anonymity is not None:
            proxy_url = anonymity.proxy_url

            # Synchronous dependency check — must fire before we hand
            # the proxy URL to httpx, otherwise httpx raises a low-level
            # ImportError that bypasses our structured error handling.
            if anonymity.is_active and anonymity.has_dependency_error:
                raise ProxyConnectionError(
                    f"Anonymity proxy is not usable: {anonymity.dependency_error()}"
                )

        # httpx.AsyncClient accepts proxy at construction time only;
        # trust_env is disabled when an explicit proxy is in effect.
        client_kwargs: dict = {
            "verify": self.policy.verify_tls,
            "trust_env": self.policy.trust_env_proxies and proxy_url is None,
            "follow_redirects": False,
            "timeout": httpx.Timeout(
                connect=self.policy.connect_timeout,
                read=self.policy.read_timeout,
                write=self.policy.read_timeout,
                pool=self.policy.connect_timeout,
            ),
            "limits": httpx.Limits(
                max_connections=self.policy.max_concurrency,
                max_keepalive_connections=self.policy.max_concurrency,
            ),
        }
        if proxy_url:
            client_kwargs["proxy"] = proxy_url

        self._client = httpx.AsyncClient(**client_kwargs)

    # ═══════════════════════════════════════════════════════════
    #  Lifecycle
    # ═══════════════════════════════════════════════════════════

    async def __aenter__(self) -> SafeHttpClient:
        # Pre-flight: verify the anonymity proxy is reachable *before*
        # accepting any request. This prevents a scenario where a dead
        # proxy silently turns every scan into a false "no findings".
        if self.anonymity is not None and self.anonymity.is_active:
            proxy_url = self.anonymity.proxy_url
            if proxy_url:
                ok, reason = await self.anonymity.health_check()
                if not ok:
                    raise ProxyConnectionError(
                        f"Anonymity proxy is not reachable ({proxy_url}): {reason}"
                    )

        await self._client.__aenter__()
        self._semaphore = asyncio.Semaphore(self.policy.max_concurrency)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self._client.__aexit__(exc_type, exc_val, exc_tb)

    async def close(self) -> None:
        await self._client.aclose()

    # ═══════════════════════════════════════════════════════════
    #  Internals
    # ═══════════════════════════════════════════════════════════

    def _anonymity_active(self) -> bool:
        return self.anonymity is not None and self.anonymity.is_active

    def _skip_peer_ip_check(self) -> bool:
        return (
            self.anonymity is not None
            and self.anonymity.should_skip_peer_ip_check()
        )

    def _same_origin(self, a: str, b: str) -> bool:
        pa, pb = urlparse(a), urlparse(b)
        return (
            pa.scheme.lower() == pb.scheme.lower()
            and (pa.hostname or "").lower() == (pb.hostname or "").lower()
            and (pa.port or (443 if pa.scheme == "https" else 80))
                == (pb.port or (443 if pb.scheme == "https" else 80))
        )

    def _strip_sensitive_headers(
        self, headers: dict[str, str] | None
    ) -> dict[str, str] | None:
        if not headers:
            return headers
        return {
            k: v for k, v in headers.items()
            if k.lower() not in _SENSITIVE_HEADERS
        }

    def _verify_peer_ip(
        self,
        response: httpx.Response,
        expected_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    ) -> None:
        try:
            ext = response.extensions or {}
            stream = ext.get("network_stream")
            if stream is None:
                return
            server_addr = stream.get_extra_info("server_addr")
            # Defensive: mocked network streams in tests may return a
            # coroutine that is never awaited. Discard it silently.
            if asyncio.iscoroutine(server_addr):
                server_addr.close()
                return
            if not server_addr:
                return
            peer_ip = server_addr[0] if isinstance(server_addr, tuple) else server_addr
            try:
                peer = ipaddress.ip_address(peer_ip)
            except ValueError:
                return
            expected_strs = {str(ip) for ip in expected_ips}
            if str(peer) not in expected_strs:
                raise DNSRebindingDetectedError(
                    f"DNS rebinding detected: peer {peer} not in resolved set {expected_strs}"
                )
        except DNSRebindingDetectedError:
            raise
        except Exception:
            return

    def _clear_httpx_cookies(self) -> None:
        """Empty httpx's internal jar so isolation is enforced."""
        try:
            self._client.cookies.clear()
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════
    #  Request
    # ═══════════════════════════════════════════════════════════

    async def request(self, method: str, url: str, **kwargs) -> SafeResponse:
        current_url = _as_str(url)
        current_method = method

        headers_kw = kwargs.pop("headers", None)
        current_headers: dict[str, str] | None = (
            dict(headers_kw) if headers_kw else None
        )

        params = kwargs.pop("params", None)
        data = kwargs.pop("data", None)
        json_data = kwargs.pop("json", None)
        timeout = kwargs.pop("timeout", None)

        redirect_count = 0
        redirect_chain: list[str] = []
        original_url = current_url

        # ── Anonymity: pre-request header preparation (once per call) ──
        if self._anonymity_active():
            current_headers = self.anonymity.prepare_headers(
                current_url, current_headers or {},
            )

        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.policy.max_concurrency)

        async with self._semaphore:
            async with self._rate_limiter:
                # ── Anonymity: pacing (once per call) ──
                if self._anonymity_active():
                    await self.anonymity.apply_pacing()

                while True:
                    scheme, host, port = self.resolver.validate_url_structure(current_url)
                    resolved_ips = await self.resolver.resolve_and_validate(host, port)

                    # ── Anonymity: DoH cross-check (once per hop) ──
                    if self._anonymity_active():
                        ok, reason = await self.anonymity.verify_dns(
                            host, [str(ip) for ip in resolved_ips],
                        )
                        if not ok:
                            raise ScopeViolationError(
                                f"DNS hijack suspected: {reason}"
                            )

                    resolved_ip = resolved_ips[0] if resolved_ips else None
                    if not self.policy.scope_policy.is_in_scope(
                        host, resolved_ip=resolved_ip
                    ):
                        raise ScopeViolationError(
                            f"Host '{host}' is outside authorized scope"
                        )

                    req_kwargs = {"timeout": timeout} if timeout else {}

                    req = self._client.build_request(
                        method=current_method,
                        url=current_url,
                        headers=current_headers,
                        params=params if redirect_count == 0 else None,
                        data=data if redirect_count == 0 else None,
                        json=json_data if redirect_count == 0 else None,
                        **req_kwargs,
                    )

                    raw_response = await self._client.send(req, stream=True)
                    try:
                        # Skip peer IP check when routing through a proxy.
                        if not self._skip_peer_ip_check():
                            self._verify_peer_ip(raw_response, resolved_ips)

                        # ── Anonymity: capture Set-Cookie ──
                        if self._anonymity_active():
                            self.anonymity.on_response(current_url, raw_response)
                            if self.anonymity.cookie_isolation_enabled:
                                self._clear_httpx_cookies()

                        if raw_response.is_redirect and "location" in raw_response.headers:
                            redirect_count += 1
                            if redirect_count > self.policy.max_redirects:
                                raise RedirectLimitExceededError(
                                    f"Redirect chain exceeded {self.policy.max_redirects} for {original_url}"
                                )

                            location = raw_response.headers["location"]
                            new_url = urljoin(current_url, _as_str(location))
                            redirect_chain.append(new_url)

                            if not self._same_origin(current_url, new_url):
                                current_headers = self._strip_sensitive_headers(
                                    current_headers
                                )

                            current_url = new_url
                            current_method = "GET"
                            continue

                        body_chunks: list[bytes] = []
                        bytes_read = 0
                        async for chunk in raw_response.aiter_bytes():
                            bytes_read += len(chunk)
                            if bytes_read > self.policy.max_response_bytes:
                                raise ResponseSizeExceededError(
                                    f"Response > {self.policy.max_response_bytes} bytes from {current_url}"
                                )
                            body_chunks.append(chunk)

                        full_content = b"".join(body_chunks)
                        text_content = full_content.decode(
                            raw_response.encoding or "utf-8",
                            errors="replace",
                        )

                        return SafeResponse(
                            status_code=raw_response.status_code,
                            headers=raw_response.headers,
                            url=_as_str(req.url),
                            final_url=_as_str(raw_response.url),
                            content=full_content,
                            text=text_content,
                            http_version=raw_response.http_version,
                            redirect_chain=redirect_chain,
                            cookies=raw_response.cookies,
                        )
                    finally:
                        await raw_response.aclose()

    async def get(self, url: str, **kwargs) -> SafeResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> SafeResponse:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs) -> SafeResponse:
        return await self.request("HEAD", url, **kwargs)
