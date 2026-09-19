"""HTTP Probe — works with SafeHttpClient (single outbound gateway)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from spiderforge.network.client import SafeHttpClient
from spiderforge.utils.logging import get_logger
from spiderforge.utils.urls import normalize_url

log = get_logger("recon.http")

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass
class ProbeResult:
    url: str
    final_url: str | None = None
    status_code: int | None = None
    reason: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str | None = None
    content_length: int | None = None
    title: str | None = None
    server: str | None = None
    redirects: list[str] = field(default_factory=list)
    elapsed_ms: float | None = None
    tls: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    body_snippet: str | None = None


def _extract_title(html: str) -> str | None:
    m = _TITLE_RE.search(html)
    if not m:
        return None
    text = re.sub(r"\s+", " ", m.group(1)).strip()
    return text[:300] or None


async def probe(
    url: str,
    *,
    client: SafeHttpClient,
    scope=None,
    max_body: int = 200_000,
    verify_tls: bool = True,
    timeout: float = 20.0,
) -> ProbeResult:
    normalized = normalize_url(url)

    try:
        resp = await client.get(normalized)
    except Exception as exc:  # noqa: BLE001
        return ProbeResult(url=normalized, error=f"{type(exc).__name__}: {exc}")

    result = ProbeResult(
        url=normalized,
        final_url=resp.final_url,
        status_code=resp.status_code,
        reason=resp.headers.get("reason", None),
        headers={k.lower(): v for k, v in resp.headers.items()},
        content_type=resp.headers.get("content-type"),
        content_length=len(resp.content),
        server=resp.headers.get("server"),
        redirects=list(resp.redirect_chain or []),
    )

    ctype = (result.content_type or "").lower()
    if any(k in ctype for k in ("text/", "html", "json", "javascript", "xml")):
        text = resp.safe_text()
        if "html" in ctype:
            result.title = _extract_title(text[:max_body])
        result.body_snippet = text[:2000]

    return result
