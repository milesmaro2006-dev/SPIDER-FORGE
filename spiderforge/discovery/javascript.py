from __future__ import annotations

import re
from urllib.parse import urlsplit

import httpx

from spiderforge.discovery.models import JSFinding
from spiderforge.scope.validator import ScopeValidator
from spiderforge.utils.urls import normalize_url

# URL patterns
_URL_RE = re.compile(r"""["'`](https?://[^\s"'`<>\\]+)["'`]""", re.IGNORECASE)
_PATH_RE = re.compile(r"""["'`](/[a-zA-Z0-9_\-./]{2,200}(?:\?[^\s"'`<>\\]*)?)["'`]""")
_WS_RE = re.compile(r"""["'`](wss?://[^\s"'`<>\\]+)["'`]""", re.IGNORECASE)
_SOURCE_MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s]+)")

# Framework call patterns
_FETCH_RE = re.compile(r"""fetch\(\s*["'`]([^"'`]+)["'`]""", re.IGNORECASE)
_AXIOS_RE = re.compile(
    r"""axios\.(?:get|post|put|delete|patch|request)\(\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE,
)
_XHR_OPEN_RE = re.compile(
    r"""\.open\(\s*["'](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["']\s*,\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE,
)
_JQUERY_AJAX_URL_RE = re.compile(r"""url\s*:\s*["'`]([^"'`]+)["'`]""", re.IGNORECASE)

# Interesting strings (variable names, headers, keywords)
_INTERESTING_KEYS = (
    "api_key", "apikey", "api-key", "secret", "client_secret", "access_token",
    "refresh_token", "auth_token", "bearer", "password", "passwd",
    "authorization", "x-api-key", "aws_", "firebase", "s3.amazonaws",
    "google_api", "sendgrid", "stripe", "twilio",
)
_INTERESTING_RE = re.compile(
    r"""["'`](""" + "|".join(re.escape(k) for k in _INTERESTING_KEYS) + r""")["'`]""",
    re.IGNORECASE,
)

# Parameter name patterns inside template literals or query strings
_QUERY_PARAM_RE = re.compile(r"[?&]([a-zA-Z_][a-zA-Z0-9_\-]{0,50})=")
_TEMPLATE_PARAM_RE = re.compile(r"\$\{([a-zA-Z_][a-zA-Z0-9_]{0,50})\}")

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")


def _dedupe(seq: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _is_interesting_path(path: str) -> bool:
    """Filter obvious noise (font/image extensions)."""
    low = path.lower()
    return not any(low.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".mp3", ".wav", ".ogg"))


def analyze_js(source_url: str, content: str) -> JSFinding:
    finding = JSFinding(source_url=source_url, size_bytes=len(content))

    endpoints: list[str] = []
    for m in _URL_RE.finditer(content):
        endpoints.append(m.group(1))
    for m in _PATH_RE.finditer(content):
        if _is_interesting_path(m.group(1)):
            endpoints.append(m.group(1))

    fetch_calls: list[str] = []
    for regex in (_FETCH_RE, _AXIOS_RE, _XHR_OPEN_RE, _JQUERY_AJAX_URL_RE):
        for m in regex.finditer(content):
            val = m.group(1)
            fetch_calls.append(val)
            if val.startswith("/") and _is_interesting_path(val):
                endpoints.append(val)

    websockets: list[str] = [m.group(1) for m in _WS_RE.finditer(content)]
    source_maps: list[str] = [m.group(1) for m in _SOURCE_MAP_RE.finditer(content)]

    parameters: list[str] = []
    for m in _QUERY_PARAM_RE.finditer(content):
        parameters.append(m.group(1))
    for m in _TEMPLATE_PARAM_RE.finditer(content):
        parameters.append(m.group(1))

    interesting: list[str] = []
    for m in _INTERESTING_RE.finditer(content):
        interesting.append(m.group(1))
    if _JWT_RE.search(content):
        interesting.append("jwt_token_literal")

    finding.endpoints = _dedupe(endpoints)[:500]
    finding.parameters = _dedupe(parameters)[:500]
    finding.websockets = _dedupe(websockets)[:100]
    finding.source_maps = _dedupe(source_maps)[:50]
    finding.interesting_strings = _dedupe(interesting)[:100]
    finding.fetch_calls = _dedupe(fetch_calls)[:200]

    # Confidence heuristic:
    #   - base 0.3
    #   - +0.3 if we found any endpoints
    #   - +0.2 if we found fetch/xhr calls (real client-side activity)
    #   - +0.2 if source is in-scope
    conf = 0.3
    if finding.endpoints:
        conf += 0.3
    if finding.fetch_calls:
        conf += 0.2
    if urlsplit(source_url).scheme in ("http", "https"):
        conf += 0.2
    finding.confidence = round(min(conf, 1.0), 2)

    return finding


async def fetch_and_analyze(
    js_url: str,
    *,
    scope: ScopeValidator,
    client: httpx.AsyncClient,
    max_size: int = 2_000_000,
    timeout: float = 15.0,
) -> JSFinding:
    url = normalize_url(js_url)
    if not scope.is_allowed(url):
        return JSFinding(source_url=url, error="out_of_scope")

    try:
        resp = await client.get(url, timeout=timeout)
    except httpx.HTTPError as exc:
        return JSFinding(source_url=url, error=f"{type(exc).__name__}: {exc}")

    if resp.status_code != 200:
        return JSFinding(source_url=url, error=f"status {resp.status_code}")

    content = resp.text
    if len(content) > max_size:
        content = content[:max_size]

    return analyze_js(url, content)
