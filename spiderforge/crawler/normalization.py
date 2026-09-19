from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# Analytics / ad tracking params stripped before dedup
TRACKING_PARAMS: frozenset[str] = frozenset(
    {
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "utm_id", "utm_source_platform", "utm_creative_format", "utm_marketing_tactic",
        "fbclid", "gclid", "dclid", "msclkid", "yclid", "twclid",
        "_ga", "_gl", "mc_eid", "mkt_tok", "igshid", "vero_conv", "vero_id",
        "wickedid", "s_kwcid", "ef_id",
    }
)

DEFAULT_PORTS = {"http": 80, "https": 443}


def canonicalize(url: str, *, strip_tracking: bool = True) -> str:
    """Return a canonical form of ``url`` for crawl dedup.

    * lowercases scheme + host
    * drops default port
    * collapses duplicate slashes in path
    * strips fragments
    * removes tracking params and sorts the rest
    """
    parts = urlsplit(url.strip())

    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    if port is not None and DEFAULT_PORTS.get(scheme) == port:
        port = None
    netloc = host if port is None else f"{host}:{port}"

    path = parts.path or "/"
    while "//" in path:
        path = path.replace("//", "/")

    query = ""
    if parts.query:
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        if strip_tracking:
            pairs = [(k, v) for k, v in pairs if k.lower() not in TRACKING_PARAMS]
        pairs.sort()
        query = urlencode(pairs)

    return urlunsplit((scheme, netloc, path, query, ""))
