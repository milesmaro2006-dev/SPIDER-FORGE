from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_url(url: str, *, strip_fragment: bool = True, sort_query: bool = True) -> str:
    """Return a canonical form of a URL for deduplication."""
    parts = urlsplit(url.strip())

    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    if port is not None and DEFAULT_PORTS.get(scheme) == port:
        port = None

    netloc = host if port is None else f"{host}:{port}"

    path = parts.path or "/"

    query = parts.query
    if sort_query and query:
        pairs = parse_qsl(query, keep_blank_values=True)
        pairs.sort()
        query = urlencode(pairs)

    fragment = "" if strip_fragment else parts.fragment
    return urlunsplit((scheme, netloc, path, query, fragment))


def same_origin(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    return (
        pa.scheme.lower() == pb.scheme.lower()
        and (pa.hostname or "").lower() == (pb.hostname or "").lower()
        and _eff_port(pa) == _eff_port(pb)
    )


def _eff_port(parts) -> int | None:
    if parts.port is not None:
        return parts.port
    return DEFAULT_PORTS.get(parts.scheme.lower())


def join_url(base: str, link: str) -> str:
    return urljoin(base, link)


def get_hostname(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def is_http_url(url: str) -> bool:
    return urlsplit(url).scheme.lower() in {"http", "https"}
