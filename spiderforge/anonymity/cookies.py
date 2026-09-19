"""Per-origin cookie isolation."""

from __future__ import annotations

from urllib.parse import urlparse


def _origin_of(url: str) -> str:
    try:
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        pass
    return ""


class CookieJarManager:
    """Maintain isolated cookie dictionaries per origin.

    Cookies set by ``https://a.example`` never leak to ``https://b.example``.
    Designed for use with a "no automatic cookies" HTTP client: the caller
    asks for the jar for a URL, merges it into the request, then feeds back
    any ``Set-Cookie`` headers after the response.
    """

    def __init__(self) -> None:
        self._jars: dict[str, dict[str, str]] = {}

    def jar_for(self, url: str) -> dict[str, str]:
        """Return the cookie dict for the origin of ``url`` (creating it if needed)."""
        origin = _origin_of(url)
        if not origin:
            return {}
        return self._jars.setdefault(origin, {})

    def apply_to_headers(self, url: str, headers: dict[str, str]) -> dict[str, str]:
        """Merge the origin's cookies into ``headers`` as a ``Cookie`` header."""
        jar = self.jar_for(url)
        if not jar:
            return dict(headers)
        merged = dict(headers)
        cookie_value = "; ".join(f"{k}={v}" for k, v in jar.items())
        existing = merged.get("Cookie") or merged.get("cookie")
        if existing:
            merged["Cookie"] = f"{existing}; {cookie_value}"
        else:
            merged["Cookie"] = cookie_value
        return merged

    def store_from_response(self, url: str, set_cookie_values: list[str]) -> None:
        """Store cookies parsed from raw ``Set-Cookie`` header values."""
        if not _origin_of(url):
            return
        jar = self.jar_for(url)
        for raw in set_cookie_values:
            if not raw:
                continue
            first = raw.split(";", 1)[0].strip()
            if not first or "=" not in first:
                continue
            name, _, value = first.partition("=")
            name = name.strip()
            value = value.strip()
            if name:
                jar[name] = value

    def clear_origin(self, url: str) -> None:
        origin = _origin_of(url)
        if origin:
            self._jars.pop(origin, None)

    def clear_all(self) -> None:
        self._jars.clear()

    def origins(self) -> list[str]:
        return list(self._jars.keys())

    def __len__(self) -> int:
        return len(self._jars)
