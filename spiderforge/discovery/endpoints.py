from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import urlsplit

from spiderforge.discovery.models import Endpoint

# Path segments that look like IDs
_NUMERIC_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
_MONGO_ID_RE = re.compile(r"^[0-9a-f]{24}$", re.IGNORECASE)


def _is_id_like(segment: str) -> str | None:
    if not segment:
        return None
    if _NUMERIC_RE.match(segment):
        return "{id}"
    if _UUID_RE.match(segment):
        return "{uuid}"
    if _MONGO_ID_RE.match(segment):
        return "{objectid}"
    if _HEX_RE.match(segment):
        return "{hex}"
    return None


def path_template(url: str) -> str:
    """Turn ``/users/123/orders/456`` into ``/users/{id}/orders/{id}``."""
    parts = urlsplit(url)
    segments = [s for s in parts.path.split("/") if s]
    templated = []
    for seg in segments:
        kind = _is_id_like(seg)
        templated.append(kind if kind else seg)
    return "/" + "/".join(templated)


def endpoint_key(url: str, method: str = "GET") -> str:
    parts = urlsplit(url)
    return f"{method.upper()} {parts.scheme}://{parts.netloc}{path_template(url)}"


def group_endpoints(endpoints: list[Endpoint]) -> dict[str, list[Endpoint]]:
    """Group endpoints by their templated key."""
    groups: dict[str, list[Endpoint]] = defaultdict(list)
    for ep in endpoints:
        groups[endpoint_key(ep.url, ep.method)].append(ep)
    return dict(groups)


def merge_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Deduplicate endpoints by (method, templated url). Keep first, merge params."""
    merged: dict[str, Endpoint] = {}
    for ep in endpoints:
        key = endpoint_key(ep.url, ep.method)
        existing = merged.get(key)
        if existing is None:
            ep.path_template = path_template(ep.url)
            merged[key] = ep
            continue
        # Merge params and sources
        for p in ep.parameters:
            if p not in existing.parameters:
                existing.parameters.append(p)
        if ep.status_code and not existing.status_code:
            existing.status_code = ep.status_code
        if ep.content_type and not existing.content_type:
            existing.content_type = ep.content_type
    return list(merged.values())
