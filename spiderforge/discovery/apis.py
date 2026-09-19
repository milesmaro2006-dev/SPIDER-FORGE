from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import urlsplit

from spiderforge.discovery.endpoints import path_template
from spiderforge.discovery.models import APICluster, Endpoint

# Common API base path patterns
_API_BASE_RE = re.compile(
    r"^/(?:api|rest|rpc|graphql|gql|services?|v\d+|backend)(?:/v\d+)?",
    re.IGNORECASE,
)

_AUTH_HINT_HEADERS = {
    "www-authenticate": "basic/digest",
    "x-auth-token": "token",
    "x-api-key": "api_key",
}
_AUTH_HINT_PATHS = {
    "/oauth": "oauth",
    "/token": "token",
    "/auth": "auth",
    "/login": "login",
    "/sso": "sso",
    "/saml": "saml",
}


def _api_base(path: str) -> str | None:
    m = _API_BASE_RE.match(path)
    if not m:
        return None
    # Base is the matched segment plus one more (e.g. /api/v1)
    segments = [s for s in path.split("/") if s]
    base_segments = segments[: m.end() and 2 or 1]
    return "/" + "/".join(base_segments)


def cluster_api_endpoints(
    endpoints: list[Endpoint],
    headers_by_url: dict[str, dict[str, str]] | None = None,
) -> list[APICluster]:
    """Group endpoints into API clusters by base path."""
    by_base: dict[str, list[Endpoint]] = defaultdict(list)

    for ep in endpoints:
        path = urlsplit(ep.url).path
        base = _api_base(path)
        if base is None:
            continue
        by_base[base].append(ep)

    clusters: list[APICluster] = []

    for base, eps in by_base.items():
        methods = sorted({e.method.upper() for e in eps})
        params: list[str] = []
        for e in eps:
            for p in e.parameters:
                if p not in params:
                    params.append(p)

        auth_hint = None
        if headers_by_url:
            for e in eps:
                hdrs = headers_by_url.get(e.url, {})
                for h, label in _AUTH_HINT_HEADERS.items():
                    if h in hdrs:
                        auth_hint = label
                        break
                if auth_hint:
                    break
        if auth_hint is None:
            for e in eps:
                low = e.url.lower()
                for path_frag, label in _AUTH_HINT_PATHS.items():
                    if path_frag in low:
                        auth_hint = label
                        break
                if auth_hint:
                    break

        # Determine API kind
        api_kind = "rest"
        for e in eps:
            ct = (e.content_type or "").lower()
            if "json" in ct:
                api_kind = "json"
            if "graphql" in e.url.lower():
                api_kind = "graphql"

        clusters.append(
            APICluster(
                base_path=base,
                endpoints=[path_template(e.url) for e in eps],
                methods=methods,
                parameters=params,
                auth_hint=auth_hint,
                api_kind=api_kind,
            )
        )

    return sorted(clusters, key=lambda c: (-len(c.endpoints), c.base_path))
