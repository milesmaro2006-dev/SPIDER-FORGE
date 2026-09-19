from __future__ import annotations

import json
from urllib.parse import urljoin

import httpx

from spiderforge.discovery.models import GraphQLInfo
from spiderforge.scope.validator import ScopeValidator
from spiderforge.utils.urls import normalize_url

COMMON_GRAPHQL_PATHS = [
    "/graphql",
    "/gql",
    "/query",
    "/api/graphql",
    "/v1/graphql",
    "/graphql/v1",
]

_INTROSPECTION_QUERY = {"query": "{ __schema { types { name } } }"}


async def detect(
    origin: str,
    *,
    scope: ScopeValidator,
    client: httpx.AsyncClient,
    try_introspection: bool = True,
) -> list[GraphQLInfo]:
    results: list[GraphQLInfo] = []
    for path in COMMON_GRAPHQL_PATHS:
        url = normalize_url(urljoin(origin.rstrip("/") + "/", path.lstrip("/")))
        if not scope.is_allowed(url):
            continue
        info = await _probe(url, client=client, try_introspection=try_introspection)
        if info.detected:
            results.append(info)
    return results


async def _probe(
    url: str, *, client: httpx.AsyncClient, try_introspection: bool
) -> GraphQLInfo:
    info = GraphQLInfo(url=url)

    # First: verify with a minimal non-introspection query.
    # GraphQL endpoints typically respond 400 with "query" in the message
    # when queried without a body, or 200 with a JSON `errors` field.
    try:
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        info.error = f"{type(exc).__name__}: {exc}"
        return info

    body = ""
    try:
        body = resp.text[:2000]
    except Exception:
        pass

    signals = 0
    if "application/json" in (resp.headers.get("content-type") or "").lower():
        signals += 1
    if any(k in body.lower() for k in ("graphql", "query", "variables", "operationname")):
        signals += 1
    if resp.status_code in (400, 405) and "query" in body.lower():
        signals += 1

    if signals >= 2 or signals == 1 and resp.status_code == 200:
        info.detected = True
    else:
        return info

    if try_introspection:
        try:
            resp2 = await client.post(
                url,
                json=_INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"},
            )
            if resp2.status_code == 200:
                try:
                    payload = resp2.json()
                except json.JSONDecodeError:
                    payload = {}
                schema = (payload.get("data") or {}).get("__schema") or {}
                types = schema.get("types") or []
                if types:
                    info.introspection_enabled = True
                    info.schema_types = [t.get("name", "") for t in types if t.get("name")][:100]
        except httpx.HTTPError as exc:
            info.error = f"introspection: {type(exc).__name__}: {exc}"

    return info
