from __future__ import annotations

import json
from urllib.parse import urljoin, urlsplit

import httpx
import yaml

from spiderforge.discovery.models import Endpoint, SwaggerSpec
from spiderforge.scope.validator import ScopeValidator
from spiderforge.utils.urls import normalize_url

COMMON_SPEC_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/api/docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/swagger-ui/swagger.json",
    "/openapi.yaml",
    "/swagger.yaml",
]


async def discover_specs(
    origin: str,
    *,
    scope: ScopeValidator,
    client: httpx.AsyncClient,
    extra_paths: list[str] | None = None,
) -> list[SwaggerSpec]:
    paths = list(COMMON_SPEC_PATHS) + list(extra_paths or [])
    results: list[SwaggerSpec] = []
    for path in paths:
        url = normalize_url(urljoin(origin.rstrip("/") + "/", path.lstrip("/")))
        if not scope.is_allowed(url):
            continue
        spec = await _try_parse(url, client=client)
        if spec is not None and spec.error is None and spec.endpoints:
            results.append(spec)
    return results


async def _try_parse(url: str, *, client: httpx.AsyncClient) -> SwaggerSpec | None:
    try:
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        return SwaggerSpec(url=url, error=f"{type(exc).__name__}: {exc}")

    if resp.status_code != 200:
        return None
    ctype = (resp.headers.get("content-type") or "").lower()
    text = resp.text
    if not text.strip():
        return None

    data = None
    if "json" in ctype or text.lstrip().startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
    elif "yaml" in ctype or "yml" in ctype or text.lstrip().startswith(("openapi:", "swagger:")):
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError:
            return None
    else:
        return None

    if not isinstance(data, dict):
        return None
    if "swagger" not in data and "openapi" not in data:
        return None

    version = str(data.get("swagger") or data.get("openapi") or "")
    info = data.get("info") or {}
    title = info.get("title")
    base_path = data.get("basePath") or ""

    spec = SwaggerSpec(url=url, version=version, title=title, base_path=base_path)

    # Build server origin
    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    if version.startswith("3"):
        servers = data.get("servers") or []
        if servers:
            base_path = servers[0].get("url", base_path)

    paths = data.get("paths") or {}
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, meta in methods.items():
            method_upper = method.upper()
            if method_upper not in {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}:
                continue
            full_path = _join_paths(base_path, path)
            endpoint_url = urljoin(origin, full_path)
            params: list[str] = []
            for p in (meta or {}).get("parameters") or []:
                name = p.get("name") if isinstance(p, dict) else None
                if name:
                    params.append(name)
            # Request body
            req_body = (meta or {}).get("requestBody") or {}
            content = (req_body.get("content") or {}) if isinstance(req_body, dict) else {}
            for _ct, ct_def in content.items():
                schema = (ct_def or {}).get("schema") or {}
                props = schema.get("properties") or {}
                for name in props:
                    if name not in params:
                        params.append(name)
            spec.endpoints.append(
                Endpoint(
                    url=endpoint_url,
                    method=method_upper,
                    source="swagger",
                    parameters=params,
                )
            )

    return spec


def _join_paths(base: str, path: str) -> str:
    if not base:
        return path
    if base.endswith("/") and path.startswith("/"):
        return base + path[1:]
    if not base.endswith("/") and not path.startswith("/"):
        return base + "/" + path
    return base + path
