from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass
class HttpCapture:
    request: str
    response: str
    request_headers: dict[str, str]
    response_headers: dict[str, str]
    status_code: int
    url: str
    method: str


def capture(
    *,
    method: str,
    url: str,
    request_headers: dict[str, str] | None = None,
    request_body: str | None = None,
    response: httpx.Response | None,
    max_body: int = 100_000,
) -> HttpCapture:
    req_lines = [f"{method.upper()} {url}"]
    for k, v in (request_headers or {}).items():
        req_lines.append(f"{k}: {v}")
    if request_body:
        req_lines.append("")
        req_lines.append(request_body[:max_body])
    request_str = "\n".join(req_lines)

    resp_str = ""
    status = 0
    resp_headers: dict[str, str] = {}
    if response is not None:
        status = response.status_code
        resp_headers = dict(response.headers.items())
        resp_lines = [f"HTTP {response.status_code} {response.reason_phrase}"]
        for k, v in resp_headers.items():
            resp_lines.append(f"{k}: {v}")
        try:
            body = response.text[:max_body]
        except Exception:
            body = response.content[:max_body].decode("utf-8", errors="replace")
        if body:
            resp_lines.append("")
            resp_lines.append(body)
        resp_str = "\n".join(resp_lines)

    return HttpCapture(
        request=request_str,
        response=resp_str,
        request_headers=request_headers or {},
        response_headers=resp_headers,
        status_code=status,
        url=url,
        method=method.upper(),
    )
