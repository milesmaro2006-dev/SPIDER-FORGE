"""Analysis module framework for SpiderForge v3.

Provides:
  • ModuleContext          — shared context passed to every module
  • SecurityModule         — abstract base for every analysis module
  • build_response_evidence — helper to redact + build evidence
  • in_scope_urls          — helper to enumerate candidate URLs
  • body_text              — extract text body safely from a response
  • response_headers_lower — case-insensitive header lookup
"""

from __future__ import annotations

import re as _re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from spiderforge.core.events import EventBus
from spiderforge.evidence.redactor import SecretRedactor
from spiderforge.findings.models import (
    Confidence,
    Evidence,
    Finding,
    FindingEvidence,
    FindingStatus,
    Severity,
)
from spiderforge.scope.validator import ScopeValidator

# ═══════════════════════════════════════════════════════════════
#  ModuleContext
# ═══════════════════════════════════════════════════════════════

@dataclass
class ModuleContext:
    target: str
    scope: ScopeValidator
    client: httpx.AsyncClient = None  # type: ignore[assignment]
    config: Any = None
    crawl_result: Any = None
    discovery_result: Any = None
    recon_result: Any = None
    bus: EventBus | None = None
    safe_client: Any = None
    origin: str = ""
    options: dict = field(default_factory=dict)
    logger: Any = None

    def __post_init__(self) -> None:
        if not self.origin and self.target:
            try:
                p = urlsplit(self.target)
                self.origin = f"{p.scheme}://{p.netloc}"
            except Exception:
                self.origin = self.target

    async def get(self, url: str, **kwargs):
        """Fetch a URL using the safest available client.

        Prefers ``safe_client`` (SpiderForge SafeHttpClient, which enforces
        SSRF/scope/rate-limit) over the raw ``httpx.AsyncClient``. Falls back
        to httpx only when ``safe_client`` is absent.
        """
        if self.safe_client is not None:
            return await self.safe_client.get(url, **kwargs)
        if self.client is None:
            raise RuntimeError("ModuleContext has no HTTP client")
        return await self.client.get(url, **kwargs)


# ═══════════════════════════════════════════════════════════════
#  SecurityModule
# ═══════════════════════════════════════════════════════════════

class SecurityModule(ABC):
    name: str = "unnamed"
    category: str = "misc"
    description: str = ""

    @abstractmethod
    async def run(self, ctx: ModuleContext) -> list[Finding]:
        """Execute the module and return findings."""

    def make_finding(
        self,
        *,
        title: str,
        category: str,
        severity: Severity,
        url: str,
        description: str = "",
        impact: str = "",
        remediation: str = "",
        confidence: Confidence | float = Confidence.MEDIUM,
        evidence: Evidence | FindingEvidence | list | dict | None = None,
        parameter: str | None = None,
        http_method: str = "GET",
        payload_applied: str | None = None,
        cwe_id: str | None = None,
        owasp_category: str | None = None,
        status: FindingStatus = FindingStatus.UNCONFIRMED,
        root_cause: str | None = None,
        **extra: Any,
    ) -> Finding:
        host = ""
        try:
            from urllib.parse import urlparse
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            pass

        ev_list: list[FindingEvidence] = []
        if evidence is None:
            ev_list = []
        elif isinstance(evidence, FindingEvidence):
            ev_list = [evidence]
        elif isinstance(evidence, dict):
            ev_list = [FindingEvidence(**evidence)]
        elif isinstance(evidence, list):
            for item in evidence:
                if isinstance(item, FindingEvidence):
                    ev_list.append(item)
                elif isinstance(item, dict):
                    ev_list.append(FindingEvidence(**item))

        return Finding(
            title=title,
            category=category,
            severity=severity,
            confidence=confidence,
            url=url,
            host=host,
            http_method=http_method,
            parameter=parameter,
            payload_applied=payload_applied,
            description=description,
            impact=impact,
            remediation=remediation,
            cwe_id=cwe_id,
            owasp_category=owasp_category,
            scanner_name=self.name,
            status=status,
            evidence=ev_list,
            tags=[root_cause] if root_cause else [],
            **extra,
        )


# ═══════════════════════════════════════════════════════════════
#  Response helpers
# ═══════════════════════════════════════════════════════════════

def body_text(resp: Any, max_bytes: int = 200_000) -> str:
    if resp is None:
        return ""
    try:
        if hasattr(resp, "safe_text"):
            text = resp.safe_text() or ""
        elif hasattr(resp, "text"):
            text = resp.text or ""
        elif hasattr(resp, "content"):
            content = resp.content or b""
            text = content if isinstance(content, str) else content.decode("utf-8", errors="replace")
        else:
            return ""

        if max_bytes and len(text) > max_bytes:
            text = text[:max_bytes]
        return text
    except Exception:
        return ""


def body_text_lower(resp: Any, max_bytes: int = 200_000) -> str:
    return body_text(resp, max_bytes=max_bytes).lower()


def body_bytes(resp: Any) -> bytes:
    if resp is None:
        return b""
    try:
        if hasattr(resp, "safe_content"):
            return resp.safe_content() or b""
        if hasattr(resp, "content"):
            content = resp.content or b""
            return content.encode("utf-8", errors="replace") if isinstance(content, str) else content
    except Exception:
        pass
    return b""


def response_headers_lower(resp: Any) -> dict[str, str]:
    if resp is None:
        return {}
    try:
        headers = getattr(resp, "headers", None)
        return {str(k).lower(): str(v) for k, v in headers.items()} if headers else {}
    except Exception:
        return {}


def get_header(resp: Any, name: str, default: str = "") -> str:
    return response_headers_lower(resp).get(name.lower(), default)


def content_type(resp: Any) -> str:
    return get_header(resp, "content-type", "").split(";", 1)[0].strip().lower()


def header(resp: Any, name: str, default: str = "") -> str:
    return get_header(resp, name, default)


def text_of(resp: Any) -> str:
    return body_text(resp)


def status_of(resp: Any) -> int:
    try:
        return int(getattr(resp, "status_code", 0) or 0)
    except Exception:
        return 0


def url_of(resp: Any) -> str:
    try:
        return str(getattr(resp, "url", ""))
    except Exception:
        return ""


# ═══════════════════════════════════════════════════════════════
#  Evidence helper
# ═══════════════════════════════════════════════════════════════

def build_response_evidence(resp: Any, *, max_body: int = 1024) -> dict:
    try:
        status = getattr(resp, "status_code", 0)
        url = str(getattr(resp, "url", ""))
        headers = dict(getattr(resp, "headers", {}))
        body = body_text(resp, max_bytes=max_body) if max_body > 0 else ""

        return {
            "request_url": url,
            "response_status": status,
            "response_headers": SecretRedactor.redact_headers(headers),
            "response_body": SecretRedactor.redact_text(body) if body else None,
        }
    except Exception:
        return {
            "request_url": "",
            "response_status": 0,
            "response_headers": {},
            "response_body": None,
        }


# ═══════════════════════════════════════════════════════════════
#  URL enumeration helper
# ═══════════════════════════════════════════════════════════════

def in_scope_urls(ctx: ModuleContext, require_params: bool = False) -> list[str]:
    """Return in-scope URLs from the crawl result, plus the target.

    If ``require_params`` is True, only URLs with at least one query
    parameter are returned.
    """
    urls: list[str] = []
    seen: set[str] = set()

    def _add(url: str) -> None:
        if not url:
            return
        url = str(url)
        if url in seen:
            return
        try:
            if ctx.scope is not None and not ctx.scope.is_allowed(url):
                return
        except Exception:
            return
        if require_params and not has_params(url):
            return
        seen.add(url)
        urls.append(url)

    _add(ctx.target)

    crawl = ctx.crawl_result
    if crawl is not None:
        for p in getattr(crawl, "pages", None) or []:
            final = getattr(p, "final_url", None) or getattr(p, "url", None)
            if final:
                _add(final)

        for ep in getattr(crawl, "endpoints", None) or []:
            u = getattr(ep, "url", None)
            if u:
                _add(u)

    return urls


# ═══════════════════════════════════════════════════════════════
#  Parameter extraction & manipulation helpers
# ═══════════════════════════════════════════════════════════════

class ParamsDict(dict):
    def __iter__(self):
        return iter(self.items())


def extract_params(url: str) -> ParamsDict:
    try:
        qs = urlsplit(url).query
        if not qs:
            return ParamsDict()
        pairs = parse_qsl(qs, keep_blank_values=True)
        out = ParamsDict()
        for k, v in pairs:
            if k:
                out[k] = v
        return out
    except Exception:
        return ParamsDict()


def extract_param_names(url: str) -> list[str]:
    try:
        qs = urlsplit(url).query
        if not qs:
            return []
        names: list[str] = []
        seen: set = set()
        for k, _ in parse_qsl(qs, keep_blank_values=True):
            if k and k not in seen:
                seen.add(k)
                names.append(k)
        return names
    except Exception:
        return []


def has_params(url: str) -> bool:
    return bool(extract_param_names(url))


def build_url_with_params(base: str, params: dict[str, str]) -> str:
    try:
        parts = urlsplit(base)
        existing = dict(parse_qsl(parts.query, keep_blank_values=True))
        existing.update({k: str(v) for k, v in params.items()})
        new_query = urlencode(existing, doseq=True)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
    except Exception:
        return base


def replace_param(url: str, name: str, value: str) -> str:
    try:
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        new_pairs = [(k, value if k == name else v) for k, v in pairs]
        new_query = urlencode(new_pairs, doseq=True)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
    except Exception:
        return url


def with_param(url: str, name: str, value: str) -> str:
    return replace_param(url, name, value)


def set_param(url: str, name: str, value: str) -> str:
    try:
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        found = False
        new_pairs = []
        for k, v in pairs:
            if k == name:
                new_pairs.append((k, value))
                found = True
            else:
                new_pairs.append((k, v))
        if not found:
            new_pairs.append((name, value))
        new_query = urlencode(new_pairs, doseq=True)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
    except Exception:
        return url


def remove_param(url: str, name: str) -> str:
    try:
        parts = urlsplit(url)
        pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != name]
        new_query = urlencode(pairs, doseq=True)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
    except Exception:
        return url


def extract_param_values(url: str, name: str) -> list[str]:
    try:
        qs = urlsplit(url).query
        return [v for k, v in parse_qsl(qs, keep_blank_values=True) if k == name]
    except Exception:
        return []


# ═══════════════════════════════════════════════════════════════
#  Status / format helpers
# ═══════════════════════════════════════════════════════════════

def is_success(resp: Any) -> bool:
    return 200 <= status_of(resp) < 300


def is_redirect(resp: Any) -> bool:
    code = status_of(resp)
    return (300 <= code < 400) and bool(get_header(resp, "location", ""))


def location_of(resp: Any) -> str:
    return get_header(resp, "location", "")


def content_length(resp: Any) -> int:
    try:
        h = get_header(resp, "content-length", "")
        if h and h.isdigit():
            return int(h)
    except Exception:
        pass
    try:
        return len(body_bytes(resp))
    except Exception:
        return 0


def safe_str(value: Any, default: str = "") -> str:
    return default if value is None else str(value)


def truncate(text: str, max_len: int = 2000) -> str:
    if not text or len(text) <= max_len:
        return text or ""
    return text[: max_len - 1] + "…"


def is_html(resp: Any) -> bool:
    return "html" in content_type(resp)


def is_json(resp: Any) -> bool:
    ct = content_type(resp)
    return "json" in ct or "javascript" in ct


def is_json_response(resp: Any) -> bool:
    return is_json(resp)


def safe_json(resp: Any) -> Any:
    try:
        import json
        return json.loads(body_text(resp))
    except Exception:
        return None


def headers_of(resp: Any) -> dict[str, str]:
    return response_headers_lower(resp)


def status_code_of(resp: Any) -> int:
    return status_of(resp)


def response_url(resp: Any) -> str:
    return url_of(resp)


def body_of(resp: Any) -> str:
    return body_text(resp)


def response_body(resp: Any, max_bytes: int = 200_000) -> str:
    return body_text(resp, max_bytes=max_bytes)


def extract_cookies(resp: Any) -> dict[str, str]:
    try:
        out: dict[str, str] = {}
        headers = getattr(resp, "headers", None)
        if headers is None:
            return out
        raws = headers.get_list("set-cookie") if hasattr(headers, "get_list") else [v for k, v in headers.items() if k.lower() == "set-cookie"]
        from http.cookies import SimpleCookie
        for raw in raws or []:
            c = SimpleCookie()
            try:
                c.load(raw)
            except Exception:
                continue
            for k, morsel in c.items():
                out[k] = morsel.value
        return out
    except Exception:
        return {}


def parse_cookies(resp: Any) -> dict[str, str]:
    return extract_cookies(resp)


# ═══════════════════════════════════════════════════════════════
#  URL / ID Parameter Heuristics
# ═══════════════════════════════════════════════════════════════

_URL_PARAM_NAMES = {
    "url", "uri", "link", "href", "redirect", "redirect_uri", "redirect_url",
    "next", "next_url", "continue", "continue_url", "return", "return_to",
    "return_url", "return_uri", "return_path", "target", "target_url",
    "to", "dest", "destination", "destination_url", "goto", "forward",
    "callback", "callback_url", "redir", "redirect_to",
    "image", "img", "file", "path", "src", "source", "view", "load", "fetch",
    "reference", "ref", "site", "location", "domain",
}

_ID_PARAM_PATTERNS = _re.compile(
    r"^(id|user_?id|account_?id|item_?id|order_?id|doc_?id|file_?id|profile_?id|customer_?id|uid|uuid|guid|member_?id|number|no)$",
    _re.IGNORECASE,
)


def looks_like_url_param(name: str) -> bool:
    if not name:
        return False
    normalized = name.strip().lower().replace("-", "_")
    if normalized in _URL_PARAM_NAMES:
        return True
    return any(normalized.endswith(s) for s in ("_url", "_uri", "_link", "_target", "_path", "_file"))


def looks_like_id_param(name: str, value: str = "") -> bool:
    if not name:
        return False
    clean = name.strip().lower().replace("-", "_")
    if _ID_PARAM_PATTERNS.match(clean) or clean.endswith("_id") or clean.startswith("id_"):
        return True
    if value:
        v = str(value).strip()
        if v.isdigit() or (len(v) == 36 and v.count("-") == 4):
            if any(tok in clean for tok in ("id", "user", "account", "order", "item", "doc", "num", "no")):
                return True
    return False


__all__ = [
    "ModuleContext",
    "SecurityModule",
    "body_text",
    "body_text_lower",
    "body_bytes",
    "body_of",
    "response_body",
    "text_of",
    "response_headers_lower",
    "headers_of",
    "get_header",
    "header",
    "content_type",
    "status_of",
    "status_code_of",
    "url_of",
    "response_url",
    "is_success",
    "is_redirect",
    "location_of",
    "content_length",
    "is_html",
    "is_json",
    "is_json_response",
    "safe_json",
    "build_response_evidence",
    "in_scope_urls",
    "extract_params",
    "extract_param_names",
    "extract_param_values",
    "has_params",
    "build_url_with_params",
    "replace_param",
    "with_param",
    "set_param",
    "remove_param",
    "extract_cookies",
    "parse_cookies",
    "safe_str",
    "truncate",
    "looks_like_url_param",
    "looks_like_id_param",
]
