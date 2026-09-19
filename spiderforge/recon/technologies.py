from __future__ import annotations

import re
from dataclasses import dataclass

from spiderforge.recon.http_probe import ProbeResult

_VER_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


def _ver_from(s: str) -> str | None:
    m = _VER_RE.search(s)
    return m.group(1) if m else None


@dataclass
class Technology:
    name: str
    category: str = "other"
    version: str | None = None
    evidence: str = ""
    confidence: float = 0.5


_SERVER_SIGNATURES: list[tuple[str, str]] = [
    ("nginx", r"nginx(?:/([\d.]+))?"),
    ("Apache", r"apache(?:/([\d.]+))?"),
    ("IIS", r"microsoft-iis(?:/([\d.]+))?"),
    ("LiteSpeed", r"litespeed"),
    ("Caddy", r"caddy"),
    ("Cloudflare", r"cloudflare"),
]

_POWERED_SIGNATURES: list[tuple[str, str]] = [
    ("PHP", r"PHP(?:/([\d.]+))?"),
    ("Express", r"express"),
    ("ASP.NET", r"asp\.net"),
    ("Next.js", r"next\.js"),
    ("Nuxt", r"nuxt"),
]


def _from_headers(headers: dict[str, str]) -> list[Technology]:
    found: list[Technology] = []
    server = headers.get("server", "")
    if server:
        for name, pattern in _SERVER_SIGNATURES:
            m = re.search(pattern, server, re.IGNORECASE)
            if m:
                found.append(
                    Technology(
                        name=name,
                        category="server",
                        version=(m.group(1) if m.lastindex else None) or _ver_from(server),
                        evidence=f"server: {server}",
                        confidence=0.9,
                    )
                )
    powered = headers.get("x-powered-by", "")
    if powered:
        for name, pattern in _POWERED_SIGNATURES:
            m = re.search(pattern, powered, re.IGNORECASE)
            if m:
                found.append(
                    Technology(
                        name=name,
                        category="framework",
                        version=(m.group(1) if m.lastindex else None),
                        evidence=f"x-powered-by: {powered}",
                        confidence=0.9,
                    )
                )
    return found


_HEADER_HINTS: list[tuple[str, str, float]] = [
    ("cf-ray", "Cloudflare", 0.95),
    ("x-vercel-id", "Vercel", 0.95),
    ("x-amz-cf-id", "AWS CloudFront", 0.95),
    ("x-azure-ref", "Azure Front Door", 0.9),
    ("x-github-request-id", "GitHub Pages", 0.9),
    ("x-shopify-stage", "Shopify", 0.95),
    ("x-drupal-cache", "Drupal", 0.9),
    ("x-generator", "Generator", 0.6),
]


def _from_headers_extended(headers: dict[str, str]) -> list[Technology]:
    found: list[Technology] = []
    for header, name, conf in _HEADER_HINTS:
        if header in headers:
            found.append(
                Technology(
                    name=name,
                    category="cdn" if conf >= 0.9 else "other",
                    evidence=f"header: {header}={headers[header][:60]}",
                    confidence=conf,
                )
            )
    return found


_COOKIE_SIGNATURES: list[tuple[str, str]] = [
    ("wordpress_", "WordPress"),
    ("wp-settings", "WordPress"),
    ("drupal", "Drupal"),
    ("joomla", "Joomla"),
    ("laravel_session", "Laravel"),
    ("csrftoken", "Django"),
    ("phpsessid", "PHP"),
    ("asp.net_sessionid", "ASP.NET"),
]


def _from_cookies(set_cookie_header: str) -> list[Technology]:
    found: list[Technology] = []
    low = set_cookie_header.lower()
    for sig, name in _COOKIE_SIGNATURES:
        if sig in low:
            found.append(
                Technology(
                    name=name,
                    category="framework",
                    evidence=f"cookie signature: {sig}",
                    confidence=0.75,
                )
            )
    return found


_META_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

_HTML_SIGNATURES: list[tuple[str, str]] = [
    ("React", r"react(?:\.min)?\.js"),
    ("Vue.js", r"vue(?:\.min)?\.js"),
    ("Angular", r"angular(?:\.min)?\.js"),
    ("jQuery", r"jquery(?:-[\d.]+)?(?:\.min)?\.js"),
    ("Bootstrap", r"bootstrap(?:\.min)?\.(?:js|css)"),
    ("Cloudflare CDN", r"cdnjs\.cloudflare\.com"),
    ("Google Analytics", r"google-analytics\.com|googletagmanager\.com"),
    ("Next.js", r"/_next/static"),
    ("Nuxt", r"/_nuxt/"),
]


def _from_html(html: str) -> list[Technology]:
    found: list[Technology] = []
    if not html:
        return found

    m = _META_GENERATOR_RE.search(html)
    if m:
        content = m.group(1)
        found.append(
            Technology(
                name="Meta Generator",
                category="cms",
                version=_ver_from(content),
                evidence=f"meta generator: {content[:80]}",
                confidence=0.85,
            )
        )
        for cms in ("WordPress", "Drupal", "Joomla", "TYPO3"):
            if cms.lower() in content.lower():
                found.append(
                    Technology(
                        name=cms,
                        category="cms",
                        version=_ver_from(content),
                        evidence=f"meta generator: {content[:80]}",
                        confidence=0.9,
                    )
                )

    for name, sig in _HTML_SIGNATURES:
        if re.search(sig, html, re.IGNORECASE):
            found.append(
                Technology(
                    name=name,
                    category="frontend",
                    evidence=f"html pattern: {sig}",
                    confidence=0.7,
                )
            )

    if "__NEXT_DATA__" in html:
        found.append(
            Technology(
                name="Next.js",
                category="frontend",
                evidence="__NEXT_DATA__ payload present",
                confidence=0.9,
            )
        )

    m2 = re.search(r'ng-version=["\']([\d.]+)["\']', html)
    if m2:
        found.append(
            Technology(
                name="Angular",
                category="frontend",
                version=m2.group(1),
                evidence="ng-version attribute",
                confidence=0.85,
            )
        )

    return found


def detect(probe: ProbeResult) -> list[Technology]:
    """Signature-based technology detection with dedup by name."""
    found: list[Technology] = []
    found.extend(_from_headers(probe.headers))
    found.extend(_from_headers_extended(probe.headers))

    set_cookie = probe.headers.get("set-cookie", "")
    if set_cookie:
        found.extend(_from_cookies(set_cookie))

    if probe.body_snippet:
        found.extend(_from_html(probe.body_snippet))

    # Deduplicate by name; keep the highest-confidence entry
    by_name: dict[str, Technology] = {}
    for t in found:
        existing = by_name.get(t.name)
        if existing is None or t.confidence > existing.confidence:
            by_name[t.name] = t

    return sorted(by_name.values(), key=lambda t: (-t.confidence, t.name))
