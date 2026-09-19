from __future__ import annotations

import asyncio

from spiderforge.analysis.base import (
    ModuleContext,
    SecurityModule,
    build_response_evidence,
    in_scope_urls,
)
from spiderforge.findings.models import Evidence, Finding, Severity

# (header, severity, title, remediation)
CHECKS: tuple[tuple[str, Severity, str, str], ...] = (
    (
        "content-security-policy",
        Severity.MEDIUM,
        "Missing Content-Security-Policy",
        "Define a Content-Security-Policy that restricts script-src, object-src, "
        "and frame-ancestors to trusted origins. Start with a report-only policy "
        "and iterate toward enforcement.",
    ),
    (
        "strict-transport-security",
        Severity.MEDIUM,
        "Missing HTTP Strict-Transport-Security",
        "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` on "
        "HTTPS responses. Consider `preload` if the whole domain is HTTPS-only.",
    ),
    (
        "x-content-type-options",
        Severity.LOW,
        "Missing X-Content-Type-Options",
        "Set `X-Content-Type-Options: nosniff` on all responses to prevent MIME "
        "sniffing.",
    ),
    (
        "referrer-policy",
        Severity.LOW,
        "Missing Referrer-Policy",
        "Set `Referrer-Policy: strict-origin-when-cross-origin` (or stricter) to "
        "reduce referrer leakage.",
    ),
    (
        "permissions-policy",
        Severity.INFO,
        "Missing Permissions-Policy",
        "Define a Permissions-Policy to disable browser features the application "
        "does not use (camera, geolocation, microphone, etc.).",
    ),
)


class HeadersModule(SecurityModule):
    name = "headers"
    category = "configuration"
    description = "Check security-relevant HTTP response headers."

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        urls = in_scope_urls(ctx)[:20]

        async def _check(url: str) -> None:
            resp = await ctx.get(url)
            if resp is None or resp.status_code >= 400:
                return
            # Only apply header rules to HTML responses — APIs, images, etc. don't
            # need CSP/HSTS the same way.
            ctype = (resp.headers.get("content-type") or "").lower()
            if "html" not in ctype:
                return

            headers = {k.lower(): v for k, v in resp.headers.items()}
            # X-Frame-Options / CSP frame-ancestors — one or the other
            has_csp_frame = "frame-ancestors" in headers.get("content-security-policy", "")
            has_xfo = "x-frame-options" in headers
            if not (has_csp_frame or has_xfo):
                findings.append(
                    self.make_finding(
                        title="Missing clickjacking protection",
                        category="headers.clickjacking",
                        severity=Severity.MEDIUM,
                        url=str(resp.url),
                        description="Neither `Content-Security-Policy: frame-ancestors` "
                        "nor `X-Frame-Options` is set. The page can be embedded in "
                        "an attacker-controlled iframe.",
                        impact="Clickjacking: an attacker can overlay the target page "
                        "and trick users into clicking unintended controls.",
                        remediation="Add `Content-Security-Policy: frame-ancestors 'self'` "
                        "(preferred) or `X-Frame-Options: DENY`/`SAMEORIGIN`.",
                        confidence=0.9,
                        evidence=Evidence(
                            request=f"HEAD {resp.url}",
                            response=build_response_evidence(resp, max_body=0),
                            headers=dict(resp.headers.items()),
                        ),
                        root_cause="missing_clickjacking_protection",
                    )
                )

            for header, sev, title, fix in CHECKS:
                if header in headers:
                    continue
                findings.append(
                    self.make_finding(
                        title=title,
                        category=f"headers.{header.replace('-', '_')}",
                        severity=sev,
                        url=str(resp.url),
                        description=f"Response does not include `{header}`.",
                        impact="Reduces defense-in-depth; missing mitigations expose "
                        "users to a variety of client-side attacks.",
                        remediation=fix,
                        confidence=0.85,
                        evidence=Evidence(
                            request=f"HEAD {resp.url}",
                            response=build_response_evidence(resp, max_body=0),
                            headers=dict(resp.headers.items()),
                        ),
                        root_cause=f"missing_{header}",
                    )
                )

        await asyncio.gather(*(_check(u) for u in urls), return_exceptions=True)
        return findings
