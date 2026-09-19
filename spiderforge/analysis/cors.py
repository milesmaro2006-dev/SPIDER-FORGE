from __future__ import annotations

import asyncio

from spiderforge.analysis.base import (
    ModuleContext,
    SecurityModule,
    build_response_evidence,
    in_scope_urls,
)
from spiderforge.findings.models import Evidence, Finding, Severity
from spiderforge.utils.urls import normalize_url

EVIL_ORIGIN = "https://spiderforge-evil.example"


class CorsModule(SecurityModule):
    name = "cors"
    category = "configuration"
    description = "Test for CORS misconfigurations (reflection, wildcard + creds)."

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        urls = in_scope_urls(ctx)[:10]

        async def _check(url: str) -> None:
            # Send a GET with a controlled Origin header. Use ctx.get() so the
            # request goes through the SafeHttpClient when available.
            try:
                resp = await ctx.get(url, headers={"Origin": EVIL_ORIGIN})
            except Exception:
                return

            acao = resp.headers.get("access-control-allow-origin")
            acac = (resp.headers.get("access-control-allow-credentials") or "").lower()

            if not acao:
                return

            if acao == "*" and acac == "true":
                findings.append(
                    self.make_finding(
                        title="CORS: wildcard origin with credentials",
                        category="cors.wildcard_credentials",
                        severity=Severity.HIGH,
                        url=str(resp.url),
                        description="Response returns "
                        "`Access-Control-Allow-Origin: *` together with "
                        "`Access-Control-Allow-Credentials: true`.",
                        impact="Browsers reject this combination, but proxies and "
                        "older implementations may forward authenticated cross-"
                        "origin requests, leaking user data.",
                        remediation="Return a specific origin from an allow-list "
                        "when `Access-Control-Allow-Credentials: true` is set.",
                        confidence=0.9,
                        evidence=Evidence(
                            request=f"GET {url}\nOrigin: {EVIL_ORIGIN}",
                            response=build_response_evidence(resp, max_body=0),
                            notes=f"ACAO={acao}, ACAC={acac}",
                        ),
                        root_cause="cors_wildcard_credentials",
                    )
                )
                return

            if acao == EVIL_ORIGIN and acac == "true":
                findings.append(
                    self.make_finding(
                        title="CORS: arbitrary origin reflection with credentials",
                        category="cors.origin_reflection_creds",
                        severity=Severity.HIGH,
                        url=str(resp.url),
                        description="The server reflects any supplied `Origin` header "
                        "back as `Access-Control-Allow-Origin`, and also sets "
                        "`Access-Control-Allow-Credentials: true`.",
                        impact="Any attacker-controlled site can read authenticated "
                        "responses from this origin on behalf of a logged-in user.",
                        remediation="Use a strict allow-list of trusted origins. Never "
                        "reflect arbitrary Origin values when credentials are enabled.",
                        confidence=0.95,
                        evidence=Evidence(
                            request=f"GET {url}\nOrigin: {EVIL_ORIGIN}",
                            response=build_response_evidence(resp, max_body=0),
                            notes=f"ACAO={acao}, ACAC={acac}",
                        ),
                        root_cause="cors_origin_reflection_credentials",
                    )
                )
                return

            if acao == EVIL_ORIGIN:
                findings.append(
                    self.make_finding(
                        title="CORS: arbitrary origin reflection",
                        category="cors.origin_reflection",
                        severity=Severity.MEDIUM,
                        url=str(resp.url),
                        description="The server echoes any supplied `Origin` header "
                        "into `Access-Control-Allow-Origin`.",
                        impact="Cross-origin reads are enabled for untrusted sites; "
                        "impact is lower without `Access-Control-Allow-Credentials: true`.",
                        remediation="Return a fixed origin or validate against an "
                        "allow-list.",
                        confidence=0.85,
                        evidence=Evidence(
                            request=f"GET {url}\nOrigin: {EVIL_ORIGIN}",
                            response=build_response_evidence(resp, max_body=0),
                            notes=f"ACAO={acao}",
                        ),
                        root_cause="cors_origin_reflection",
                    )
                )

        await asyncio.gather(*(_check(normalize_url(u)) for u in urls), return_exceptions=True)
        return findings
