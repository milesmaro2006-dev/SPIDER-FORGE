from __future__ import annotations

from urllib.parse import urlsplit

from spiderforge.analysis.base import (
    ModuleContext,
    SecurityModule,
    build_response_evidence,
    extract_params,
    in_scope_urls,
    looks_like_url_param,
    with_param,
)
from spiderforge.findings.models import Evidence, Finding, Severity

MARKER = "https://spiderforge-redirect.example/pwn"


class RedirectsModule(SecurityModule):
    name = "redirects"
    category = "logic"
    description = "Test for open redirects on URL-like parameters."

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        urls = in_scope_urls(ctx, require_params=True)[:15]

        for url in urls:
            for name, _ in extract_params(url):
                if not looks_like_url_param(name):
                    continue
                test_url = with_param(url, name, MARKER)
                if not ctx.scope.is_allowed(test_url):
                    continue
                try:
                    resp = await ctx.client.get(test_url, follow_redirects=False)
                except Exception:
                    continue
                location = resp.headers.get("location", "")
                if not location:
                    continue
                # Check if the Location points to the marker or its host
                loc_parts = urlsplit(location)
                if "spiderforge-redirect.example" in location or loc_parts.netloc == "spiderforge-redirect.example":
                    findings.append(
                        self.make_finding(
                            title=f"Open redirect via `{name}`",
                            category="redirects.open",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter=name,
                            description="The application issues a redirect to an "
                            "attacker-supplied absolute URL.",
                            impact="Phishing: attackers can craft links on the trusted "
                            "domain that silently redirect victims to malicious sites.",
                            remediation="Validate redirect targets against an allow-"
                            "list of paths/hosts. Do not trust user-supplied URLs.",
                            confidence=0.9,
                            evidence=Evidence(
                                request=f"GET {test_url}",
                                response=build_response_evidence(resp, max_body=0),
                                payload=MARKER,
                                notes=f"Location: {location}",
                            ),
                            root_cause=f"open_redirect:{name}",
                        )
                    )
        return findings
