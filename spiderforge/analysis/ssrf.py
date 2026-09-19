from __future__ import annotations

from spiderforge.analysis.base import (
    ModuleContext,
    SecurityModule,
    extract_params,
    in_scope_urls,
    looks_like_url_param,
)
from spiderforge.findings.models import Evidence, Finding, Severity


class SsrfModule(SecurityModule):
    name = "ssrf"
    category = "injection"
    description = "Flag URL-like parameters as SSRF test points (manual verification)."

    # We do NOT auto-request internal or callback targets. SSRF is reported as
    # a candidate requiring manual testing with the operator's own callback
    # infrastructure. This is by design.

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        urls = in_scope_urls(ctx, require_params=True)[:20]

        for url in urls:
            for name, value in extract_params(url):
                if not looks_like_url_param(name):
                    continue
                # Heuristic: current value looks like a URL or a host:path
                v = value.strip()
                if not v:
                    continue
                url_like = (
                    v.startswith(("http://", "https://", "//"))
                    or "." in v
                    or v.startswith("/")
                )
                if not url_like:
                    continue

                findings.append(
                    self.make_finding(
                        title=f"Potential SSRF surface: `{name}`",
                        category="ssrf.candidate",
                        severity=Severity.INFO,
                        url=url,
                        parameter=name,
                        description=(
                            f"Parameter `{name}` accepts URL-like values. This is "
                            "not a confirmed SSRF; it is a candidate for manual "
                            "testing against a controlled callback server (e.g. "
                            "Burp Collaborator, interactsh, or your own DNS logger)."
                        ),
                        impact="If the parameter is fetched server-side without "
                        "validation, an attacker could access internal services, "
                        "cloud metadata (169.254.169.254), or the local file system.",
                        remediation="Validate URLs against an allow-list of hosts "
                        "and schemes. Block loopback, link-local, and RFC1918 "
                        "ranges. Disable redirects, or re-validate after each hop. "
                        "Put URL fetchers behind an egress proxy with strict rules.",
                        confidence=0.3,
                        evidence=Evidence(
                            request=f"GET {url}",
                            payload=f"{name}={value}",
                            notes="Candidate only — no callback test performed.",
                        ),
                        root_cause=f"ssrf_candidate:{name}",
                    )
                )
        return findings
