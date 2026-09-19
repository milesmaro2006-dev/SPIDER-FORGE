from __future__ import annotations

import re
import secrets

from spiderforge.analysis.base import (
    ModuleContext,
    SecurityModule,
    body_text,
    extract_params,
    in_scope_urls,
    with_param,
)
from spiderforge.findings.models import Evidence, Finding, Severity


def _html_context_score(body: str, marker: str) -> tuple[bool, str | None]:
    """Return (is_injectable, context). Detects raw marker HTML tags in body."""
    open_tag = f"<{marker}>"
    if open_tag in body:
        # Check whether the surrounding context looks like HTML
        if re.search(re.escape(open_tag) + r"[\s\S]{0,200}?" + re.escape(f"</{marker}>"), body):
            return True, "html"
        return True, "html"
    # Attribute injection — look for the literal `"` we sent next to the marker
    attr = f'"{marker}'
    if attr in body:
        return True, "attribute"
    return False, None


class XssModule(SecurityModule):
    name = "xss"
    category = "injection"
    description = "Reflected XSS detection with context identification."

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        urls = in_scope_urls(ctx, require_params=True)[:15]

        for url in urls:
            for name, original in extract_params(url):
                tag = "sf" + secrets.token_hex(4)
                html_payload = f"<{tag}>sfx</{tag}>"
                attr_payload = f'"{tag}'

                for payload, kind in ((html_payload, "html"), (attr_payload, "attr")):
                    test_url = with_param(url, name, payload)
                    if not ctx.scope.is_allowed(test_url):
                        continue
                    try:
                        resp = await ctx.client.get(test_url, follow_redirects=False)
                    except Exception:
                        continue
                    if resp.status_code >= 500:
                        continue

                    body = body_text(resp)
                    ctype = (resp.headers.get("content-type") or "").lower()
                    if "html" not in ctype and "xml" not in ctype:
                        continue

                    if kind == "html":
                        reflected = f"<{tag}>" in body
                        context = "HTML element"
                    else:
                        reflected = f'"{tag}' in body
                        context = "HTML attribute"

                    if not reflected:
                        continue

                    # Escalation: was a raw `<` or `"` preserved unescaped?
                    escaped_variants = [
                        f"&lt;{tag}&gt;",
                        f"&quot;{tag}",
                        f"&#34;{tag}",
                    ]
                    if any(v in body for v in escaped_variants):
                        # Encoded — only reflection
                        continue

                    findings.append(
                        self.make_finding(
                            title=f"Reflected XSS in `{name}` ({context})",
                            category="xss.reflected",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=name,
                            description=(
                                f"Parameter `{name}` reflects the injected payload "
                                f"into {context} without encoding. Original value: "
                                f"`{original[:60]}`."
                            ),
                            impact="An attacker can execute arbitrary JavaScript in "
                            "victims' browsers in the origin's context (session theft, "
                            "CSRF, data exfiltration).",
                            remediation="Context-aware output encoding: HTML-encode on "
                            "HTML contexts, attribute-encode on attribute contexts, "
                            "and JS-encode before embedding in scripts. Add a strict "
                            "Content-Security-Policy as defense-in-depth.",
                            confidence=0.9,
                            evidence=Evidence(
                                request=f"GET {test_url}",
                                response=f"HTTP {resp.status_code}\n\n"
                                + body[:3000],
                                payload=payload,
                                notes=f"reflected unescaped in {context}",
                            ),
                            root_cause=f"xss_reflected:{name}",
                        )
                    )
                    break  # one finding per parameter is enough
        return findings
