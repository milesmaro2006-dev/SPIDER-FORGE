from __future__ import annotations

from spiderforge.analysis.base import (
    ModuleContext,
    SecurityModule,
    body_text,
    extract_params,
    in_scope_urls,
    with_param,
)
from spiderforge.findings.models import Evidence, Finding, Severity

# (payload, expected_marker, family)
PAYLOADS: tuple[tuple[str, str, str], ...] = (
    ("{{7*7}}", "49", "Jinja2 / Twig / Django-like"),
    ("${7*7}", "49", "JSP EL / Freemarker"),
    ("#{7*7}", "49", "Ruby (ERB-like) / Thymeleaf"),
    ("<%= 7*7 %>", "49", "ERB / EJS"),
    ("{{7*'7'}}", "7777777", "Jinja2 (string multiply)"),
)


class SstiModule(SecurityModule):
    name = "ssti"
    category = "injection"
    description = "Detect template-expression evaluation (multiple families)."

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        urls = in_scope_urls(ctx, require_params=True)[:15]

        for url in urls:
            for name, _original in extract_params(url):
                # Baseline: does the plain marker appear unchanged?
                marker = "SF_TEMPLATE_CANARY_249"
                base_url = with_param(url, name, marker)
                if not ctx.scope.is_allowed(base_url):
                    continue
                try:
                    base_resp = await ctx.client.get(base_url, follow_redirects=False)
                except Exception:
                    continue
                base_body = body_text(base_resp)
                if marker not in base_body:
                    continue  # parameter not reflected at all → skip

                for payload, expected, family in PAYLOADS:
                    test_url = with_param(url, name, payload)
                    if not ctx.scope.is_allowed(test_url):
                        continue
                    try:
                        resp = await ctx.client.get(test_url, follow_redirects=False)
                    except Exception:
                        continue
                    body = body_text(resp)

                    # Real evaluation: the literal payload should NOT appear,
                    # but the computed value SHOULD.
                    payload_echoed = payload in body
                    value_present = expected in body
                    if value_present and not payload_echoed:
                        findings.append(
                            self.make_finding(
                                title=f"SSTI in `{name}` (evaluated: {family})",
                                category="ssti.evaluated",
                                severity=Severity.HIGH,
                                url=url,
                                parameter=name,
                                description=(
                                    f"Payload `{payload}` was evaluated to `{expected}` "
                                    f"by the server template engine ({family})."
                                ),
                                impact="Template injection often escalates to "
                                "server-side code execution (e.g. via Jinja2 "
                                "`__class__` chains or Twig filters), leading to full "
                                "server compromise.",
                                remediation="Do not build templates from user input. "
                                "If users must supply fragments, use a sandboxed "
                                "template engine with a strict allow-list of filters "
                                "and disable dangerous builtins.",
                                confidence=0.9,
                                evidence=Evidence(
                                    request=f"GET {test_url}",
                                    response=f"HTTP {resp.status_code}\n\n"
                                    + body[:3000],
                                    payload=payload,
                                    notes=f"family={family}, expected={expected}",
                                ),
                                root_cause=f"ssti:{name}:{family}",
                            )
                        )
                        break
        return findings
