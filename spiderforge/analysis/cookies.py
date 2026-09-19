from __future__ import annotations

import asyncio
from http.cookies import SimpleCookie

from spiderforge.analysis.base import (
    ModuleContext,
    SecurityModule,
    build_response_evidence,
    in_scope_urls,
)
from spiderforge.findings.models import Evidence, Finding, Severity


def _parse_set_cookie(raw: str) -> dict[str, str]:
    c = SimpleCookie()
    try:
        c.load(raw)
    except Exception:
        return {}
    if not c:
        return {}
    morsel = next(iter(c.values()))
    flags = {
        "name": morsel.key,
        "value": morsel.value,
        "secure": "secure" in raw.lower(),
        "httponly": "httponly" in raw.lower(),
    }
    low = raw.lower()
    if "samesite=none" in low:
        flags["samesite"] = "none"
    elif "samesite=lax" in low:
        flags["samesite"] = "lax"
    elif "samesite=strict" in low:
        flags["samesite"] = "strict"
    else:
        flags["samesite"] = ""
    return flags


def _is_session_cookie(name: str) -> bool:
    low = name.lower()
    return any(
        token in low
        for token in ("sess", "session", "auth", "token", "jwt", "sid", "csrf", "xsrf")
    )


class CookiesModule(SecurityModule):
    name = "cookies"
    category = "configuration"
    description = "Analyze Set-Cookie flags (Secure, HttpOnly, SameSite)."

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        urls = in_scope_urls(ctx)[:10]

        async def _check(url: str) -> None:
            resp = await ctx.get(url)
            if resp is None:
                return
            raw_cookies = resp.headers.get_list("set-cookie") if hasattr(
                resp.headers, "get_list"
            ) else [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]
            if not raw_cookies:
                return

            for raw in raw_cookies:
                flags = _parse_set_cookie(raw)
                if not flags:
                    continue
                name = flags["name"]
                is_session = _is_session_cookie(name)
                base_sev = Severity.HIGH if is_session else Severity.MEDIUM

                if not flags["secure"]:
                    findings.append(
                        self.make_finding(
                            title=f"Cookie `{name}` missing Secure flag",
                            category="cookies.secure",
                            severity=base_sev,
                            url=str(resp.url),
                            description=f"Set-Cookie for `{name}` does not set "
                            "`Secure`. The cookie can be transmitted over HTTP.",
                            impact="Session hijacking via MITM on a shared network.",
                            remediation="Add the `Secure` attribute to every sensitive "
                            "cookie.",
                            confidence=0.95,
                            evidence=Evidence(
                                request=f"GET {resp.url}",
                                response=build_response_evidence(resp, max_body=0),
                                notes=f"Set-Cookie: {raw}",
                            ),
                            root_cause="cookie_missing_secure",
                        )
                    )

                if not flags["httponly"] and is_session:
                    findings.append(
                        self.make_finding(
                            title=f"Session cookie `{name}` missing HttpOnly",
                            category="cookies.httponly",
                            severity=Severity.MEDIUM,
                            url=str(resp.url),
                            description=f"Session cookie `{name}` is readable by "
                            "JavaScript.",
                            impact="Any XSS in the origin can steal this cookie.",
                            remediation="Add the `HttpOnly` attribute.",
                            confidence=0.9,
                            evidence=Evidence(
                                request=f"GET {resp.url}",
                                response=build_response_evidence(resp, max_body=0),
                                notes=f"Set-Cookie: {raw}",
                            ),
                            root_cause="cookie_missing_httponly",
                        )
                    )

                if is_session and flags["samesite"] not in ("lax", "strict"):
                    findings.append(
                        self.make_finding(
                            title=f"Session cookie `{name}` missing SameSite",
                            category="cookies.samesite",
                            severity=Severity.MEDIUM,
                            url=str(resp.url),
                            description=f"Session cookie `{name}` has no (or too "
                            "permissive) SameSite attribute.",
                            impact="Cross-site request forgery (CSRF) becomes easier "
                            "to exploit.",
                            remediation="Set `SameSite=Lax` (default safe choice) or "
                            "`SameSite=Strict` for CSRF-sensitive cookies.",
                            confidence=0.85,
                            evidence=Evidence(
                                request=f"GET {resp.url}",
                                response=build_response_evidence(resp, max_body=0),
                                notes=f"Set-Cookie: {raw}",
                            ),
                            root_cause="cookie_missing_samesite",
                        )
                    )

        await asyncio.gather(*(_check(u) for u in urls), return_exceptions=True)
        return findings
