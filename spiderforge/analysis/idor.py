from __future__ import annotations

import re

from spiderforge.analysis.base import (
    ModuleContext,
    SecurityModule,
    body_text,
    extract_params,
    in_scope_urls,
    looks_like_id_param,
    with_param,
)
from spiderforge.findings.models import Evidence, Finding, Severity

_NUMERIC = re.compile(r"^\d+$")
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


def _next_value(value: str) -> str | None:
    if _NUMERIC.match(value):
        n = int(value)
        return str(n + 1) if n < 2**31 else None
    if _UUID.match(value):
        tail = value[-1].lower()
        bumped = "0" if tail == "f" else f"{int(tail, 16) + 1:x}"
        return value[:-1] + bumped
    return None


class IdorModule(SecurityModule):
    name = "idor"
    category = "access_control"
    description = "Heuristic IDOR / BOLA candidate detection (manual verification)."

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        urls = in_scope_urls(ctx)[:30]

        for url in urls:
            params = extract_params(url)
            items = params.items() if hasattr(params, "items") else params

            for item in items:
                if isinstance(item, tuple) and len(item) == 2:
                    name, value = item
                else:
                    name, value = str(item), ""

                if not looks_like_id_param(name, value):
                    continue
                alt = _next_value(value)
                if alt is None or alt == value:
                    continue
                candidate = with_param(url, name, alt)
                if not ctx.scope.is_allowed(candidate):
                    continue
                finding = await self._compare(ctx, url, candidate, name, value, alt, "url")
                if finding:
                    findings.append(finding)

        return findings

    async def _compare(
        self,
        ctx: ModuleContext,
        original_url: str,
        candidate_url: str,
        name: str,
        original_value: str,
        alt_value: str,
        where: str,
    ) -> Finding | None:
        try:
            r1 = await ctx.client.get(original_url, follow_redirects=False)
            r2 = await ctx.client.get(candidate_url, follow_redirects=False)
        except Exception:
            return None

        if r1.status_code != 200 or r2.status_code != 200:
            return None

        b1 = body_text(r1)
        b2 = body_text(r2)
        if not b1 or not b2:
            return None

        len_diff = abs(len(b1) - len(b2))
        rel = len_diff / max(len(b1), len(b2), 1)
        if rel > 0.5:
            return None

        if b1 == b2:
            return None

        return self.make_finding(
            title=f"IDOR candidate on `{name}`",
            category="idor.candidate",
            severity=Severity.INFO,
            url=original_url,
            parameter=name,
            description=(
                f"Changing `{name}` from `{original_value}` to `{alt_value}` "
                "returned a different 200 response of similar size. This is a "
                "candidate IDOR — confirm manually by authenticating as another "
                "user and checking whether object ownership is enforced."
            ),
            impact="If ownership is not checked server-side, users can read or "
            "modify other users' objects by changing the ID.",
            remediation="Enforce object-level authorization on every request. "
            "Validate that the authenticated principal owns the referenced object "
            "(or is otherwise authorized), regardless of how the ID was supplied.",
            confidence=0.35,
            evidence=Evidence(
                request=f"GET {original_url}\n--- vs ---\nGET {candidate_url}",
                response=(
                    f"len_original={len(b1)} len_candidate={len(b2)} "
                    f"relative_diff={rel:.2f}"
                ),
                notes="Candidate only — no authenticated cross-user test performed.",
            ),
            root_cause=f"idor:{name}",
        )
