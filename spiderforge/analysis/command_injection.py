from __future__ import annotations

import asyncio
import time

from spiderforge.analysis.base import (
    ModuleContext,
    SecurityModule,
    extract_params,
    in_scope_urls,
    with_param,
)
from spiderforge.findings.models import Evidence, Finding, Severity

SLEEP_SECONDS = 4
PAYLOADS: tuple[str, ...] = (
    "; sleep {n}",
    "| sleep {n}",
    "& sleep {n}",
    "`sleep {n}`",
    "$(sleep {n})",
    "&& sleep {n}",
    "|| sleep {n}",
    "%0a sleep {n}",
)
# Timing threshold: how much longer than baseline is "suspicious"
TIMING_SLACK = 2.5


class CommandInjectionModule(SecurityModule):
    name = "cmdi"
    category = "injection"
    description = "Blind OS command injection detection via timing differential."

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        urls = in_scope_urls(ctx, require_params=True)[:10]

        for url in urls:
            for name, original in extract_params(url):
                if not original:
                    continue

                # Baseline timing (2 samples, take min)
                base_times: list[float] = []
                for _ in range(2):
                    t0 = time.monotonic()
                    try:
                        await ctx.client.get(url, follow_redirects=False)
                    except Exception:
                        pass
                    base_times.append(time.monotonic() - t0)
                baseline = min(base_times)
                if baseline > 8.0:
                    continue  # already slow, timing test unreliable

                for tmpl in PAYLOADS:
                    payload = tmpl.format(n=SLEEP_SECONDS)
                    test_url = with_param(url, name, original + payload)
                    if not ctx.scope.is_allowed(test_url):
                        continue
                    t0 = time.monotonic()
                    try:
                        await ctx.client.get(test_url, follow_redirects=False)
                    except Exception:
                        continue
                    elapsed = time.monotonic() - t0

                    if elapsed - baseline >= TIMING_SLACK and elapsed >= SLEEP_SECONDS - 1.0:
                        findings.append(
                            self.make_finding(
                                title=f"Blind command injection in `{name}`",
                                category="cmdi.blind",
                                severity=Severity.CRITICAL,
                                url=url,
                                parameter=name,
                                description=(
                                    f"Payload `{payload}` caused the server to pause "
                                    f"~{elapsed:.1f}s (baseline ~{baseline:.1f}s). "
                                    "This suggests shell metacharacters are passed "
                                    "to an OS command unsafely."
                                ),
                                impact="Remote code execution on the server with the "
                                "web application's privileges.",
                                remediation="Never pass user input into a shell. Use "
                                "`subprocess.run([...], shell=False)` with a fixed "
                                "program and validated arguments. Prefer library "
                                "calls over invoking external tools.",
                                confidence=0.75,
                                evidence=Evidence(
                                    request=f"GET {test_url}",
                                    payload=payload,
                                    notes=(
                                        f"baseline={baseline:.2f}s, "
                                        f"observed={elapsed:.2f}s"
                                    ),
                                ),
                                root_cause=f"cmdi_blind:{name}",
                            )
                        )
                        break
                await asyncio.sleep(0)  # yield
        return findings
