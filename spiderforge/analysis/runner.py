from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

from spiderforge.analysis.base import ModuleContext, SecurityModule
from spiderforge.core.events import Event, EventBus, EventType
from spiderforge.findings.models import Finding
from spiderforge.findings.severity import rank
from spiderforge.scope.validator import ScopeValidator
from spiderforge.utils.logging import get_logger

log = get_logger("analysis.runner")


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    module_errors: dict[str, str] = field(default_factory=dict)
    modules_run: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate by fingerprint, keeping the highest-confidence entry."""
    by_fp: dict[str, Finding] = {}
    for f in findings:
        existing = by_fp.get(f.fingerprint)
        if existing is None:
            by_fp[f.fingerprint] = f
            continue
        if f.confidence > existing.confidence:
            by_fp[f.fingerprint] = f
    return list(by_fp.values())


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (-rank(f.severity), -f.confidence.to_float(), f.url),
    )


async def run_modules(
    modules: list[SecurityModule],
    *,
    ctx: ModuleContext,
    bus: EventBus | None = None,
) -> AnalysisResult:
    result = AnalysisResult()

    for module in modules:
        if bus:
            await bus.emit(
                Event(
                    EventType.SCAN_STARTED,
                    message=f"module:{module.name}",
                    data={"phase": "analysis", "module": module.name},
                )
            )
        try:
            findings = await module.run(ctx)
        except Exception as exc:  # noqa: BLE001 — one module must never kill the scan
            log.exception("module crashed: %s", module.name)
            result.module_errors[module.name] = f"{type(exc).__name__}: {exc}"
            if bus:
                await bus.emit(
                    Event(EventType.ERROR, message=f"{module.name}: {exc}")
                )
            continue

        result.modules_run.append(module.name)
        result.findings.extend(findings)

        if bus:
            await bus.emit(
                Event(
                    EventType.SCAN_FINISHED,
                    message=f"module:{module.name}",
                    data={"phase": "analysis", "module": module.name, "findings": len(findings)},
                )
            )

    result.findings = sort_findings(dedupe_findings(result.findings))

    by_sev: dict[str, int] = {}
    for f in result.findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1

    result.stats = {
        "modules_run": len(result.modules_run),
        "findings": len(result.findings),
        "by_severity": by_sev,
        "module_errors": len(result.module_errors),
    }
    return result


def make_context(
    *,
    target: str,
    scope: ScopeValidator,
    client: httpx.AsyncClient,
    config,
    crawl_result=None,
    discovery_result=None,
    recon_result=None,
    bus: EventBus | None = None,
    options: dict | None = None,
) -> ModuleContext:
    parts = urlsplit(target)
    origin = f"{parts.scheme}://{parts.netloc}"
    return ModuleContext(
        target=target,
        origin=origin,
        scope=scope,
        client=client,
        config=config,
        crawl_result=crawl_result,
        discovery_result=discovery_result,
        recon_result=recon_result,
        bus=bus,
        logger=log,
        options=options or {},
    )
