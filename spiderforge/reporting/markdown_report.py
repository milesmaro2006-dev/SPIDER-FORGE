from __future__ import annotations

from pathlib import Path

from spiderforge.findings.models import Confidence
from spiderforge.findings.severity import to_cvss_label
from spiderforge.reporting.models import ReportContext


def _conf_float(value) -> float:
    """Return a numeric 0.0–1.0 confidence from enum, float, or int."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, Confidence):
        return value.to_float()
    if hasattr(value, "to_float"):
        return value.to_float()  # type: ignore[no-any-return]
    return 0.5


def _sev_emoji(sev: str) -> str:
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }.get(sev, "•")


def _sev_to_enum(name: str):
    from spiderforge.findings.models import Severity

    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }[name]


def render(ctx: ReportContext, out_path: Path) -> Path:
    lines: list[str] = []
    m = ctx.meta

    lines += [
        "# SpiderForge — Security Assessment Report",
        "",
        f"**Project:** {m.project_name}  ",
        f"**Scan ID:** `{m.scan_id}`  ",
        f"**Target:** `{m.target}`  ",
        f"**Started:** {m.started_at}  ",
        f"**Finished:** {m.finished_at or '—'}  ",
        f"**Author:** {m.author}",
        "",
        "---",
        "",
        "## Executive summary",
        "",
    ]

    counts = ctx.severity_counts()
    total = sum(counts.values())
    lines += [
        f"The scan produced **{total}** findings across the assessed attack surface.",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(
            f"| {_sev_emoji(sev)} {to_cvss_label(_sev_to_enum(sev))} "
            f"| {counts.get(sev, 0)} |"
        )
    lines += ["", "---", "", "## Scope", "", "**Included:**", ""]
    for i in ctx.scope_include or ["—"]:
        lines.append(f"- `{i}`")
    lines += ["", "**Excluded:**", ""]
    for e in ctx.scope_exclude or ["—"]:
        lines.append(f"- `{e}`")

    lines += ["", "---", "", "## Methodology", ""]
    lines += [
        "1. Scope validation for every outbound request.",
        "2. Reconnaissance: DNS, HTTP probe, technology detection, robots.txt, sitemap.",
        "3. Crawling: scope-aware, async, form/JS/parameter extraction.",
        "4. Discovery: endpoint templating, parameter typing, API clustering, "
        "JS static analysis, Swagger/OpenAPI, GraphQL detection, hidden-path probing.",
        "5. Analysis: security headers, cookies, CORS, redirects, XSS, SQLi, SSTI, "
        "command injection, path traversal, file upload, IDOR.",
        "6. Evidence collection and finding deduplication.",
        "7. Report generation.",
    ]

    lines += ["", "---", "", "## Findings summary", ""]
    if not ctx.findings:
        lines.append("_No findings._")
    else:
        lines += [
            "| ID | Severity | Conf | Category | Title |",
            "|---|---|---|---|---|",
        ]
        for f in ctx.findings:
            conf = _conf_float(f.confidence)
            lines.append(
                f"| `{f.id}` | {_sev_emoji(f.severity.value.lower())} "
                f"{f.severity.value.upper()} | {conf:.2f} | {f.category} | {f.title} |"
            )

    lines += ["", "---", "", "## Detailed findings", ""]
    for f in ctx.findings:
        conf = _conf_float(f.confidence)
        lines += [
            f"### `{f.id}` — {f.title}",
            "",
            f"- **Severity:** {f.severity.value.upper()}",
            f"- **Confidence:** {conf:.2f}",
        ]
        if f.cvss_score is not None:
            lines.append(f"- **CVSS:** {f.cvss_score} (`{f.cvss_vector}`)")
        lines += [
            f"- **Category:** `{f.category}`",
            f"- **URL:** `{f.url}`",
            f"- **Method:** {f.http_method}",
        ]
        if f.parameter:
            lines.append(f"- **Parameter:** `{f.parameter}`")
        lines.append("")

        if f.description:
            lines += ["**Description**", "", f.description, ""]
        if f.impact:
            lines += ["**Impact**", "", f.impact, ""]

        # Evidence (list — first item used for legacy single-evidence rendering)
        if f.evidence:
            ev = f.evidence[0]
            if ev.payload:
                lines += ["**Payload**", "", "```", ev.payload, "```", ""]
            # Legacy evidence fields support — if response_body starts with
            # "GET " / "HTTP/" treat as request/response
            if ev.request_body and ev.request_body.startswith(("GET ", "POST ", "PUT ")):
                lines += ["**Request**", "", "```http", ev.request_body[:2000], "```", ""]
            if ev.response_body:
                lines += [
                    "**Response (excerpt)**", "",
                    "```http", ev.response_body[:2000], "```", "",
                ]
        if f.remediation:
            lines += ["**Remediation**", "", f.remediation, ""]
        lines.append("---")
        lines.append("")

    lines += ["", "## Appendix — module errors", ""]
    if ctx.module_errors:
        for name, err in ctx.module_errors.items():
            lines.append(f"- **{name}**: {err}")
    else:
        lines.append("_No module errors._")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path
