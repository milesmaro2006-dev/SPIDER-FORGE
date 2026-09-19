from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from spiderforge.findings.models import Confidence
from spiderforge.reporting.models import ReportContext

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_ASSETS_DIR = Path(__file__).parent / "assets"


def _conf_float(value) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, Confidence):
        return value.to_float()
    if hasattr(value, "to_float"):
        return value.to_float()  # type: ignore[no-any-return]
    return 0.5


def _prepare_finding(f) -> dict:
    """Flatten a Finding into a template-friendly dict."""
    ev_list = []
    for ev in f.evidence:
        ev_list.append({
            "kind": ev.kind,
            "request_url": ev.request_url,
            "http_method": ev.http_method,
            "request_headers": ev.request_headers,
            "request_body": ev.request_body,
            "response_status": ev.response_status,
            "response_headers": ev.response_headers,
            "response_body": ev.response_body,
            "payload": ev.payload,
            "note": ev.note,
            "evidence_hash": ev.evidence_hash,
            # Legacy convenience fields
            "request": ev.request_body or ev.request_url,
            "response": ev.response_body or "",
            "notes": ev.note or "",
            "headers": ev.response_headers,
        })

    return {
        "id": f.id,
        "fingerprint": f.fingerprint,
        "title": f.title,
        "category": f.category,
        "severity": f.severity.value,
        "confidence": _conf_float(f.confidence),
        "status": f.status.value,
        "cvss_score": f.cvss_score,
        "cvss_vector": f.cvss_vector,
        "cwe_id": f.cwe_id,
        "owasp_category": f.owasp_category,
        "url": f.url,
        "host": f.host,
        "method": f.http_method,
        "http_method": f.http_method,
        "parameter": f.parameter,
        "payload_applied": f.payload_applied,
        "description": f.description,
        "impact": f.impact,
        "remediation": f.remediation,
        "references": list(f.references),
        "tags": list(f.tags),
        "scanner_name": f.scanner_name,
        "evidence": ev_list,
        # Legacy single-evidence shape for templates that expect it
        "ev": ev_list[0] if ev_list else {
            "request": "", "response": "", "payload": "", "notes": "", "headers": {},
        },
    }


def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["conf"] = _conf_float
    return env


def render_html(ctx: ReportContext) -> str:
    env = _env()
    tmpl = env.get_template("report.html.j2")

    css_path = _ASSETS_DIR / "report.css"
    css = css_path.read_text(encoding="utf-8") if css_path.exists() else ""

    findings_view = [_prepare_finding(f) for f in ctx.findings]

    return tmpl.render(
        meta=ctx.meta,
        scope_include=ctx.scope_include,
        scope_exclude=ctx.scope_exclude,
        findings=findings_view,
        counts=ctx.severity_counts(),
        total_findings=len(ctx.findings),
        module_count=ctx.stats.get("modules_run", "N/A"),
        discovery=ctx.discovery,
        module_errors=ctx.module_errors,
        css=css,
    )


def render(ctx: ReportContext, out_path: Path) -> Path:
    html = render_html(ctx)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    return out_path
