"""SpiderForge — Canonical Reporting Module.

Single source of truth for all report formats. Every format reads
from the same canonical data structure — no per-renderer DB queries.

Architecture:
    Database
       ↓
    CanonicalReport (dataclass)
       ↓
    Renderers: JSON / HTML / Markdown / PDF / Bundle

PDF is a capability — if the renderer is unavailable, the other
formats still work, and the API reports PDF as unavailable.
"""

from __future__ import annotations

import html
import io
import json
import logging
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("spiderforge.reporting")


SCHEMA_VERSION = "1.0"
TOOL_NAME = "SpiderForge"
TOOL_VERSION = "3.0.0"


# ═══════════════════════════════════════════════════════════════
#  Canonical Report Model
# ═══════════════════════════════════════════════════════════════

@dataclass
class ReportFinding:
    title: str
    severity: str
    confidence: str
    category: str
    url: str
    host: str = ""
    method: str = "GET"
    parameter: str | None = None
    payload: str | None = None
    description: str = ""
    impact: str = ""
    remediation: str = ""
    cwe: str | None = None
    owasp: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    scanner: str = ""
    fingerprint: str = ""
    evidence: dict | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if v not in (None, "", [], {})}


@dataclass
class CanonicalReport:
    """The single canonical representation every renderer consumes."""

    schema_version: str = SCHEMA_VERSION
    tool_name: str = TOOL_NAME
    tool_version: str = TOOL_VERSION
    report_id: str = ""
    assessment_id: str = ""
    target: str = ""
    scope_include: list[str] = field(default_factory=list)
    scope_exclude: list[str] = field(default_factory=list)
    status: str = ""
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    finding_count: int = 0
    findings: list[ReportFinding] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)
    generated_at: str = ""

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "tool": {
                "name": self.tool_name,
                "version": self.tool_version,
            },
            "report_id": self.report_id,
            "assessment": {
                "id": self.assessment_id,
                "target": self.target,
                "status": self.status,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "duration_seconds": self.duration_seconds,
            },
            "scope": {
                "include": list(self.scope_include),
                "exclude": list(self.scope_exclude),
            },
            "summary": {
                "findings": self.finding_count,
                "severity_counts": dict(self.severity_counts),
            },
            "generated_at": self.generated_at,
            "findings": [f.to_dict() for f in self.findings],
        }


# ═══════════════════════════════════════════════════════════════
#  Build from DB
# ═══════════════════════════════════════════════════════════════

def build_canonical_report(scan, rows) -> CanonicalReport:
    """Build the canonical report from DB scan + finding rows."""
    findings: list[ReportFinding] = []
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for r in rows:
        sev = (r.severity or "INFO").upper()
        if sev in counts:
            counts[sev] += 1

        # Parse first evidence bundle (already redacted at persist time)
        evidence_dict: dict | None = None
        try:
            import json as _json
            evs = _json.loads(r.evidence_json or "[]")
            if evs and isinstance(evs[0], dict):
                evidence_dict = evs[0]
        except Exception:
            evidence_dict = None

        findings.append(ReportFinding(
            title=r.title,
            severity=sev,
            confidence=r.confidence or "MEDIUM",
            category=r.category or "",
            url=r.url or "",
            host=r.host or "",
            method=r.method or "GET",
            parameter=r.parameter,
            payload=r.payload_applied,
            description=r.description or "",
            impact=r.impact or "",
            remediation=r.remediation or "",
            cwe=r.cwe_id,
            owasp=r.owasp_category,
            cvss_score=getattr(r, "cvss_score", None),
            cvss_vector=getattr(r, "cvss_vector", None),
            scanner=r.scanner_name or "",
            fingerprint=r.fingerprint or "",
            evidence=evidence_dict,
        ))

    started = scan.started_at.isoformat() if scan.started_at else ""
    finished = scan.finished_at.isoformat() if scan.finished_at else ""
    duration = 0.0
    if scan.started_at and scan.finished_at:
        try:
            duration = (scan.finished_at - scan.started_at).total_seconds()
        except Exception:
            duration = 0.0

    scope_include: list[str] = []
    scope_exclude: list[str] = []
    try:
        import json as _json
        scope = _json.loads(scan.scope_config or "{}")
        scope_include = scope.get("include", []) or []
        scope_exclude = scope.get("exclude", []) or []
    except Exception:
        pass

    report_id = f"SF-RPT-{scan.id:06d}"

    return CanonicalReport(
        report_id=report_id,
        assessment_id=scan.scan_uid or f"scan-{scan.id}",
        target=scan.target or "",
        scope_include=scope_include,
        scope_exclude=scope_exclude,
        status=scan.status or "",
        started_at=started,
        finished_at=finished,
        duration_seconds=round(duration, 2),
        finding_count=len(findings),
        findings=findings,
        severity_counts=counts,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


# ═══════════════════════════════════════════════════════════════
#  JSON Renderer
# ═══════════════════════════════════════════════════════════════

def render_json(report: CanonicalReport) -> bytes:
    return json.dumps(
        report.to_dict(),
        indent=2,
        default=str,
        ensure_ascii=False,
    ).encode("utf-8")


# ═══════════════════════════════════════════════════════════════
#  Markdown Renderer
# ═══════════════════════════════════════════════════════════════

def render_markdown(report: CanonicalReport) -> bytes:
    lines: list[str] = [
        f"# {report.tool_name} — Security Assessment Report",
        "",
        f"**Report ID:** `{report.report_id}`  ",
        f"**Assessment ID:** `{report.assessment_id}`  ",
        f"**Target:** `{report.target}`  ",
        f"**Status:** {report.status}  ",
        f"**Started:** {report.started_at or '—'}  ",
        f"**Finished:** {report.finished_at or '—'}  ",
        f"**Duration:** {report.duration_seconds:.2f}s  ",
        f"**Findings:** {report.finding_count}",
        "",
        "---",
        "",
        "## Severity Summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"| {sev} | {report.severity_counts.get(sev, 0)} |")

    lines += ["", "---", "", "## Findings", ""]

    if not report.findings:
        lines.append("_No findings detected._")
    else:
        for i, f in enumerate(report.findings, 1):
            lines += [
                f"### {i}. {f.title}",
                "",
                f"- **Severity:** {f.severity}",
                f"- **Confidence:** {f.confidence}",
                f"- **URL:** `{f.url}`",
            ]
            if f.parameter:
                lines.append(f"- **Parameter:** `{f.parameter}`")
            if f.method:
                lines.append(f"- **Method:** {f.method}")
            if f.cvss_score is not None:
                lines.append(f"- **CVSS:** {f.cvss_score} (`{f.cvss_vector or ''}`)")
            if f.cwe:
                lines.append(f"- **CWE:** {f.cwe}")
            if f.owasp:
                lines.append(f"- **OWASP:** {f.owasp}")
            if f.scanner:
                lines.append(f"- **Scanner:** {f.scanner}")
            lines.append("")

            if f.description:
                lines += ["**Description**", "", f.description, ""]
            if f.impact:
                lines += ["**Impact**", "", f.impact, ""]
            if f.payload:
                lines += ["**Payload**", "", "```", str(f.payload), "```", ""]
            if f.evidence:
                body = f.evidence.get("response_body") or f.evidence.get("note") or ""
                if body:
                    lines += ["**Evidence**", "", "```", str(body)[:2000], "```", ""]
            if f.remediation:
                lines += ["**Remediation**", "", f.remediation, ""]
            lines += ["---", ""]

    lines += [
        "",
        "---",
        "",
        f"*Generated by {report.tool_name} v{report.tool_version} · "
        f"Schema {report.schema_version} · {report.generated_at}*",
        "",
        "> Authorized security testing only.",
    ]
    return "\n".join(lines).encode("utf-8")


# ═══════════════════════════════════════════════════════════════
#  HTML Renderer (self-contained, no Jinja)
# ═══════════════════════════════════════════════════════════════

def _esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


def render_html(report: CanonicalReport) -> bytes:
    counts = report.severity_counts

    # Severity cards
    sev_cards = ""
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        sev_cards += (
            f'<div class="sev-card sev-{sev.lower()}">'
            f'<div class="sev-label">{sev}</div>'
            f'<div class="sev-value">{counts.get(sev, 0)}</div>'
            f'</div>'
        )

    # Findings
    finding_blocks: list[str] = []
    for _i, f in enumerate(report.findings, 1):
        sev = f.severity.lower()

        # Meta rows
        meta_rows: list[str] = []
        if f.url:
            meta_rows.append(f'<div><span class="mk">URL</span><code>{_esc(f.url)}</code></div>')
        if f.method:
            meta_rows.append(f'<div><span class="mk">Method</span><code>{_esc(f.method)}</code></div>')
        if f.parameter:
            meta_rows.append(f'<div><span class="mk">Parameter</span><code>{_esc(f.parameter)}</code></div>')
        if f.confidence:
            meta_rows.append(f'<div><span class="mk">Confidence</span><code>{_esc(f.confidence)}</code></div>')
        if f.cvss_score is not None:
            meta_rows.append(
                f'<div><span class="mk">CVSS</span>'
                f'<code>{_esc(f.cvss_score)}</code>'
                f' <code style="opacity:.7">{_esc(f.cvss_vector or "")}</code></div>'
            )
        if f.cwe:
            meta_rows.append(f'<div><span class="mk">CWE</span><code>{_esc(f.cwe)}</code></div>')
        if f.owasp:
            meta_rows.append(f'<div><span class="mk">OWASP</span><code>{_esc(f.owasp)}</code></div>')
        if f.scanner:
            meta_rows.append(f'<div><span class="mk">Scanner</span><code>{_esc(f.scanner)}</code></div>')
        meta_html = "".join(meta_rows)

        # CVSS badge in header
        cvss_badge = ""
        if f.cvss_score is not None:
            cvss_badge = f'<span class="cvss-badge">CVSS {_esc(f.cvss_score)}</span>'

        # Code blocks
        payload_html = ""
        if f.payload:
            payload_html = (
                '<div class="code"><div class="code-head">PAYLOAD</div>'
                f'<pre>{_esc(f.payload)}</pre></div>'
            )
        evidence_html = ""
        if f.evidence:
            body = f.evidence.get("response_body") or f.evidence.get("note") or ""
            if body:
                evidence_html = (
                    '<div class="code"><div class="code-head">EVIDENCE</div>'
                    f'<pre>{_esc(str(body)[:4000])}</pre></div>'
                )

        # Description/impact/remediation
        desc_html = f'<p class="desc">{_esc(f.description)}</p>' if f.description else ""
        impact_html = ""
        if f.impact:
            impact_html = f'<div class="impact"><strong>Impact</strong><p>{_esc(f.impact)}</p></div>'
        remediation_html = ""
        if f.remediation:
            remediation_html = (
                '<div class="remediation"><strong>Remediation</strong>'
                f'<p>{_esc(f.remediation)}</p></div>'
            )

        finding_blocks.append(f"""
<article class="finding sev-{sev}">
  <header class="finding-head">
    <span class="sev-badge sev-{sev}">{_esc(f.severity)}</span>
    {cvss_badge}
    <h3>{_esc(f.title)}</h3>
  </header>
  <div class="meta">{meta_html}</div>
  {desc_html}
  {payload_html}
  {evidence_html}
  {impact_html}
  {remediation_html}
</article>
""")

    findings_html = "\n".join(finding_blocks) if finding_blocks else (
        '<div class="no-findings">'
        '<div class="nf-icon">✓</div>'
        '<h3>No findings detected</h3>'
        '<p>The assessment did not identify issues with the tested payloads.</p>'
        '</div>'
    )

    scope_include = "".join(f"<li><code>{_esc(s)}</code></li>" for s in report.scope_include) or "<li>—</li>"
    scope_exclude = "".join(f"<li><code>{_esc(s)}</code></li>" for s in report.scope_exclude) or "<li>—</li>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(report.tool_name)} Report — {_esc(report.target)}</title>
<style>
:root {{
  --bg: #05080d; --panel: #0d141d; --panel2: #131c27;
  --line: #22303f; --text: #e6edf5; --dim: #93a2b8; --mute: #5a667a;
  --red: #e23636; --orange: #ff7a45; --yellow: #ffc857;
  --blue: #4a90d9; --green: #4ade80; --grey: #64748b;
  --mono: "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
  font-family: var(--sans); background: var(--bg); color: var(--text);
  font-size: 14px; line-height: 1.6; padding: 40px 24px;
}}
.report {{ max-width: 1040px; margin: 0 auto; }}

.cover {{
  padding: 40px 0 32px; margin-bottom: 32px;
  border-bottom: 2px solid var(--red);
}}
.cover h1 {{
  font-family: var(--mono); font-size: 24px; letter-spacing: 3px;
  margin-bottom: 8px;
}}
.cover h1 span {{ color: var(--red); }}
.cover .sub {{
  font-family: var(--mono); font-size: 11px; letter-spacing: 3px;
  text-transform: uppercase; color: var(--mute); margin-bottom: 24px;
}}
.cover h2 {{ font-size: 18px; font-weight: 500; color: var(--text); }}

.meta-grid {{
  display: grid; grid-template-columns: 180px 1fr;
  gap: 8px 20px; font-family: var(--mono); font-size: 12.5px;
  margin: 24px 0;
}}
.meta-grid .k {{ color: var(--mute); }}
.meta-grid .v {{ color: var(--dim); word-break: break-word; }}

.section-title {{
  font-family: var(--mono); font-size: 12px; font-weight: 600;
  letter-spacing: 2px; text-transform: uppercase; color: var(--dim);
  margin: 40px 0 16px; display: flex; align-items: center; gap: 10px;
}}
.section-title::before {{
  content: ""; width: 3px; height: 14px;
  background: linear-gradient(180deg, var(--red), var(--blue));
  border-radius: 2px;
}}

.sev-summary {{
  display: grid; grid-template-columns: repeat(5, 1fr);
  gap: 12px; margin: 16px 0 24px;
}}
.sev-card {{
  background: var(--panel); border: 1px solid var(--line);
  border-radius: 8px; padding: 16px; text-align: center;
}}
.sev-card .sev-label {{
  font-family: var(--mono); font-size: 10px; font-weight: 700;
  letter-spacing: 2px; margin-bottom: 8px;
}}
.sev-card .sev-value {{
  font-family: var(--mono); font-size: 26px; font-weight: 700; color: var(--text);
}}
.sev-card.sev-critical .sev-label {{ color: var(--red); }}
.sev-card.sev-high     .sev-label {{ color: var(--orange); }}
.sev-card.sev-medium   .sev-label {{ color: var(--yellow); }}
.sev-card.sev-low      .sev-label {{ color: var(--blue); }}
.sev-card.sev-info     .sev-label {{ color: var(--grey); }}

.scope-grid {{
  display: grid; grid-template-columns: 1fr 1fr; gap: 16px;
}}
.scope-box {{
  background: var(--panel); border: 1px solid var(--line);
  border-radius: 8px; padding: 16px;
}}
.scope-box h4 {{
  font-family: var(--mono); font-size: 11px; letter-spacing: 1.5px;
  text-transform: uppercase; color: var(--mute); margin-bottom: 10px;
}}
.scope-box ul {{ list-style: none; }}
.scope-box li {{
  font-family: var(--mono); font-size: 12px; color: var(--dim);
  padding: 4px 0; word-break: break-word;
}}

.finding {{
  background: var(--panel); border: 1px solid var(--line);
  border-left: 3px solid var(--grey); border-radius: 8px;
  padding: 20px; margin-bottom: 16px;
}}
.finding.sev-critical {{ border-left-color: var(--red); }}
.finding.sev-high     {{ border-left-color: var(--orange); }}
.finding.sev-medium   {{ border-left-color: var(--yellow); }}
.finding.sev-low      {{ border-left-color: var(--blue); }}
.finding.sev-info     {{ border-left-color: var(--grey); }}

.finding-head {{
  display: flex; align-items: flex-start; gap: 12px; margin-bottom: 14px;
}}
.finding-head h3 {{
  font-size: 15px; font-weight: 600; color: var(--text); line-height: 1.35;
}}
.sev-badge {{
  font-family: var(--mono); font-size: 10px; font-weight: 700;
  letter-spacing: 1.4px; padding: 3px 9px; border-radius: 4px;
  border: 1px solid transparent; white-space: nowrap; flex-shrink: 0;
}}
.sev-badge.sev-critical {{ color: #ffb3c0; background: rgba(226,54,54,.18); border-color: rgba(226,54,54,.5); }}
.sev-badge.sev-high     {{ color: #ffbea3; background: rgba(255,122,69,.14); border-color: rgba(255,122,69,.4); }}
.sev-badge.sev-medium   {{ color: #ffe1a6; background: rgba(255,200,87,.13); border-color: rgba(255,200,87,.35); }}
.sev-badge.sev-low      {{ color: #b8dfff; background: rgba(74,144,217,.15); border-color: rgba(74,144,217,.4); }}
.sev-badge.sev-info     {{ color: #b9c1cf; background: rgba(100,116,139,.14); border-color: rgba(100,116,139,.35); }}

.cvss-badge {{ font-family: var(--mono); font-size: 10px; font-weight: 700;
    padding: 2px 8px; border-radius: 3px; background: var(--panel2);
    border: 1px solid var(--line); color: #c9a227; margin-left: 4px;
    letter-spacing: 1px; white-space: nowrap; flex-shrink: 0; }}

.meta {{
  display: grid; grid-template-columns: 1fr 1fr;
  gap: 8px 24px; margin-bottom: 14px;
  font-family: var(--mono); font-size: 12px;
}}
.meta > div {{ display: flex; gap: 10px; align-items: baseline; }}
.meta .mk {{
  color: var(--mute); text-transform: uppercase; letter-spacing: 1px;
  flex-shrink: 0; min-width: 80px; font-size: 10.5px;
}}
.meta code {{
  background: var(--panel2); padding: 2px 8px; border-radius: 3px;
  color: var(--blue); word-break: break-all; font-size: 11.5px;
}}

.desc {{ font-size: 13.5px; color: var(--dim); margin-bottom: 12px; line-height: 1.65; }}

.code {{
  margin: 12px 0; background: #03060a; border: 1px solid var(--line);
  border-radius: 6px; overflow: hidden;
}}
.code-head {{
  background: var(--panel2); padding: 6px 12px;
  font-family: var(--mono); font-size: 10px; letter-spacing: 1.4px;
  text-transform: uppercase; color: var(--mute);
  border-bottom: 1px solid var(--line);
}}
.code pre {{
  margin: 0; padding: 12px 14px;
  font-family: var(--mono); font-size: 12px; line-height: 1.6;
  color: #cbd6ec; overflow-x: auto; white-space: pre-wrap;
  word-break: break-word; max-height: 360px; overflow-y: auto;
}}

.impact, .remediation {{
  margin-top: 12px; padding: 12px 14px; border-radius: 6px;
}}
.impact {{
  background: rgba(255,200,87,.05); border: 1px solid rgba(255,200,87,.18);
}}
.impact strong {{ color: var(--yellow); }}
.impact p {{ color: #ffe1a6; margin-top: 4px; font-size: 13px; }}
.remediation {{
  background: rgba(74,222,128,.05); border: 1px solid rgba(74,222,128,.2);
}}
.remediation strong {{ color: var(--green); }}
.remediation p {{ color: #c6f0cf; margin-top: 4px; font-size: 13px; }}

.no-findings {{
  background: var(--panel); border: 1px solid var(--line);
  border-radius: 8px; padding: 56px 24px; text-align: center;
}}
.nf-icon {{
  width: 56px; height: 56px; margin: 0 auto 16px;
  display: grid; place-items: center; border-radius: 50%;
  background: rgba(74,222,128,.08); color: var(--green);
  font-size: 26px; border: 1px solid rgba(74,222,128,.3);
}}
.no-findings h3 {{ color: var(--green); margin-bottom: 6px; }}
.no-findings p {{ color: var(--mute); }}

.footer {{
  margin-top: 56px; padding-top: 24px;
  border-top: 1px solid var(--line); text-align: center;
  font-family: var(--mono); font-size: 10.5px; letter-spacing: 1.5px;
  color: var(--mute); text-transform: uppercase;
}}
.footer p + p {{ margin-top: 8px; opacity: .7; }}

@media print {{
  @page {{ size: A4; margin: 18mm 15mm; }}
  body {{ background: #fff; color: #111; padding: 0; }}
  .cover h1, .cover h1 span {{ color: #111; }}
  .cover h1 span {{ color: #b91c1c; }}
  .section-title {{ color: #333; }}
  .section-title::before {{ background: #b91c1c; }}
  .finding, .sev-card, .scope-box, .no-findings, .code {{
    background: #fff !important; border-color: #ddd !important;
  }}
  .finding-head h3, .meta code, .desc {{ color: #111 !important; }}
  .code pre {{ color: #111 !important; background: #f6f6f6 !important; }}
  .finding {{ page-break-inside: avoid; }}
}}
@media (max-width: 700px) {{
  .meta-grid, .meta, .scope-grid {{ grid-template-columns: 1fr; }}
  .sev-summary {{ grid-template-columns: repeat(2, 1fr); }}
}}
</style>
</head>
<body>
<div class="report">

  <header class="cover">
    <h1>Spider<span>Forge</span></h1>
    <p class="sub">Web Security Assessment Report</p>
    <h2>{_esc(report.target or 'Assessment Report')}</h2>
  </header>

  <div class="meta-grid">
    <div class="k">Report ID</div><div class="v">{_esc(report.report_id)}</div>
    <div class="k">Assessment ID</div><div class="v">{_esc(report.assessment_id)}</div>
    <div class="k">Status</div><div class="v">{_esc(report.status)}</div>
    <div class="k">Started</div><div class="v">{_esc(report.started_at or '—')}</div>
    <div class="k">Finished</div><div class="v">{_esc(report.finished_at or '—')}</div>
    <div class="k">Duration</div><div class="v">{report.duration_seconds:.2f}s</div>
    <div class="k">Total Findings</div><div class="v">{report.finding_count}</div>
    <div class="k">Generated</div><div class="v">{_esc(report.generated_at)}</div>
    <div class="k">Tool</div><div class="v">{_esc(report.tool_name)} v{_esc(report.tool_version)}</div>
    <div class="k">Schema</div><div class="v">{_esc(report.schema_version)}</div>
  </div>

  <h2 class="section-title">Severity Summary</h2>
  <div class="sev-summary">{sev_cards}</div>

  <h2 class="section-title">Scope</h2>
  <div class="scope-grid">
    <div class="scope-box">
      <h4>Included</h4>
      <ul>{scope_include}</ul>
    </div>
    <div class="scope-box">
      <h4>Excluded</h4>
      <ul>{scope_exclude}</ul>
    </div>
  </div>

  <h2 class="section-title">Findings ({report.finding_count})</h2>
  {findings_html}

  <footer class="footer">
    <p>{_esc(report.tool_name)} v{_esc(report.tool_version)} · Schema {_esc(report.schema_version)} · {_esc(report.generated_at)}</p>
    <p>Authorized security testing only. Confidential.</p>
  </footer>

</div>
</body>
</html>""".encode()


# ═══════════════════════════════════════════════════════════════
#  PDF Renderer (capability-based)
# ═══════════════════════════════════════════════════════════════

class PDFUnavailableError(RuntimeError):
    """Raised when the PDF renderer is not available on this system."""


# Module-level cache: probing WeasyPrint is expensive (it spins up the
# rendering runtime). We only need to do it once per process.
_PDF_CAPABILITY_CACHE: dict[str, Any] | None = None


def pdf_capability(force: bool = False) -> dict[str, Any]:
    """Check PDF capability. Result is cached after first call.

    Pass ``force=True`` to bypass the cache (useful if you just
    installed WeasyPrint and don't want to restart the server).
    """
    global _PDF_CAPABILITY_CACHE
    if _PDF_CAPABILITY_CACHE is not None and not force:
        return _PDF_CAPABILITY_CACHE

    result = _compute_pdf_capability()
    _PDF_CAPABILITY_CACHE = result
    return result


def _compute_pdf_capability() -> dict[str, Any]:
    """Perform the actual capability probe. Never raises."""
    try:
        import weasyprint  # noqa: F401
        try:
            # Smoke test — actually try to render a tiny PDF
            from weasyprint import HTML  # type: ignore
            HTML(string="<p>ok</p>").write_pdf()
            return {
                "available": True,
                "engine": "weasyprint",
                "version": getattr(weasyprint, "__version__", "unknown"),
                "reason": None,
            }
        except Exception as exc:
            logger.warning("WeasyPrint installed but render failed: %s", exc)
            return {
                "available": False,
                "engine": "weasyprint",
                "version": getattr(weasyprint, "__version__", "unknown"),
                "reason": _pdf_reason_short(exc),
            }
    except ImportError:
        return {
            "available": False,
            "engine": None,
            "version": None,
            "reason": "WeasyPrint is not installed.",
        }
    except Exception as exc:
        return {
            "available": False,
            "engine": None,
            "version": None,
            "reason": f"{type(exc).__name__}: {exc}",
        }


def _pdf_reason_short(exc: Exception) -> str:
    """Convert low-level exceptions into a user-friendly reason."""
    msg = str(exc)
    if "libgobject" in msg or "libpango" in msg or "libcairo" in msg:
        return (
            "PDF rendering runtime (GTK/Pango/Cairo) is not installed. "
            "See README for platform-specific installation instructions."
        )
    return f"{type(exc).__name__}: {msg[:200]}"


def render_pdf(report: CanonicalReport) -> bytes:
    """Render PDF. Raises PDFUnavailableError if not available."""
    cap = pdf_capability()
    if not cap["available"]:
        raise PDFUnavailableError(cap["reason"] or "PDF renderer unavailable.")

    from weasyprint import HTML  # type: ignore
    html_bytes = render_html(report)
    html_str = html_bytes.decode("utf-8")
    try:
        return HTML(string=html_str).write_pdf()
    except Exception as exc:
        logger.exception("PDF render failed")
        raise PDFUnavailableError(_pdf_reason_short(exc)) from exc


# ═══════════════════════════════════════════════════════════════
#  Report Bundle (ZIP)
# ═══════════════════════════════════════════════════════════════

def render_bundle(report: CanonicalReport) -> bytes:
    """Create a ZIP bundle with all available formats + manifest.

    PDF is included only if available. Never fails because PDF is missing.
    """
    buf = io.BytesIO()
    included: list[str] = []

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # JSON
        json_bytes = render_json(report)
        zf.writestr(f"{report.report_id}/report.json", json_bytes)
        included.append("report.json")

        # Markdown
        md_bytes = render_markdown(report)
        zf.writestr(f"{report.report_id}/report.md", md_bytes)
        included.append("report.md")

        # HTML
        html_bytes = render_html(report)
        zf.writestr(f"{report.report_id}/report.html", html_bytes)
        included.append("report.html")

        # PDF (optional)
        pdf_status: dict[str, Any] = {"included": False, "reason": None}
        try:
            pdf_bytes = render_pdf(report)
            zf.writestr(f"{report.report_id}/report.pdf", pdf_bytes)
            included.append("report.pdf")
            pdf_status["included"] = True
        except PDFUnavailableError as exc:
            pdf_status["reason"] = str(exc)
        except Exception as exc:  # noqa: BLE001
            pdf_status["reason"] = f"{type(exc).__name__}: {exc}"

        # Manifest
        manifest = {
            "schema_version": report.schema_version,
            "tool": {"name": report.tool_name, "version": report.tool_version},
            "report_id": report.report_id,
            "assessment_id": report.assessment_id,
            "target": report.target,
            "generated_at": report.generated_at,
            "finding_count": report.finding_count,
            "severity_counts": report.severity_counts,
            "formats": {
                "json": {"included": True, "filename": "report.json"},
                "markdown": {"included": True, "filename": "report.md"},
                "html": {"included": True, "filename": "report.html"},
                "pdf": {
                    "included": pdf_status["included"],
                    "filename": "report.pdf" if pdf_status["included"] else None,
                    "reason": pdf_status["reason"],
                },
            },
        }
        zf.writestr(
            f"{report.report_id}/manifest.json",
            json.dumps(manifest, indent=2, default=str),
        )
        included.append("manifest.json")

    buf.seek(0)
    return buf.read()
