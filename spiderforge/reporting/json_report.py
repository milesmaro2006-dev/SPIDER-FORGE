from __future__ import annotations

import json
from pathlib import Path

from spiderforge.reporting.models import ReportContext


def _findings_payload(ctx: ReportContext) -> list[dict]:
    """Serialize findings safely, converting enums to their string values."""
    out: list[dict] = []
    for f in ctx.findings:
        d = f.model_dump(mode="python")
        # Ensure enums are represented as plain strings
        if hasattr(f.severity, "value"):
            d["severity"] = f.severity.value
        if hasattr(f.confidence, "value"):
            d["confidence"] = f.confidence.value
        if hasattr(f.status, "value"):
            d["status"] = f.status.value
        # Numeric confidence for consumers expecting 0.0–1.0
        d["confidence_score"] = (
            f.confidence.to_float()
            if hasattr(f.confidence, "to_float")
            else float(f.confidence) if isinstance(f.confidence, (int, float)) else 0.5
        )
        out.append(d)
    return out


def render(ctx: ReportContext, out_path: Path) -> Path:
    payload = {
        "meta": {
            "project": ctx.meta.project_name,
            "scan_id": ctx.meta.scan_id,
            "target": ctx.meta.target,
            "started_at": ctx.meta.started_at,
            "finished_at": ctx.meta.finished_at,
            "author": ctx.meta.author,
        },
        "scope": {"include": ctx.scope_include, "exclude": ctx.scope_exclude},
        "stats": ctx.stats,
        "severity_counts": ctx.severity_counts(),
        "module_errors": ctx.module_errors,
        "recon": ctx.recon,
        "discovery": ctx.discovery,
        "findings": _findings_payload(ctx),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(payload, indent=2, default=str),
        encoding="utf-8",
    )
    return out_path
