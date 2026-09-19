"""SpiderForge Backend — FastAPI wrapper around AssessmentEngine v3."""

from __future__ import annotations

import logging
import os
import traceback
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend import reporting as rpt
from spiderforge.core.engine import AssessmentEngine
from spiderforge.database.repositories import FindingRepository, ScanRepository

logger = logging.getLogger("spiderforge.api")


app = FastAPI(
    title="SpiderForge Web Platform",
    description="Unified Web and CLI Security Assessment Platform",
    version="3.0.0",
)


# ═══════════════════════════════════════════════════════════════
#  Error model
# ═══════════════════════════════════════════════════════════════

class ApiError(Exception):
    """Structured application error."""

    def __init__(
        self,
        code: str,
        message: str,
        detail: str = "",
        status_code: int = 500,
    ):
        self.code = code
        self.message = message
        self.detail = detail
        self.status_code = status_code
        super().__init__(message)


@app.exception_handler(ApiError)
async def api_error_handler(request: Request, exc: ApiError):
    logger.warning("ApiError [%s]: %s — %s", exc.code, exc.message, exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.code,
                "message": exc.message,
                "detail": exc.detail,
            }
        },
    )


@app.exception_handler(HTTPException)
async def http_error_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": f"HTTP_{exc.status_code}",
                "message": exc.detail or "Request failed.",
                "detail": "",
            }
        },
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    logger.error(
        "Unhandled exception on %s %s: %s\n%s",
        request.method, request.url.path, exc, traceback.format_exc(),
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An internal error occurred.",
                "detail": f"{type(exc).__name__}: {exc}",
            }
        },
    )


# ═══════════════════════════════════════════════════════════════
#  Request model
# ═══════════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    target: str = Field(..., description="Target URL")
    max_urls: int = Field(200, ge=1, le=5000)
    max_depth: int = Field(3, ge=0, le=10)
    concurrency: int = Field(10, ge=1, le=100)
    rate_limit: float = Field(20.0, ge=0.1, le=200.0)
    allow_private: bool = Field(False)
    verify_tls: bool = Field(True)
    scope_free: bool = Field(
        False,
        description=(
            "Skip hostname scope validation (like Burp/ZAP). "
            "SSRF / loopback / cloud-metadata protection still applies."
        ),
    )


# ═══════════════════════════════════════════════════════════════
#  Frontend resolution (works from checkout AND pipx install)
# ═══════════════════════════════════════════════════════════════

def _resolve_frontend_dir() -> str | None:
    """Locate the web UI bundle.

    Priority:
      1. ``$SPIDERFORGE_FRONTEND_DIR``
      2. ``<backend>/static/frontend/`` — packaged wheel
      3. ``<repo>/frontend/`` — source checkout
    """
    env_dir = os.environ.get("SPIDERFORGE_FRONTEND_DIR")
    if env_dir:
        candidate = os.path.abspath(os.path.expanduser(env_dir))
        if os.path.isfile(os.path.join(candidate, "index.html")):
            return candidate

    here = os.path.dirname(os.path.abspath(__file__))

    # Packaged: backend/static/frontend
    packaged = os.path.join(here, "static", "frontend")
    if os.path.isfile(os.path.join(packaged, "index.html")):
        return packaged

    # Dev: <repo>/frontend
    repo_root = os.path.abspath(os.path.join(here, ".."))
    dev = os.path.join(repo_root, "frontend")
    if os.path.isfile(os.path.join(dev, "index.html")):
        return dev

    return None


FRONTEND_DIR = _resolve_frontend_dir()


if FRONTEND_DIR:
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/")
def serve_index():
    if FRONTEND_DIR:
        index_path = os.path.join(FRONTEND_DIR, "index.html")
        if os.path.isfile(index_path):
            return FileResponse(index_path)
    return JSONResponse(
        status_code=503,
        content={
            "error": {
                "code": "FRONTEND_MISSING",
                "message": "Web UI bundle is not installed.",
                "detail": (
                    "Reinstall spiderforge, or set SPIDERFORGE_FRONTEND_DIR "
                    "to a directory containing index.html."
                ),
            }
        },
    )


@app.get("/styles.css")
def serve_css():
    if not FRONTEND_DIR:
        raise ApiError("STYLES_NOT_FOUND", "styles.css not found.", status_code=404)
    f = os.path.join(FRONTEND_DIR, "styles.css")
    if not os.path.isfile(f):
        raise ApiError("STYLES_NOT_FOUND", "styles.css not found.", status_code=404)
    return FileResponse(f, media_type="text/css")


@app.get("/app.js")
def serve_js():
    if not FRONTEND_DIR:
        raise ApiError("JS_NOT_FOUND", "app.js not found.", status_code=404)
    f = os.path.join(FRONTEND_DIR, "app.js")
    if not os.path.isfile(f):
        raise ApiError("JS_NOT_FOUND", "app.js not found.", status_code=404)
    return FileResponse(f, media_type="application/javascript")


# ═══════════════════════════════════════════════════════════════
#  Health + Capabilities + Debug
# ═══════════════════════════════════════════════════════════════

@app.get("/api/health")
@app.head("/api/health")
def health_check():
    return {
        "status": "online",
        "service": "spiderforge",
        "version": "3.0.0",
        "frontend": bool(FRONTEND_DIR),
    }


@app.get("/api/capabilities")
def get_capabilities():
    """Report runtime capabilities (PDF, etc). Never raises."""
    pdf = rpt.pdf_capability()
    return {
        "reports": {
            "json": {"available": True},
            "html": {"available": True},
            "markdown": {"available": True},
            "pdf": {
                "available": pdf["available"],
                "engine": pdf["engine"],
                "version": pdf["version"],
                "reason": pdf["reason"],
            },
            "bundle": {
                "available": True,
                "includes_pdf": pdf["available"],
            },
        }
    }


@app.get("/api/debug/routes")
def debug_routes():
    out = []
    for r in app.routes:
        if hasattr(r, "methods") and hasattr(r, "path"):
            out.append({"path": r.path, "methods": sorted(r.methods)})
    return {"routes": out}


# ═══════════════════════════════════════════════════════════════
#  Scan API
# ═══════════════════════════════════════════════════════════════

def _finding_to_dict(finding) -> dict[str, Any]:
    evidence_text = ""
    if finding.evidence:
        first = finding.evidence[0]
        evidence_text = first.note or first.response_body or first.payload or ""
        if isinstance(evidence_text, str) and len(evidence_text) > 500:
            evidence_text = evidence_text[:500] + "…"

    return {
        "title": finding.title,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "category": finding.category,
        "description": finding.description,
        "impact": finding.impact,
        "remediation": finding.remediation,
        "param": finding.parameter or "",
        "payload": finding.payload_applied or "",
        "url": finding.url,
        "host": finding.host,
        "http_method": finding.http_method,
        "evidence": evidence_text,
        "cwe": finding.cwe_id or "",
        "owasp": finding.owasp_category or "",
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector or "",
        "scanner": finding.scanner_name,
        "fingerprint": finding.fingerprint,
    }


@app.post("/api/scan")
async def run_web_scan(request: ScanRequest):
    target = (request.target or "").strip()
    if not target:
        raise ApiError("TARGET_REQUIRED", "Target URL is required.", status_code=400)

    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    try:
        engine = AssessmentEngine(
            target_url=target,
            allow_private_targets=request.allow_private,
            verify_tls=request.verify_tls,
            max_concurrency=request.concurrency,
            rate_limit_rps=request.rate_limit,
            max_urls=request.max_urls,
            max_depth=request.max_depth,
            scope_free=request.scope_free,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Engine init failed for %s", target)
        raise ApiError(
            "ENGINE_INIT_FAILED",
            "Failed to initialize the assessment engine.",
            detail=f"{type(exc).__name__}: {exc}",
            status_code=500,
        )

    try:
        result = await engine.run()
    except Exception as exc:  # noqa: BLE001
        logger.exception("Assessment failed for %s", target)
        msg = str(exc) or type(exc).__name__

        code = "ASSESSMENT_FAILED"
        user_msg = "Assessment failed."
        low = msg.lower()
        if "scope" in low:
            code, user_msg = "SCOPE_VIOLATION", "Target is outside the authorized scope."
        elif "ssrf" in low or "blocked" in low:
            code, user_msg = "TARGET_BLOCKED", "Target is blocked by the network safety policy."
        elif "timeout" in low:
            code, user_msg = "TIMEOUT", "The target did not respond in time."
        elif "dns" in low or "resolve" in low:
            code, user_msg = "DNS_FAILURE", "Could not resolve the target hostname."
        elif "connect" in low or "connection" in low:
            code, user_msg = "CONNECTION_FAILED", "Could not connect to the target."

        return JSONResponse(
            status_code=502,
            content={
                "error": {
                    "code": code,
                    "message": user_msg,
                    "detail": f"{type(exc).__name__}: {msg[:400]}",
                    "target": target,
                }
            },
        )

    # Engine reports fatal failures in ``result.error_msg`` (never raises).
    # We surface those as structured HTTP errors so the UI cannot mistake
    # an aborted scan for a clean target.
    error_msg = getattr(result, "error_msg", None)
    if error_msg:
        low = error_msg.lower()
        if "proxy" in low or "tor" in low:
            code, user_msg = (
                "PROXY_UNREACHABLE",
                "Anonymity proxy is unreachable. Check `spiderforge anonymity status`.",
            )
        elif "scope" in low:
            code, user_msg = "SCOPE_VIOLATION", "Target is outside the authorized scope."
        elif "ssrf" in low or "blocked" in low:
            code, user_msg = "TARGET_BLOCKED", "Target is blocked by the network safety policy."
        elif "dns" in low or "resolve" in low:
            code, user_msg = "DNS_FAILURE", "Could not resolve the target hostname."
        elif "timeout" in low:
            code, user_msg = "TIMEOUT", "The target did not respond in time."
        elif (
            "connect" in low
            or "refused" in low
            or "unreachable" in low
            or "all" in low and "failed" in low
        ):
            code, user_msg = (
                "CONNECTION_FAILED",
                "Could not reach the target. The scan was aborted to avoid a false result.",
            )
        else:
            code, user_msg = (
                "ASSESSMENT_FAILED",
                "Assessment did not complete successfully.",
            )

        return JSONResponse(
            status_code=502,
            content={
                "error": {
                    "code": code,
                    "message": user_msg,
                    "detail": error_msg[:400],
                    "target": target,
                }
            },
        )

    findings: list[dict[str, Any]] = [_finding_to_dict(f) for f in result.findings]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 99))

    return {
        "status": "success",
        "target": result.target,
        "total_issues": len(findings),
        "findings": findings,
        "summary": result.summary,
        "technologies": result.technologies,
        "discovered_urls": len(result.discovered_urls),
        "duration_seconds": (result.end_time - result.start_time).total_seconds(),
        "scan_uid": getattr(result, "scan_uid", None),
    }


# ═══════════════════════════════════════════════════════════════
#  Scans History
# ═══════════════════════════════════════════════════════════════

@app.get("/api/scans")
def list_scans(limit: int = 20):
    try:
        scans = ScanRepository().list_recent(limit=limit)
    except Exception as exc:  # noqa: BLE001
        raise ApiError(
            "DB_READ_FAILED",
            "Could not read scans from the database.",
            detail=f"{type(exc).__name__}: {exc}",
            status_code=500,
        )

    return {
        "scans": [
            {
                "id": s.id,
                "scan_uid": s.scan_uid,
                "target": s.target,
                "status": s.status,
                "finding_count": s.finding_count,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            }
            for s in scans
        ]
    }


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int):
    scan = ScanRepository().get_by_id(scan_id)
    if scan is None:
        raise ApiError("SCAN_NOT_FOUND", "Scan not found.", status_code=404)
    return {
        "id": scan.id,
        "scan_uid": scan.scan_uid,
        "project_id": scan.project_id,
        "target": scan.target,
        "profile": scan.profile,
        "status": scan.status,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "finding_count": scan.finding_count,
        "discovered_urls_count": scan.discovered_urls_count,
        "error": scan.error,
        "scope_config": scan.scope_config,
        "configuration": scan.configuration,
    }


@app.get("/api/scans/{scan_id}/findings")
def get_scan_findings(scan_id: int):
    scan = ScanRepository().get_by_id(scan_id)
    if scan is None:
        raise ApiError("SCAN_NOT_FOUND", "Scan not found.", status_code=404)

    rows = FindingRepository().list_for_scan(scan_id)
    return {
        "scan_id": scan_id,
        "total": len(rows),
        "findings": [
            {
                "title": r.title,
                "severity": r.severity,
                "confidence": r.confidence,
                "category": r.category,
                "url": r.url,
                "host": r.host,
                "method": r.method,
                "param": r.parameter or "",
                "payload": r.payload_applied or "",
                "description": r.description,
                "impact": r.impact,
                "remediation": r.remediation,
                "cwe": r.cwe_id or "",
                "owasp": r.owasp_category or "",
                "cvss_score": getattr(r, "cvss_score", None),
                "cvss_vector": getattr(r, "cvss_vector", "") or "",
                "scanner": r.scanner_name,
                "fingerprint": r.fingerprint,
            }
            for r in rows
        ],
    }


# ═══════════════════════════════════════════════════════════════
#  Report API
# ═══════════════════════════════════════════════════════════════

def _build_report_or_fail(scan_id: int) -> rpt.CanonicalReport:
    scan = ScanRepository().get_by_id(scan_id)
    if scan is None:
        raise ApiError("SCAN_NOT_FOUND", "Scan not found.", status_code=404)
    rows = FindingRepository().list_for_scan(scan_id)
    return rpt.build_canonical_report(scan, rows)


@app.get("/api/scans/{scan_id}/report")
def get_scan_report(scan_id: int, format: str = "html", download: bool = False):
    """Generate a report. Never returns fake success — uses structured errors."""
    report = _build_report_or_fail(scan_id)

    fmt = (format or "html").lower()
    disposition = "attachment" if download else "inline"
    filename = f"{report.report_id}-report"
    ext_map = {"html": "html", "json": "json", "md": "md", "markdown": "md", "pdf": "pdf"}
    ext = ext_map.get(fmt)
    if ext is None:
        raise ApiError(
            "UNSUPPORTED_FORMAT",
            f"Unsupported report format: {format}",
            detail="Supported: html, json, md, pdf",
            status_code=400,
        )

    if fmt == "html":
        body = rpt.render_html(report)
        media = "text/html; charset=utf-8"
    elif fmt == "json":
        body = rpt.render_json(report)
        media = "application/json"
    elif fmt in ("md", "markdown"):
        body = rpt.render_markdown(report)
        media = "text/markdown; charset=utf-8"
    elif fmt == "pdf":
        try:
            body = rpt.render_pdf(report)
        except rpt.PDFUnavailableError as exc:
            raise ApiError(
                "PDF_RENDERER_UNAVAILABLE",
                "PDF report generation is unavailable on this server.",
                detail=str(exc),
                status_code=501,
            )
        media = "application/pdf"

    return Response(
        content=body,
        media_type=media,
        headers={
            "Content-Disposition": f'{disposition}; filename="{filename}.{ext}"',
        },
    )


@app.get("/api/scans/{scan_id}/report/bundle")
def get_scan_report_bundle(scan_id: int):
    """Download a ZIP bundle with all available report formats + manifest."""
    report = _build_report_or_fail(scan_id)
    try:
        body = rpt.render_bundle(report)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Bundle rendering failed for scan %s", scan_id)
        raise ApiError(
            "BUNDLE_FAILED",
            "Could not generate the report bundle.",
            detail=f"{type(exc).__name__}: {exc}",
            status_code=500,
        )
    return Response(
        content=body,
        media_type="application/zip",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{report.report_id}-bundle.zip"'
            ),
        },
    )
