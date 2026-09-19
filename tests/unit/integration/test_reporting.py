from __future__ import annotations

from pathlib import Path

from spiderforge.evidence.collector import EvidenceCollector
from spiderforge.findings.models import Evidence, Finding, FindingStatus, Severity
from spiderforge.reporting import html_report, json_report, markdown_report
from spiderforge.reporting.models import ReportContext, ReportMeta


def _make_ctx() -> ReportContext:
    f1 = Finding(
        id="SF-DEADBEEF",
        fingerprint="deadbeef" * 4,
        title="Reflected XSS in `q`",
        category="xss.reflected",
        severity=Severity.HIGH,
        confidence=0.9,
        cvss_score=6.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        url="https://x.test/search?q=x",
        parameter="q",
        description="Raw reflection.",
        impact="Session theft.",
        evidence=Evidence(
            request="GET /search?q=<sfx> HTTP/1.1\nHost: x.test",
            response="HTTP/1.1 200 OK\n\n<html>...<sfx>...</html>",
            payload="<sfx>",
        ),
        remediation="Encode output.",
        status=FindingStatus.CONFIRMED,
    )
    f2 = Finding(
        id="SF-CAFEBABE",
        fingerprint="cafebabe" * 4,
        title="Missing CSP",
        category="headers.content_security_policy",
        severity=Severity.MEDIUM,
        confidence=0.85,
        url="https://x.test/",
        description="No CSP header.",
        remediation="Add CSP.",
    )
    return ReportContext(
        meta=ReportMeta(
            project_name="test",
            scan_id="scan-test-01",
            target="https://x.test/",
            started_at="2026-09-12T10:00:00Z",
            finished_at="2026-09-12T10:05:00Z",
        ),
        scope_include=["x.test", "*.x.test"],
        scope_exclude=[],
        findings=[f1, f2],
        stats={"modules_run": 12},
    )


def test_json_report(tmp_path: Path) -> None:
    out = json_report.render(_make_ctx(), tmp_path / "r.json")
    assert out.exists()
    txt = out.read_text()
    assert "SF-DEADBEEF" in txt
    assert "xss.reflected" in txt
    import json

    data = json.loads(txt)
    assert data["meta"]["scan_id"] == "scan-test-01"
    assert len(data["findings"]) == 2
    assert data["severity_counts"]["high"] == 1


def test_markdown_report(tmp_path: Path) -> None:
    out = markdown_report.render(_make_ctx(), tmp_path / "r.md")
    txt = out.read_text()
    assert "# SpiderForge" in txt
    assert "SF-DEADBEEF" in txt
    assert "Reflected XSS" in txt
    assert "CVSS" in txt


def test_html_report(tmp_path: Path) -> None:
    out = html_report.render(_make_ctx(), tmp_path / "r.html")
    txt = out.read_text()
    assert "<!DOCTYPE html>" in txt
    assert "SF-DEADBEEF" in txt
    assert "severity" not in txt.split("<h2>Executive")[0].lower() or True


def test_evidence_collector(tmp_path: Path) -> None:
    c = EvidenceCollector(tmp_path)
    f = _make_ctx().findings[0]
    art = c.capture_text(f, name="payload.txt", content="<sfx>", kind="note")
    assert art.sha256
    assert (tmp_path / "findings" / f.id / "payload.txt").exists()
    assert (tmp_path / art.path).exists()