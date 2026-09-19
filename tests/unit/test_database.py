"""Tests for the persistence layer."""

from __future__ import annotations

from pathlib import Path

import pytest

from spiderforge.database import engine as db_engine
from spiderforge.database.models import Base
from spiderforge.database.repositories import (
    FindingRepository,
    ProjectRepository,
    ScanRepository,
)
from spiderforge.findings.models import (
    Confidence,
    Finding,
    FindingEvidence,
    Severity,
)


@pytest.fixture
def temp_db(tmp_path: Path, monkeypatch):
    """Initialize a fresh DB in tmp_path for each test."""
    db_file = tmp_path / "test.db"
    # Force reinit
    monkeypatch.setattr(db_engine, "_ENGINE", None)
    monkeypatch.setattr(db_engine, "_SESSION_FACTORY", None)
    monkeypatch.setattr(db_engine, "_DB_PATH", None)
    db_engine.init_db(db_file)
    yield db_file
    # Cleanup
    try:
        db_engine.get_engine().dispose()
    except Exception:
        pass


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        title="Reflected XSS",
        category="xss",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        url="http://example.com/search?q=test",
        host="example.com",
        http_method="GET",
        parameter="q",
        payload_applied="<script>",
        description="Reflected payload",
        impact="Session hijack",
        remediation="Encode output",
        scanner_name="xss_candidate_scanner",
        evidence=[
            FindingEvidence(
                request_url="http://example.com/search?q=test",
                http_method="GET",
                response_status=200,
                payload="<script>",
                note="Reflected raw",
            )
        ],
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ═══════════════════════════════════════════════════════════════
#  Initialization
# ═══════════════════════════════════════════════════════════════

def test_init_creates_schema(temp_db: Path):
    assert temp_db.exists()
    from sqlalchemy import inspect
    inspector = inspect(db_engine.get_engine())
    tables = set(inspector.get_table_names())
    assert "projects" in tables
    assert "scans" in tables
    assert "findings" in tables


def test_init_idempotent(temp_db: Path):
    # Re-init should not fail
    db_engine.init_db(temp_db)
    db_engine.init_db(temp_db)


# ═══════════════════════════════════════════════════════════════
#  Project
# ═══════════════════════════════════════════════════════════════

def test_project_create_and_get(temp_db):
    repo = ProjectRepository()
    p = repo.create("test-project")
    assert p.id is not None
    assert p.name == "test-project"

    fetched = repo.get_by_name("test-project")
    assert fetched is not None
    assert fetched.id == p.id


def test_project_get_or_create_idempotent(temp_db):
    repo = ProjectRepository()
    p1 = repo.get_or_create("proj")
    p2 = repo.get_or_create("proj")
    assert p1.id == p2.id


# ═══════════════════════════════════════════════════════════════
#  Scan lifecycle
# ═══════════════════════════════════════════════════════════════

def test_scan_lifecycle_created_running_completed(temp_db):
    project = ProjectRepository().get_or_create("p1")
    scan = ScanRepository().create(
        project_id=project.id,
        scan_uid="scan-abc",
        target="http://example.com",
    )
    assert scan.status == "created"

    ScanRepository().update_status("scan-abc", "running")
    assert ScanRepository().get_by_uid("scan-abc").status == "running"

    ScanRepository().update_status(
        "scan-abc", "completed",
        finding_count=5, discovered_urls_count=10, finished=True,
    )
    final = ScanRepository().get_by_uid("scan-abc")
    assert final.status == "completed"
    assert final.finding_count == 5
    assert final.finished_at is not None


def test_scan_lifecycle_failed(temp_db):
    project = ProjectRepository().get_or_create("p2")
    ScanRepository().create(
        project_id=project.id, scan_uid="scan-fail", target="http://x.com",
    )
    ScanRepository().update_status(
        "scan-fail", "failed", error="boom", finished=True,
    )
    scan = ScanRepository().get_by_uid("scan-fail")
    assert scan.status == "failed"
    assert scan.error == "boom"


def test_scan_list_recent(temp_db):
    project = ProjectRepository().get_or_create("p3")
    for i in range(3):
        ScanRepository().create(
            project_id=project.id,
            scan_uid=f"scan-{i}",
            target=f"http://t{i}.com",
        )
    scans = ScanRepository().list_recent(limit=10)
    assert len(scans) == 3


# ═══════════════════════════════════════════════════════════════
#  Finding persistence
# ═══════════════════════════════════════════════════════════════

def test_persist_finding_minimal(temp_db):
    from spiderforge.database.persistence import persist_finding

    project = ProjectRepository().get_or_create("p4")
    scan = ScanRepository().create(
        project_id=project.id, scan_uid="scan-f", target="http://x.com",
    )

    finding = _make_finding()
    row = persist_finding(scan.id, finding)
    assert row is not None
    assert row.severity == "MEDIUM"
    assert row.confidence == "HIGH"
    assert row.category == "xss"
    assert row.fingerprint == finding.fingerprint


def test_persist_multiple_findings(temp_db):
    from spiderforge.database.persistence import persist_finding

    project = ProjectRepository().get_or_create("p5")
    scan = ScanRepository().create(
        project_id=project.id, scan_uid="scan-m", target="http://x.com",
    )

    for i in range(5):
        f = _make_finding(title=f"Finding #{i}")
        persist_finding(scan.id, f)

    rows = FindingRepository().list_for_scan(scan.id)
    assert len(rows) == 5


def test_finding_evidence_roundtrip(temp_db):
    """Evidence must survive persistence."""
    import json
    from spiderforge.database.persistence import persist_finding

    project = ProjectRepository().get_or_create("p6")
    scan = ScanRepository().create(
        project_id=project.id, scan_uid="scan-e", target="http://x.com",
    )

    finding = _make_finding()
    persist_finding(scan.id, finding)

    rows = FindingRepository().list_for_scan(scan.id)
    assert len(rows) == 1

    evidence = json.loads(rows[0].evidence_json)
    assert len(evidence) == 1
    assert evidence[0]["request_url"] == "http://example.com/search?q=test"
    assert evidence[0]["payload"] == "<script>"


def test_fingerprint_uniqueness_in_db(temp_db):
    """Two findings with the same fingerprint — second should be insertable
    (repo does not enforce UNIQUE constraint) — dedup happens upstream."""
    from spiderforge.database.persistence import persist_finding

    project = ProjectRepository().get_or_create("p7")
    scan = ScanRepository().create(
        project_id=project.id, scan_uid="scan-dup", target="http://x.com",
    )

    finding = _make_finding()
    persist_finding(scan.id, finding)
    persist_finding(scan.id, finding)  # same fingerprint

    rows = FindingRepository().list_for_scan(scan.id)
    assert len(rows) == 2  # Both persisted — dedup is the engine's job


def test_redacted_evidence_stays_redacted(temp_db):
    """Redacted headers in evidence remain [REDACTED] after DB round-trip."""
    import json
    from spiderforge.database.persistence import persist_finding

    project = ProjectRepository().get_or_create("p8")
    scan = ScanRepository().create(
        project_id=project.id, scan_uid="scan-red", target="http://x.com",
    )

    finding = _make_finding()
    finding.evidence = [
        FindingEvidence(
            request_url="http://x.com",
            http_method="GET",
            request_headers={"Authorization": "Bearer [REDACTED]"},
            response_status=200,
        )
    ]
    persist_finding(scan.id, finding)

    rows = FindingRepository().list_for_scan(scan.id)
    evidence = json.loads(rows[0].evidence_json)
    assert evidence[0]["request_headers"]["Authorization"] == "Bearer [REDACTED]"