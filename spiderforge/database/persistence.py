"""Persistence bridge — converts canonical domain objects into DB rows.

Single source of truth for Finding → FindingRow mapping.
Callers never build FindingRow dicts by hand.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from spiderforge.database.models import FindingRow
from spiderforge.database.repositories import (
    FindingRepository,
    ProjectRepository,
    ScanRepository,
)
from spiderforge.findings.models import Finding, FindingEvidence


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ═══════════════════════════════════════════════════════════════
#  Finding → DB
# ═══════════════════════════════════════════════════════════════

def _evidence_to_dict(ev: FindingEvidence) -> dict[str, Any]:
    """Serialize FindingEvidence for JSON storage. Already redacted upstream."""
    return {
        "kind": ev.kind,
        "request_url": ev.request_url,
        "http_method": ev.http_method,
        "request_headers": ev.request_headers,
        "request_body": ev.request_body,
        "response_status": ev.response_status,
        "response_headers": ev.response_headers,
        "response_body": ev.response_body,
        "payload": ev.payload,
        "screenshot_path": ev.screenshot_path,
        "note": ev.note,
        "evidence_hash": ev.evidence_hash,
    }


def persist_finding(scan_id: int, finding: Finding) -> FindingRow | None:
    """Persist a canonical Finding to the DB.

    Evidence is assumed to already be redacted by EvidenceCollector.
    Returns the created FindingRow, or None on failure.
    """
    try:
        evidence_list = [_evidence_to_dict(ev) for ev in finding.evidence]
        return FindingRepository().add(
            scan_id=scan_id,
            finding_uid=finding.id,
            fingerprint=finding.fingerprint,
            title=finding.title,
            category=finding.category,
            severity=finding.severity.value,
            confidence=finding.confidence.value,
            status=finding.status.value,
            cvss_score=finding.cvss_score,
            cvss_vector=finding.cvss_vector,
            cwe_id=finding.cwe_id,
            owasp_category=finding.owasp_category,
            url=finding.url,
            host=finding.host,
            method=finding.http_method,
            parameter=finding.parameter,
            payload_applied=finding.payload_applied,
            description=finding.description,
            impact=finding.impact,
            remediation=finding.remediation,
            references=list(finding.references),
            scanner_name=finding.scanner_name,
            evidence=evidence_list,
        )
    except Exception as exc:  # noqa: BLE001
        # Persistence failure must never crash a running scan
        import logging
        logging.getLogger("spiderforge.persistence").error(
            "Failed to persist finding %s: %s", finding.fingerprint[:12], exc,
        )
        return None


# ═══════════════════════════════════════════════════════════════
#  Scan lifecycle helper
# ═══════════════════════════════════════════════════════════════

class ScanContext:
    """Manages the full lifecycle of a scan in the database.

    Usage:
        ctx = ScanContext(project_name="default", target=url, config=...)
        ctx.begin()                    # status=running
        ...
        ctx.record_finding(finding)    # one transaction per finding
        ...
        ctx.complete(finding_count)    # status=completed
        # or
        ctx.fail("error message")      # status=failed
    """

    def __init__(
        self,
        *,
        project_name: str,
        target: str,
        scan_uid: str,
        profile: str = "balanced",
        scope_config: dict[str, Any] | None = None,
        configuration: dict[str, Any] | None = None,
        workspace_path: str = "",
    ) -> None:
        self.project_name = project_name
        self.target = target
        self.scan_uid = scan_uid
        self.profile = profile
        self.scope_config = scope_config or {}
        self.configuration = configuration or {}
        self.workspace_path = workspace_path

        self.scan_id: int | None = None

    def begin(self) -> int:
        """Create project (or reuse) + scan row with status=running."""
        project = ProjectRepository().get_or_create(self.project_name)
        scan = ScanRepository().create(
            project_id=project.id,
            scan_uid=self.scan_uid,
            target=self.target,
            profile=self.profile,
            scope_config=self.scope_config,
            configuration=self.configuration,
            workspace_path=self.workspace_path,
        )
        self.scan_id = scan.id
        # Transition to running
        ScanRepository().update_status(self.scan_uid, "running")
        return scan.id

    def record_finding(self, finding: Finding) -> None:
        """Persist a single finding (own transaction)."""
        if self.scan_id is None:
            return
        persist_finding(self.scan_id, finding)

    def complete(self, finding_count: int, discovered_urls_count: int = 0) -> None:
        if self.scan_id is None:
            return
        ScanRepository().update_status(
            self.scan_uid,
            "completed",
            finding_count=finding_count,
            discovered_urls_count=discovered_urls_count,
            finished=True,
        )

    def fail(self, error: str) -> None:
        if self.scan_id is None:
            return
        # Truncate error to avoid leaking huge tracebacks
        safe_error = (error or "")[:2000]
        ScanRepository().update_status(
            self.scan_uid,
            "failed",
            error=safe_error,
            finished=True,
        )
