"""Repository layer: clean typed operations over SQLAlchemy models.

Repositories never expose the raw Session to callers.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from spiderforge.database.engine import session_scope
from spiderforge.database.models import FindingRow, Project, Scan


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_json_dumps(obj: Any) -> str:
    """Deterministic JSON serialization (sorted keys, no whitespace)."""
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        return "{}"


# ═══════════════════════════════════════════════════════════════
#  Project
# ═══════════════════════════════════════════════════════════════

class ProjectRepository:
    def __init__(self, session: Session | None = None) -> None:
        self._session = session

    def create(self, name: str, description: str = "") -> Project:
        with self._scope() as s:
            project = Project(name=name, description=description)
            s.add(project)
            s.flush()
            s.refresh(project)
            s.expunge(project)
            return project

    def get_by_name(self, name: str) -> Project | None:
        with self._scope() as s:
            p = s.scalars(select(Project).where(Project.name == name)).first()
            if p is not None:
                s.expunge(p)
            return p

    def get_or_create(self, name: str) -> Project:
        existing = self.get_by_name(name)
        if existing is not None:
            return existing
        return self.create(name)

    def list_all(self) -> list[Project]:
        with self._scope() as s:
            results = list(s.scalars(select(Project).order_by(Project.created_at.desc())).all())
            for p in results:
                s.expunge(p)
            return results

    def _scope(self):
        """Return a session-scope context, reusing the injected one if present."""
        if self._session is not None:
            from contextlib import nullcontext
            return nullcontext(self._session)
        return session_scope()


# ═══════════════════════════════════════════════════════════════
#  Scan
# ═══════════════════════════════════════════════════════════════

class ScanRepository:
    def __init__(self, session: Session | None = None) -> None:
        self._session = session

    def create(
        self,
        *,
        project_id: int,
        scan_uid: str,
        target: str,
        profile: str = "balanced",
        scope_config: dict[str, Any] | None = None,
        configuration: dict[str, Any] | None = None,
        workspace_path: str = "",
    ) -> Scan:
        with self._scope() as s:
            scan = Scan(
                project_id=project_id,
                scan_uid=scan_uid,
                target=target,
                profile=profile,
                status="created",
                scope_config=_safe_json_dumps(scope_config or {}),
                configuration=_safe_json_dumps(configuration or {}),
                workspace_path=workspace_path,
            )
            s.add(scan)
            s.flush()
            s.refresh(scan)
            s.expunge(scan)
            return scan

    def get_by_uid(self, scan_uid: str) -> Scan | None:
        with self._scope() as s:
            scan = s.scalars(select(Scan).where(Scan.scan_uid == scan_uid)).first()
            if scan is not None:
                s.expunge(scan)
            return scan

    def get_by_id(self, scan_id: int) -> Scan | None:
        with self._scope() as s:
            scan = s.get(Scan, scan_id)
            if scan is not None:
                s.expunge(scan)
            return scan

    def list_recent(self, limit: int = 20) -> list[Scan]:
        with self._scope() as s:
            stmt = select(Scan).order_by(Scan.started_at.desc()).limit(limit)
            results = list(s.scalars(stmt).all())
            for r in results:
                s.expunge(r)
            return results

    def update_status(
        self,
        scan_uid: str,
        status: str,
        *,
        error: str | None = None,
        finding_count: int | None = None,
        discovered_urls_count: int | None = None,
        finished: bool = False,
    ) -> bool:
        with self._scope() as s:
            scan = s.scalars(select(Scan).where(Scan.scan_uid == scan_uid)).first()
            if scan is None:
                return False
            scan.status = status
            if error is not None:
                scan.error = error
            if finding_count is not None:
                scan.finding_count = finding_count
            if discovered_urls_count is not None:
                scan.discovered_urls_count = discovered_urls_count
            if finished:
                scan.finished_at = _utc_now()
            return True

    def _scope(self):
        if self._session is not None:
            from contextlib import nullcontext
            return nullcontext(self._session)
        return session_scope()


# ═══════════════════════════════════════════════════════════════
#  Finding
# ═══════════════════════════════════════════════════════════════

class FindingRepository:
    def __init__(self, session: Session | None = None) -> None:
        self._session = session

    def add(self, scan_id: int, finding_uid: str, **fields) -> FindingRow:
        """Add a finding row. Caller must pass canonical fields."""
        with self._scope() as s:
            row = FindingRow(
                scan_id=scan_id,
                finding_uid=finding_uid,
                fingerprint=fields["fingerprint"],
                title=fields["title"],
                category=fields["category"],
                severity=fields["severity"],
                confidence=fields.get("confidence", "MEDIUM"),
                status=fields.get("status", "discovered"),
                cvss_score=fields.get("cvss_score"),
                cvss_vector=fields.get("cvss_vector"),
                cwe_id=fields.get("cwe_id"),
                owasp_category=fields.get("owasp_category"),
                url=fields["url"],
                host=fields.get("host", ""),
                method=fields.get("method", "GET"),
                parameter=fields.get("parameter"),
                payload_applied=fields.get("payload_applied"),
                description=fields.get("description", ""),
                impact=fields.get("impact", ""),
                remediation=fields.get("remediation", ""),
                references_json=_safe_json_dumps(fields.get("references", [])),
                scanner_name=fields.get("scanner_name", ""),
                evidence_json=_safe_json_dumps(fields.get("evidence", [])),
            )
            s.add(row)
            s.flush()
            s.refresh(row)
            s.expunge(row)
            return row

    def list_for_scan(self, scan_id: int) -> list[FindingRow]:
        with self._scope() as s:
            stmt = select(FindingRow).where(FindingRow.scan_id == scan_id)
            stmt = stmt.order_by(FindingRow.severity, FindingRow.title)
            results = list(s.scalars(stmt).all())
            for r in results:
                s.expunge(r)
            return results

    def _scope(self):
        if self._session is not None:
            from contextlib import nullcontext
            return nullcontext(self._session)
        return session_scope()
