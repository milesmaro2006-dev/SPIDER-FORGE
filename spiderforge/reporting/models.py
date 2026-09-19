from __future__ import annotations

from dataclasses import dataclass, field

from spiderforge.findings.models import Finding


@dataclass
class ReportMeta:
    project_name: str
    scan_id: str
    target: str
    started_at: str
    finished_at: str | None = None
    author: str = "SpiderForge"


@dataclass
class ReportContext:
    meta: ReportMeta
    scope_include: list[str] = field(default_factory=list)
    scope_exclude: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    recon: dict = field(default_factory=dict)
    discovery: dict = field(default_factory=dict)
    stats: dict = field(default_factory=dict)
    module_errors: dict[str, str] = field(default_factory=dict)

    def severity_counts(self) -> dict[str, int]:
        """Return lowercase-keyed counts.

        Example: ``{"critical": 0, "high": 3, "medium": 5, ...}``
        """
        counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        for f in self.findings:
            key = f.severity.value.lower()
            counts[key] = counts.get(key, 0) + 1
        return counts

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        groups: dict[str, list[Finding]] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": [],
        }
        for f in self.findings:
            key = f.severity.value.lower()
            groups.setdefault(key, []).append(f)
        return groups
