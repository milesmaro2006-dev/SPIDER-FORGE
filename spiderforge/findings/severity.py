from __future__ import annotations

from spiderforge.findings.models import Severity

_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def rank(sev: Severity) -> int:
    return _ORDER[sev]


def from_cvss(score: float) -> Severity:
    if score == 0:
        return Severity.INFO
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL


def to_cvss_label(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "Critical",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
        Severity.INFO: "Informational",
    }[sev]
