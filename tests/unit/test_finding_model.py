"""Canonical Finding model tests — enums, fingerprint uniqueness."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from spiderforge.findings.models import (
    Confidence,
    Finding,
    FindingEvidence,
    FindingStatus,
    Severity,
)


def _make(**overrides) -> Finding:
    defaults = dict(
        title="Reflected XSS",
        category="xss",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        url="http://example.com/search?q=1",
        host="example.com",
        http_method="GET",
        parameter="q",
        scanner_name="xss_scanner",
        evidence=[
            FindingEvidence(
                request_url="http://example.com/search?q=1",
                response_status=200,
                payload="<script>",
            )
        ],
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ═══════════════════════════════════════════════════════════════
#  Basic construction
# ═══════════════════════════════════════════════════════════════

def test_finding_creation_minimal():
    f = _make()
    assert f.severity == Severity.MEDIUM
    assert f.confidence == Confidence.HIGH
    assert f.status == FindingStatus.DISCOVERED
    assert len(f.evidence) == 1


def test_invalid_severity_rejected():
    with pytest.raises(ValidationError):
        _make(severity="SUPER_HIGH")  # not a valid enum value


def test_invalid_confidence_rejected():
    with pytest.raises(ValidationError):
        _make(confidence="MAYBE")


# ═══════════════════════════════════════════════════════════════
#  Fingerprint
# ═══════════════════════════════════════════════════════════════

def test_fingerprint_is_stable():
    """Same inputs → same fingerprint, across instances."""
    f1 = _make()
    f2 = _make()
    assert f1.fingerprint == f2.fingerprint


def test_fingerprint_differs_by_title():
    """Two different finding types on the same URL must be distinct."""
    f1 = _make(title="Missing CSP Header", category="security_headers", parameter="HTTP-Header")
    f2 = _make(title="Missing HSTS Header", category="security_headers", parameter="HTTP-Header")
    assert f1.fingerprint != f2.fingerprint


def test_fingerprint_differs_by_category():
    f1 = _make(category="xss")
    f2 = _make(category="sqli")
    assert f1.fingerprint != f2.fingerprint


def test_fingerprint_differs_by_parameter():
    f1 = _make(parameter="q")
    f2 = _make(parameter="id")
    assert f1.fingerprint != f2.fingerprint


def test_fingerprint_differs_by_host():
    f1 = _make(host="a.example.com")
    f2 = _make(host="b.example.com")
    assert f1.fingerprint != f2.fingerprint


def test_fingerprint_ignores_query_string():
    """Different query values on the same path → same fingerprint."""
    f1 = _make(url="http://example.com/search?q=1")
    f2 = _make(url="http://example.com/search?q=2")
    assert f1.fingerprint == f2.fingerprint


def test_fingerprint_ignores_trailing_slash():
    f1 = _make(url="http://example.com/search")
    f2 = _make(url="http://example.com/search/")
    assert f1.fingerprint == f2.fingerprint


def test_fingerprint_ignores_case_in_url():
    f1 = _make(url="http://example.com/SEARCH?q=1")
    f2 = _make(url="http://example.com/search?q=1")
    assert f1.fingerprint == f2.fingerprint


def test_fingerprint_length_and_format():
    f = _make()
    assert len(f.fingerprint) == 64
    int(f.fingerprint, 16)  # hex-only


# ═══════════════════════════════════════════════════════════════
#  Auto-generated ID
# ═══════════════════════════════════════════════════════════════

def test_id_is_unique_per_instance():
    ids = {_make().id for _ in range(100)}
    assert len(ids) == 100


def test_id_is_hex_32():
    f = _make()
    assert len(f.id) == 32
    int(f.id, 16)


# ═══════════════════════════════════════════════════════════════
#  Evidence hash
# ═══════════════════════════════════════════════════════════════

def test_evidence_hash_changes_with_body():
    ev1 = FindingEvidence(request_url="http://x", response_body="A")
    ev2 = FindingEvidence(request_url="http://x", response_body="B")
    assert ev1.evidence_hash != ev2.evidence_hash


def test_evidence_hash_stable_for_same_input():
    ev1 = FindingEvidence(request_url="http://x", response_body="A")
    ev2 = FindingEvidence(request_url="http://x", response_body="A")
    assert ev1.evidence_hash == ev2.evidence_hash


# ═══════════════════════════════════════════════════════════════
#  add_evidence
# ═══════════════════════════════════════════════════════════════

def test_add_evidence_appends():
    f = _make(evidence=[])
    assert len(f.evidence) == 0

    ev = FindingEvidence(request_url="http://x", response_status=200)
    f.add_evidence(ev)
    assert len(f.evidence) == 1