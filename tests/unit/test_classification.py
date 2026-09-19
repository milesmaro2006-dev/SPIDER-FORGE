"""Tests for the vulnerability classification registry."""

from __future__ import annotations

from spiderforge.findings.classification import (
    REGISTRY,
    apply_classification,
    classify,
    cwe_name_for,
)
from spiderforge.findings.cvss import PRESETS
from spiderforge.findings.models import Finding, Severity


def _make(**overrides) -> Finding:
    defaults = dict(
        title="Sample Finding",
        category="xss.reflected",
        severity=Severity.MEDIUM,
        url="http://example.com/search?q=test",
        parameter="q",
        scanner_name="xss_scanner",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ── Lookup ──────────────────────────────────────────────────

def test_classify_exact_match():
    c = classify("xss.reflected")
    assert c is not None
    assert c.cwe_id == "CWE-79"


def test_classify_prefix_fallback():
    c = classify("xss.dom.something")
    assert c is not None
    assert c.cwe_id == "CWE-79"


def test_classify_unknown_returns_none():
    assert classify("not.a.real.category") is None
    assert classify("") is None


def test_cwe_name_lookup():
    assert cwe_name_for("CWE-79") == (
        "Improper Neutralization of Input During Web Page Generation"
    )
    assert cwe_name_for("CWE-99999") is None
    assert cwe_name_for("") is None


# ── Auto-apply ──────────────────────────────────────────────

def test_finding_gets_cwe_from_category():
    f = _make(category="sqli.error", title="SQLi")
    assert f.cwe_id == "CWE-89"


def test_finding_gets_owasp_from_category():
    f = _make(category="xss.reflected")
    assert "A03:2021" in (f.owasp_category or "")


def test_finding_gets_cvss_score_and_vector():
    f = _make(category="sqli.error")
    assert f.cvss_score is not None
    assert f.cvss_score == PRESETS["sqli"].base_score()
    assert f.cvss_vector == PRESETS["sqli"].vector()


def test_finding_with_existing_cwe_not_overwritten():
    f = _make(category="xss.reflected", title="X")
    f.cwe_id = "CWE-CUSTOM"
    # Force re-apply
    apply_classification(f)
    assert f.cwe_id == "CWE-CUSTOM"


def test_finding_with_existing_cvss_not_overwritten():
    f = _make(category="sqli.error", title="S")
    f.cvss_score = 5.5
    apply_classification(f)
    assert f.cvss_score == 5.5


def test_headers_classified():
    f = _make(category="security_headers", title="Headers")
    assert f.cwe_id == "CWE-693"
    assert f.cvss_score is not None


def test_cors_classified():
    f = _make(category="cors.origin_reflection_creds", title="CORS")
    assert f.cwe_id == "CWE-942"
    assert "A05:2021" in (f.owasp_category or "")


def test_open_redirect_classified():
    f = _make(category="open_redirect", title="Redirect")
    assert f.cwe_id == "CWE-601"


def test_unknown_category_leaves_fields_empty():
    f = _make(category="my.custom.thing", title="Custom")
    assert f.cwe_id is None
    assert f.cvss_score is None


# ── Registry integrity ──────────────────────────────────────

def test_all_registry_entries_have_cwe():
    for key, c in REGISTRY.items():
        assert c.cwe_id, f"missing CWE for {key}"
        assert c.cwe_id.startswith("CWE-"), f"invalid CWE for {key}"


def test_all_cvss_presets_exist():
    for key, c in REGISTRY.items():
        if c.cvss_preset:
            assert c.cvss_preset in PRESETS, (
                f"missing preset {c.cvss_preset} for {key}"
            )


def test_new_cvss_presets_present():
    for preset in ("ssrf", "xxe", "csrf", "idor"):
        assert preset in PRESETS, f"missing preset: {preset}"
        assert PRESETS[preset].base_score() > 0
