"""Tests for secret redaction and canonical finding deduplication."""

from spiderforge.evidence.redactor import SecretRedactor
from spiderforge.findings.models import Finding, FindingEvidence


def test_redact_authorization_header():
    raw_headers = {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.supersecrettoken",
        "Content-Type": "application/json",
    }
    cleaned = SecretRedactor.redact_headers(raw_headers)
    assert cleaned["Authorization"] == "Bearer [REDACTED]"
    assert cleaned["Content-Type"] == "application/json"


def test_redact_cookie_values():
    raw_headers = {
        "Cookie": "session_id=abc123secret; tracking_id=xyz789",
    }
    cleaned = SecretRedactor.redact_headers(raw_headers)
    assert "abc123secret" not in cleaned["Cookie"]
    assert "session_id=[REDACTED]" in cleaned["Cookie"]


def test_redact_jwt_pattern_in_body():
    raw_text = '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sometokenpayload.signature123"}'
    cleaned = SecretRedactor.redact_text(raw_text)
    assert "[REDACTED_JWT]" in cleaned
    assert "signature123" not in cleaned


def test_finding_fingerprint_deterministic_dedup():
    """Ensure identical vulnerabilities generate the exact same fingerprint for deduplication."""
    finding_1 = Finding(
        title="SQL Injection Candidate",
        category="sqli",
        severity="HIGH",
        confidence="MEDIUM",
        url="http://example.com/item?id=1",
        host="example.com",
        http_method="GET",
        parameter="id",
        description="SQL syntax error found",
        impact="Data leakage",
        remediation="Use parameterized queries",
        scanner_name="sqli_scanner",
    )

    finding_2 = Finding(
        title="SQL Injection Candidate",
        category="sqli",
        severity="HIGH",
        confidence="MEDIUM",
        url="http://example.com/item?id=999",  # Different parameter value, same endpoint & parameter
        host="example.com",
        http_method="GET",
        parameter="id",
        description="SQL syntax error found",
        impact="Data leakage",
        remediation="Use parameterized queries",
        scanner_name="sqli_scanner",
    )

    assert finding_1.fingerprint == finding_2.fingerprint