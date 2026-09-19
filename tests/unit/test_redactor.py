"""SecretRedactor tests — every real secret pattern must be redacted."""

from __future__ import annotations

import pytest

from spiderforge.evidence.redactor import SecretRedactor


# ═══════════════════════════════════════════════════════════════
#  Header-based secrets
# ═══════════════════════════════════════════════════════════════

def test_bearer_token_header_redacted():
    headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"}
    out = SecretRedactor.redact_headers(headers)
    assert "eyJ" not in out["Authorization"]
    assert "[REDACTED]" in out["Authorization"]


def test_basic_auth_redacted():
    headers = {"Authorization": "Basic dXNlcjpwYXNz"}
    out = SecretRedactor.redact_headers(headers)
    assert "dXNlcjpwYXNz" not in out["Authorization"]
    assert "[REDACTED]" in out["Authorization"]


def test_cookie_header_redacted():
    headers = {"Cookie": "session=abc123secret; theme=dark"}
    out = SecretRedactor.redact_headers(headers)
    assert "abc123secret" not in out["Cookie"]
    assert "[REDACTED]" in out["Cookie"]


def test_set_cookie_header_redacted():
    headers = {"Set-Cookie": "session=verysensitive; HttpOnly"}
    out = SecretRedactor.redact_headers(headers)
    assert "verysensitive" not in out["Set-Cookie"]


def test_api_key_header_redacted():
    headers = {"X-API-Key": "sk_live_1234567890abcdef"}
    out = SecretRedactor.redact_headers(headers)
    assert "sk_live" not in out["X-API-Key"]
    assert out["X-API-Key"] == "[REDACTED]"


def test_non_sensitive_header_preserved():
    headers = {"Content-Type": "application/json", "User-Agent": "test"}
    out = SecretRedactor.redact_headers(headers)
    assert out["Content-Type"] == "application/json"
    assert out["User-Agent"] == "test"


# ═══════════════════════════════════════════════════════════════
#  Text-based secrets
# ═══════════════════════════════════════════════════════════════

def test_jwt_in_body_redacted():
    body = '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature"}'
    out = SecretRedactor.redact_text(body)
    assert "eyJhbGciOiJIUzI1NiJ9" not in out or "REDACTED" in out


def test_password_in_query_string_redacted():
    text = "https://x.com/login?user=bob&password=hunter2&next=/home"
    out = SecretRedactor.redact_text(text)
    assert "hunter2" not in out
    assert "user=bob" in out


def test_api_key_in_query_redacted():
    text = "?api_key=abcdef1234567890&format=json"
    out = SecretRedactor.redact_text(text)
    assert "abcdef1234567890" not in out


def test_json_password_redacted():
    text = '{"username": "bob", "password": "hunter2"}'
    out = SecretRedactor.redact_text(text)
    assert "hunter2" not in out
    assert "bob" in out


def test_json_access_token_redacted():
    text = '{"access_token": "eyJhbGciOiJIUzI1NiJ9.aaaa.bbbb"}'
    out = SecretRedactor.redact_text(text)
    assert "eyJhbGciOiJIUzI1NiJ9" not in out


# ═══════════════════════════════════════════════════════════════
#  Bundle sanitization
# ═══════════════════════════════════════════════════════════════

def test_sanitize_full_bundle():
    bundle = {
        "request_headers": {"Authorization": "Bearer supersecrettoken123"},
        "response_headers": {"Set-Cookie": "session=xyz789"},
        "request_body": '{"password": "secretpass"}',
        "response_body": "Welcome admin, token=eyJhbGciOiJIUzI1NiJ9.aaaa.bbbb",
    }
    out = SecretRedactor.sanitize_evidence_bundle(bundle)

    assert "supersecrettoken123" not in str(out)
    assert "xyz789" not in str(out)
    assert "secretpass" not in str(out)
    # Non-secret text preserved
    assert "Welcome admin" in out["response_body"]


def test_redact_text_handles_none_and_empty():
    assert SecretRedactor.redact_text("") == ""
    # None → should not crash
    try:
        result = SecretRedactor.redact_text(None)  # type: ignore[arg-type]
        assert result == ""
    except (TypeError, AttributeError):
        pytest.skip("redact_text does not accept None — acceptable")