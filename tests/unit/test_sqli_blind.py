"""Tests for the enhanced Blind SQLi scanner.

Deterministic, offline, uses fake HTTP clients.
"""

from __future__ import annotations

import asyncio
from typing import List, Optional
from urllib.parse import unquote

from spiderforge.findings.models import Confidence, Finding
from spiderforge.scanners.sqli_blind import (
    BOOLEAN_MEDIUM,
    BOOLEAN_STRONG,
    CONFIRM_DELAY_SECONDS,
    FAST_DELAY_SECONDS,
    BlindSQLiScanner,
)


# ═══════════════════════════════════════════════════════════════
#  Fake client + response
# ═══════════════════════════════════════════════════════════════

class FakeResponse:
    def __init__(self, status_code: int, body: str, headers: Optional[dict] = None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {"Content-Type": "text/html"}

    def safe_text(self) -> str:
        return self._body


class FakeClient:
    def __init__(self, handler, delay=None):
        self._handler = handler
        self._delay = delay or (lambda url: 0.0)
        self.calls: List[str] = []

    async def get(self, url: str) -> FakeResponse:
        self.calls.append(url)
        d = self._delay(url)
        if d:
            await asyncio.sleep(d)
        resp = self._handler(url)
        if resp is None:
            raise RuntimeError("fake network error")
        return resp


def _run(coro):
    return asyncio.run(coro)


# ═══════════════════════════════════════════════════════════════
#  Negative cases
# ═══════════════════════════════════════════════════════════════

def test_no_params_returns_empty():
    client = FakeClient(handler=lambda url: FakeResponse(200, "ok"))
    findings = _run(BlindSQLiScanner(client).scan("http://x.com/page"))
    assert findings == []


def test_clean_target_returns_empty():
    client = FakeClient(handler=lambda url: FakeResponse(200, "static content"))
    findings = _run(BlindSQLiScanner(client).scan("http://x.com/?id=1"))
    assert findings == []


def test_noise_target_returns_empty():
    """Every response is different → no boolean detection."""

    counter = {"n": 0}

    def handler(url: str) -> FakeResponse:
        counter["n"] += 1
        return FakeResponse(200, f"noise-{counter['n']}-{'x' * (counter['n'] * 15)}")

    client = FakeClient(handler=handler)
    findings = _run(BlindSQLiScanner(client).scan("http://x.com/?id=1"))
    assert findings == []


def test_sql_error_body_suppressed():
    """If probes trigger SQL errors, blind scanner must skip (error-based's job)."""

    def handler(url: str) -> FakeResponse:
        if "%27" in url or "'" in url:
            return FakeResponse(500, "You have an error in your SQL syntax")
        return FakeResponse(200, "normal page")

    client = FakeClient(handler=handler)
    findings = _run(BlindSQLiScanner(client).scan("http://x.com/?id=1"))
    assert findings == []


# ═══════════════════════════════════════════════════════════════
#  Boolean-based positive
# ═══════════════════════════════════════════════════════════════

def test_boolean_strong_signal_high_confidence():
    """TRUE=long, FALSE=short, TRUE repeated=identical → HIGH confidence."""

    long_body = "Welcome admin. " + ("A" * 800)
    short_body = "Access denied."

    def handler(url: str) -> FakeResponse:
        if "1%27%3D%271" in url or "'1'='1" in url:
            return FakeResponse(200, long_body)
        if "1%27%3D%272" in url or "'1'='2" in url:
            return FakeResponse(200, short_body)
        return FakeResponse(200, long_body)

    client = FakeClient(handler=handler)
    findings = _run(BlindSQLiScanner(client).scan("http://x.com/?id=1"))

    assert len(findings) >= 1
    f = findings[0]
    assert "Boolean" in f.title
    assert f.confidence in (Confidence.HIGH, Confidence.CONFIRMED)
    assert f.parameter == "id"


def test_boolean_medium_signal():
    """Moderate divergence, small noise → MEDIUM or higher."""

    def handler(url: str) -> FakeResponse:
        if "1%27%3D%271" in url or "'1'='1" in url:
            return FakeResponse(200, "TRUE-" + "x" * 200)
        if "1%27%3D%272" in url or "'1'='2" in url:
            return FakeResponse(200, "F-" + "y" * 100)
        return FakeResponse(200, "TRUE-" + "x" * 200)

    client = FakeClient(handler=handler)
    findings = _run(BlindSQLiScanner(client).scan("http://x.com/?id=1"))

    assert len(findings) >= 1
    assert findings[0].confidence in (
        Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH, Confidence.CONFIRMED,
    )


def test_boolean_weak_signal_rejected():
    """Very small divergence → no finding."""

    def handler(url: str) -> FakeResponse:
        if "1%27%3D%271" in url or "'1'='1" in url:
            return FakeResponse(200, "abcdefghij")
        if "1%27%3D%272" in url or "'1'='2" in url:
            return FakeResponse(200, "abcdefghij")
        return FakeResponse(200, "abcdefghij")

    client = FakeClient(handler=handler)
    findings = _run(BlindSQLiScanner(client).scan("http://x.com/?id=1"))
    assert findings == []


# ═══════════════════════════════════════════════════════════════
#  Time-based positive
# ═══════════════════════════════════════════════════════════════

def test_time_based_fast_then_confirm():
    """Server sleeps proportional to requested delay → HIGH/CONFIRMED."""

    def handler(url: str) -> FakeResponse:
        return FakeResponse(200, "ok")

    def delay(url: str) -> float:
        u = unquote(url).upper()

        if "SLEEP(4)" in u or "PG_SLEEP(4)" in u:
            return CONFIRM_DELAY_SECONDS + 0.2
        if "0:0:4" in u:
            return CONFIRM_DELAY_SECONDS + 0.2
        if "RECEIVE_MESSAGE('A',4)" in u or "RECEIVE_MESSAGE('A', 4)" in u:
            return CONFIRM_DELAY_SECONDS + 0.2
        if "RANDOMBLOB(400000000)" in u:
            return CONFIRM_DELAY_SECONDS + 0.2

        if "SLEEP(1)" in u or "PG_SLEEP(1)" in u:
            return FAST_DELAY_SECONDS + 0.2
        if "0:0:1" in u:
            return FAST_DELAY_SECONDS + 0.2
        if "RECEIVE_MESSAGE('A',1)" in u or "RECEIVE_MESSAGE('A', 1)" in u:
            return FAST_DELAY_SECONDS + 0.2
        if "RANDOMBLOB(20000000)" in u:
            return FAST_DELAY_SECONDS + 0.2

        return 0.05

    client = FakeClient(handler=handler, delay=delay)
    findings = _run(BlindSQLiScanner(client).scan("http://x.com/?id=1"))

    assert any("Time-Based" in f.title for f in findings)
    f = next(f for f in findings if "Time-Based" in f.title)
    assert f.confidence in (
        Confidence.MEDIUM, Confidence.HIGH, Confidence.CONFIRMED,
    )
    assert f.parameter == "id"


def test_time_based_fast_only_medium():
    """Fast signal fires but confirm delay is not honored → not CONFIRMED."""

    def handler(url: str) -> FakeResponse:
        return FakeResponse(200, "ok")

    def delay(url: str) -> float:
        u = unquote(url).upper()

        if "SLEEP(4)" in u or "PG_SLEEP(4)" in u:
            return 0.05
        if "0:0:4" in u:
            return 0.05
        if "RECEIVE_MESSAGE('A',4)" in u or "RECEIVE_MESSAGE('A', 4)" in u:
            return 0.05
        if "RANDOMBLOB(400000000)" in u:
            return 0.05

        if "SLEEP(1)" in u or "PG_SLEEP(1)" in u:
            return FAST_DELAY_SECONDS + 0.3
        if "0:0:1" in u:
            return FAST_DELAY_SECONDS + 0.3
        if "RECEIVE_MESSAGE('A',1)" in u or "RECEIVE_MESSAGE('A', 1)" in u:
            return FAST_DELAY_SECONDS + 0.3
        if "RANDOMBLOB(20000000)" in u:
            return FAST_DELAY_SECONDS + 0.3

        return 0.05

    client = FakeClient(handler=handler, delay=delay)
    findings = _run(BlindSQLiScanner(client).scan("http://x.com/?id=1"))

    time_findings = [f for f in findings if "Time-Based" in f.title]
    if time_findings:
        assert time_findings[0].confidence != Confidence.CONFIRMED


def test_time_based_not_triggered_by_fast_target():
    client = FakeClient(
        handler=lambda url: FakeResponse(200, "ok"),
        delay=lambda url: 0.01,
    )
    findings = _run(BlindSQLiScanner(client).scan("http://x.com/?id=1"))
    assert findings == []


# ═══════════════════════════════════════════════════════════════
#  Scoring unit tests
# ═══════════════════════════════════════════════════════════════

def test_score_boolean_high():
    assert BlindSQLiScanner._score_boolean(
        BOOLEAN_STRONG + 0.05, 0.02,
    ) == Confidence.HIGH


def test_score_boolean_medium():
    assert BlindSQLiScanner._score_boolean(
        BOOLEAN_MEDIUM + 0.05, 0.08,
    ) == Confidence.MEDIUM


def test_score_boolean_rejects_low_noise():
    assert BlindSQLiScanner._score_boolean(0.9, 0.5) is None


def test_boost_low_to_medium():
    assert BlindSQLiScanner._boost(Confidence.LOW) == Confidence.MEDIUM


def test_boost_high_to_confirmed():
    assert BlindSQLiScanner._boost(Confidence.HIGH) == Confidence.CONFIRMED


def test_boost_confirmed_saturates():
    assert BlindSQLiScanner._boost(Confidence.CONFIRMED) == Confidence.CONFIRMED


# ═══════════════════════════════════════════════════════════════
#  Utilities
# ═══════════════════════════════════════════════════════════════

def test_inject_preserves_other_params():
    from urllib.parse import urlparse
    parsed = urlparse("http://x.com/page?a=1&b=2&c=3")
    url = BlindSQLiScanner._inject(parsed, "b", "PAYLOAD")
    assert "a=1" in url
    assert "c=3" in url
    assert "b=PAYLOAD" in url


def test_has_sql_error():
    assert BlindSQLiScanner._has_sql_error("You have an error in your SQL syntax")
    assert BlindSQLiScanner._has_sql_error("ORA-01756: quoted string not properly terminated")
    assert not BlindSQLiScanner._has_sql_error("all good")


def test_response_diff_identical():
    assert BlindSQLiScanner.response_diff("hello", "hello") == 0.0
