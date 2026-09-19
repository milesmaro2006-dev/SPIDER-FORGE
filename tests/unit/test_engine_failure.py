"""Tests for the fail-loud path: proxy health-check + engine abort.

These tests validate that:
  • ``AnonymityManager.health_check()`` correctly detects a dead proxy.
  • ``AssessmentResult.success`` reflects the abort state.
  • ``CrawlFailureError`` is a ``SpiderForgeError`` subclass.
  • ``SafeHttpClient.__aenter__`` raises ``ProxyConnectionError`` when
    the proxy is unreachable.
  • ``AnonymityManager`` surfaces missing Python deps (e.g. socksio).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from spiderforge.anonymity.manager import AnonymityManager
from spiderforge.config.anonymity_config import AnonymityConfig
from spiderforge.core.engine import AssessmentResult
from spiderforge.core.exceptions import (
    CrawlFailureError,
    SpiderForgeError,
)
from spiderforge.network.client import SafeHttpClient
from spiderforge.network.exceptions import ProxyConnectionError
from spiderforge.network.policies import (
    DestinationSafetyPolicy,
    NetworkPolicy,
    ScopePolicy,
)


def _policy() -> NetworkPolicy:
    return NetworkPolicy(
        scope_policy=ScopePolicy(target_host="example.com", allow_all_hosts=True),
        destination_policy=DestinationSafetyPolicy(),
    )


# ── AssessmentResult.success ────────────────────────────

def test_assessment_result_success_default():
    r = AssessmentResult(
        target="http://x",
        scan_uid="s1",
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
    )
    assert r.success is True
    assert r.error_msg is None


def test_assessment_result_failure_marks_unsuccessful():
    r = AssessmentResult(
        target="http://x",
        scan_uid="s1",
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
        error_msg="crawl failed: connection refused",
    )
    assert r.success is False
    assert r.error_msg is not None
    assert "connection refused" in r.error_msg


# ── CrawlFailureError hierarchy ─────────────────────────

def test_crawl_failure_is_spiderforge_error():
    assert issubclass(CrawlFailureError, SpiderForgeError)


def test_crawl_failure_carries_message():
    err = CrawlFailureError("all pages failed")
    assert "all pages failed" in str(err)


# ── health_check: disabled / no proxy ───────────────────

@pytest.mark.asyncio
async def test_health_check_ok_when_anonymity_disabled():
    mgr = AnonymityManager(AnonymityConfig(enabled=False))
    ok, reason = await mgr.health_check(timeout=0.5)
    assert ok is True
    assert "disabled" in reason.lower()


@pytest.mark.asyncio
async def test_health_check_ok_when_no_proxy_configured():
    # enabled=True but no proxy/tor → proxy_url resolves to None
    mgr = AnonymityManager(AnonymityConfig(enabled=True))
    ok, reason = await mgr.health_check(timeout=0.5)
    assert ok is True
    assert "no proxy" in reason.lower()


# ── health_check: dead proxy ────────────────────────────

@pytest.mark.asyncio
async def test_health_check_rejects_dead_proxy():
    # Port 9 (discard) is essentially never open on a dev box.
    mgr = AnonymityManager(AnonymityConfig(
        enabled=True,
        proxy_url="http://127.0.0.1:9",
    ))
    ok, reason = await mgr.health_check(timeout=1.0)
    assert ok is False
    assert "127.0.0.1:9" in reason


@pytest.mark.asyncio
async def test_health_check_rejects_dead_socks5():
    mgr = AnonymityManager(AnonymityConfig(
        enabled=True,
        socks5_url="socks5://127.0.0.1:9",
    ))
    ok, reason = await mgr.health_check(timeout=1.0)
    assert ok is False
    assert "127.0.0.1:9" in reason


# ── SafeHttpClient: pre-flight integration ──────────────

@pytest.mark.asyncio
async def test_safe_client_raises_when_proxy_dead():
    mgr = AnonymityManager(AnonymityConfig(
        enabled=True,
        proxy_url="http://127.0.0.1:9",
    ))
    client = SafeHttpClient(_policy(), mgr)

    with pytest.raises(ProxyConnectionError) as exc_info:
        async with client:
            pass  # pragma: no cover — should not reach

    msg = str(exc_info.value)
    assert "127.0.0.1:9" in msg
    assert "not reachable" in msg.lower()


@pytest.mark.asyncio
async def test_safe_client_ok_when_no_anonymity():
    client = SafeHttpClient(_policy())  # no anonymity
    async with client:
        pass
    await client.close()


@pytest.mark.asyncio
async def test_safe_client_ok_when_anonymity_disabled():
    mgr = AnonymityManager(AnonymityConfig(enabled=False))
    client = SafeHttpClient(_policy(), mgr)
    async with client:
        pass
    await client.close()


# ── AnonymityManager: missing dependency surface ────────

def test_manager_dependency_error_default_none():
    """No proxy configured → no dependency error."""
    mgr = AnonymityManager(AnonymityConfig(enabled=True))
    assert mgr.has_dependency_error is False
    assert mgr.dependency_error() is None


def test_manager_dependency_error_exposed_for_socks5():
    """socksio is now a hard dep, but the flag must remain queryable.

    When socksio is importable (as in CI), no error. When it is not,
    the manager records a clear, user-facing reason.
    """
    mgr = AnonymityManager(AnonymityConfig(
        enabled=True,
        socks5_url="socks5://127.0.0.1:9050",
    ))
    # Either socksio is present (no error) or missing (error string set).
    if mgr.has_dependency_error:
        assert "socksio" in (mgr.dependency_error() or "").lower()
    else:
        assert mgr.dependency_error() is None
