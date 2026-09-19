"""Unit tests for the anonymity/privacy layer (pure logic, no network)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from spiderforge.anonymity.cookies import CookieJarManager
from spiderforge.anonymity.headers import sanitize_headers
from spiderforge.anonymity.manager import AnonymityManager
from spiderforge.anonymity.pacing import PacingController
from spiderforge.anonymity.proxy import build_proxy_url, validate_proxy_url
from spiderforge.anonymity.user_agents import USER_AGENT_POOL, UserAgentRotator
from spiderforge.config.anonymity_config import (
    DEFAULT_STRIPPED_HEADERS,
    AnonymityConfig,
    load_anonymity_config,
    reset_anonymity_config,
    save_anonymity_config,
)


@pytest.fixture
def tmp_anon_config(tmp_path: Path, monkeypatch):
    import spiderforge.config.anonymity_config as mod
    target = tmp_path / "anonymity.toml"
    monkeypatch.setattr(mod, "ANONYMITY_CONFIG_PATH", target)
    yield target
    if target.exists():
        target.unlink()


# ── Proxy resolution ─────────────────────────────────────

def test_proxy_resolution_tor_wins():
    cfg = AnonymityConfig(
        tor=True,
        socks5_url="socks5://1.2.3.4:1080",
        proxy_url="http://5.6.7.8:8080",
    )
    assert build_proxy_url(cfg) == "socks5://127.0.0.1:9050"


def test_proxy_resolution_socks5_beats_http():
    cfg = AnonymityConfig(
        socks5_url="socks5://1.2.3.4:1080",
        proxy_url="http://5.6.7.8:8080",
    )
    assert build_proxy_url(cfg) == "socks5://1.2.3.4:1080"


def test_proxy_resolution_http_only():
    cfg = AnonymityConfig(proxy_url="http://5.6.7.8:8080")
    assert build_proxy_url(cfg) == "http://5.6.7.8:8080"


def test_proxy_resolution_none():
    assert build_proxy_url(AnonymityConfig()) is None


def test_validate_proxy_url_accepts_http():
    ok, _ = validate_proxy_url("http://1.2.3.4:8080")
    assert ok


def test_validate_proxy_url_accepts_https():
    ok, _ = validate_proxy_url("https://proxy.example:8443")
    assert ok


def test_validate_proxy_url_accepts_socks5():
    ok, _ = validate_proxy_url("socks5://1.2.3.4:1080")
    assert ok


def test_validate_proxy_url_rejects_ftp():
    ok, reason = validate_proxy_url("ftp://1.2.3.4:21")
    assert not ok
    assert "scheme" in reason.lower()


def test_validate_proxy_url_rejects_missing_port():
    ok, reason = validate_proxy_url("http://1.2.3.4")
    assert not ok
    assert "port" in reason.lower()


def test_validate_proxy_url_rejects_empty():
    ok, _ = validate_proxy_url("")
    assert not ok


# ── User-Agent rotation ──────────────────────────────────

def test_ua_pool_is_nonempty():
    assert len(USER_AGENT_POOL) > 0
    assert all(isinstance(ua, str) and "Mozilla" in ua for ua in USER_AGENT_POOL)


def test_ua_rotator_avoids_immediate_repeats():
    rot = UserAgentRotator(seed=42)
    seen = [rot.next() for _ in range(20)]
    for i in range(1, len(seen)):
        assert seen[i] != seen[i - 1]


def test_ua_rotator_with_single_element_pool_is_stable():
    rot = UserAgentRotator(pool=["OnlyAgent/1.0"], seed=1)
    assert rot.next() == "OnlyAgent/1.0"
    assert rot.next() == "OnlyAgent/1.0"


# ── Header sanitization ──────────────────────────────────

def test_sanitize_removes_identity_headers():
    headers = {
        "User-Agent": "test",
        "X-Forwarded-For": "1.2.3.4",
        "Via": "1.1 proxy",
        "Forwarded": "for=1.2.3.4",
    }
    cleaned = sanitize_headers(
        headers,
        target_url="https://example.com/a",
        strip_identity=True,
        stripped_names=DEFAULT_STRIPPED_HEADERS,
    )
    assert "X-Forwarded-For" not in cleaned
    assert "Via" not in cleaned
    assert "Forwarded" not in cleaned
    assert cleaned["User-Agent"] == "test"


def test_sanitize_removes_custom_named_headers():
    cleaned = sanitize_headers(
        {"Keep": "yes", "Drop": "no"},
        strip_identity=True,
        stripped_names=["drop"],
    )
    assert "Keep" in cleaned
    assert "Drop" not in cleaned


def test_sanitize_strip_referrer_same_origin():
    cleaned = sanitize_headers(
        {"Referer": "https://evil.example/x"},
        target_url="https://target.example/page",
        strip_referrer=True,
        referrer_policy="same-origin",
    )
    assert cleaned["Referer"] == "https://target.example/"


def test_sanitize_strip_referrer_none():
    cleaned = sanitize_headers(
        {"Referer": "https://target.example/"},
        strip_referrer=True,
        referrer_policy="none",
    )
    assert "Referer" not in cleaned


def test_sanitize_noop_when_disabled():
    headers = {"Referer": "https://evil.example/", "X-Forwarded-For": "1.2.3.4"}
    cleaned = sanitize_headers(headers, strip_identity=False, strip_referrer=False)
    assert cleaned == headers


# ── Pacing ────────────────────────────────────────────────

def test_pacing_disabled_when_zero():
    p = PacingController(min_delay=0.0, max_delay=0.0)
    assert not p.enabled
    assert p.next_delay() == 0.0


def test_pacing_range_is_respected():
    p = PacingController(min_delay=0.1, max_delay=0.2)
    for _ in range(10):
        d = p.next_delay()
        assert 0.1 <= d <= 0.2


def test_pacing_fixed_value():
    p = PacingController(min_delay=0.5, max_delay=0.5)
    assert p.next_delay() == 0.5


def test_pacing_normalizes_inverted_range():
    p = PacingController(min_delay=2.0, max_delay=1.0)
    assert p.max_delay == p.min_delay == 2.0


@pytest.mark.asyncio
async def test_pacing_wait_returns_delay():
    p = PacingController(min_delay=0.0, max_delay=0.0)
    d = await p.wait()
    assert d == 0.0


# ── Cookie isolation ─────────────────────────────────────

def test_cookie_isolation_per_origin():
    jar = CookieJarManager()
    jar.store_from_response("https://a.com/x", ["session=abc; Path=/; HttpOnly"])
    jar.store_from_response("https://b.com/y", ["token=xyz"])

    assert jar.jar_for("https://a.com/") == {"session": "abc"}
    assert jar.jar_for("https://b.com/") == {"token": "xyz"}
    assert jar.jar_for("https://c.com/") == {}


def test_cookie_apply_to_headers():
    jar = CookieJarManager()
    jar.store_from_response("https://a.com/", ["a=1", "b=2"])
    headers = jar.apply_to_headers("https://a.com/x", {})
    assert "Cookie" in headers
    assert "a=1" in headers["Cookie"]
    assert "b=2" in headers["Cookie"]


def test_cookie_no_cross_origin_leak():
    jar = CookieJarManager()
    jar.store_from_response("https://a.com/", ["secret=1"])
    headers = jar.apply_to_headers("https://b.com/", {})
    assert "Cookie" not in headers


def test_cookie_clear_origin():
    jar = CookieJarManager()
    jar.store_from_response("https://a.com/", ["x=1"])
    jar.clear_origin("https://a.com/")
    assert jar.jar_for("https://a.com/") == {}


# ── Config round-trip ────────────────────────────────────

def test_config_roundtrip(tmp_anon_config):
    cfg = AnonymityConfig(
        enabled=True,
        proxy_url="http://1.2.3.4:8080",
        rotate_user_agent=True,
        pacing_enabled=True,
        pacing_min=0.1,
        pacing_max=0.3,
        cookie_isolation=True,
    )
    save_anonymity_config(cfg)
    loaded = load_anonymity_config()

    assert loaded.enabled is True
    assert loaded.proxy_url == "http://1.2.3.4:8080"
    assert loaded.rotate_user_agent is True
    assert loaded.pacing_enabled is True
    assert loaded.pacing_min == 0.1
    assert loaded.pacing_max == 0.3
    assert loaded.cookie_isolation is True


def test_config_reset(tmp_anon_config):
    save_anonymity_config(AnonymityConfig(enabled=True, proxy_url="http://x:1"))
    reset_anonymity_config()
    loaded = load_anonymity_config()
    assert loaded.enabled is False
    assert loaded.proxy_url == ""


# ── Manager ──────────────────────────────────────────────

def test_manager_inactive_when_disabled():
    cfg = AnonymityConfig(enabled=False, proxy_url="http://x:1")
    mgr = AnonymityManager(cfg)
    assert not mgr.is_active
    assert mgr.proxy_url is None
    assert not mgr.should_skip_peer_ip_check()


def test_manager_active_with_proxy():
    cfg = AnonymityConfig(enabled=True, proxy_url="http://1.2.3.4:8080")
    mgr = AnonymityManager(cfg)
    assert mgr.is_active
    assert mgr.proxy_url == "http://1.2.3.4:8080"
    assert mgr.should_skip_peer_ip_check()


def test_manager_invalid_proxy_disables_feature():
    cfg = AnonymityConfig(enabled=True, proxy_url="ftp://bad:21")
    mgr = AnonymityManager(cfg)
    assert mgr.is_active
    assert mgr.proxy_url is None
    assert not mgr.should_skip_peer_ip_check()


def test_manager_prepare_headers_noop_when_inactive():
    mgr = AnonymityManager(AnonymityConfig(enabled=False))
    out = mgr.prepare_headers("https://x/", {"A": "1"})
    assert out == {"A": "1"}


def test_manager_prepare_headers_sanitizes_when_active():
    mgr = AnonymityManager(AnonymityConfig(
        enabled=True,
        proxy_url="http://1.2.3.4:8080",
        strip_identity_headers=True,
        strip_referrer=True,
    ))
    out = mgr.prepare_headers(
        "https://target.example/",
        {"X-Forwarded-For": "1.2.3.4", "Referer": "https://evil.example/x"},
    )
    assert "X-Forwarded-For" not in out
    # With referrer_policy='same-origin', the Referer is *rewritten* to the
    # target origin (never leaked from the original source).
    assert out["Referer"] == "https://target.example/"
    assert "evil.example" not in out["Referer"]


def test_manager_ua_rotation_when_configured():
    mgr = AnonymityManager(AnonymityConfig(
        enabled=True,
        proxy_url="http://1.2.3.4:8080",
        rotate_user_agent=True,
    ))
    h1 = mgr.prepare_headers("https://x/", {})
    h2 = mgr.prepare_headers("https://x/", {})
    assert "User-Agent" in h1
    assert "User-Agent" in h2
    assert h1["User-Agent"] != h2["User-Agent"]


def test_manager_cookies_injected():
    mgr = AnonymityManager(AnonymityConfig(
        enabled=True,
        proxy_url="http://1.2.3.4:8080",
        cookie_isolation=True,
    ))
    assert mgr.cookie_isolation_enabled
    mgr.cookies.store_from_response("https://x/", ["a=1"])
    headers = mgr.prepare_headers("https://x/", {})
    assert "Cookie" in headers
    assert "a=1" in headers["Cookie"]


def test_manager_status_snapshot():
    cfg = AnonymityConfig(
        enabled=True,
        proxy_url="http://1.2.3.4:8080",
        rotate_user_agent=True,
        pacing_enabled=True,
        pacing_min=0.1,
        pacing_max=0.2,
        cookie_isolation=True,
    )
    mgr = AnonymityManager(cfg)
    s = mgr.status()
    assert s.enabled is True
    assert s.proxy_url == "http://1.2.3.4:8080"
    assert s.ua_rotation is True
    assert s.pacing is True
    assert s.cookie_isolation is True


# ── Backward compat ──────────────────────────────────────

def test_safe_http_client_backward_compatible():
    from spiderforge.network.client import SafeHttpClient
    from spiderforge.network.policies import (
        DestinationSafetyPolicy,
        NetworkPolicy,
        ScopePolicy,
    )

    policy = NetworkPolicy(
        scope_policy=ScopePolicy(target_host="example.com", allow_all_hosts=True),
        destination_policy=DestinationSafetyPolicy(),
    )
    client = SafeHttpClient(policy)
    assert client.anonymity is None
    assert client.policy is policy
    asyncio.run(client.close())


def test_safe_http_client_accepts_anonymity_kwarg():
    from spiderforge.network.client import SafeHttpClient
    from spiderforge.network.policies import (
        DestinationSafetyPolicy,
        NetworkPolicy,
        ScopePolicy,
    )

    policy = NetworkPolicy(
        scope_policy=ScopePolicy(target_host="example.com", allow_all_hosts=True),
        destination_policy=DestinationSafetyPolicy(),
    )
    mgr = AnonymityManager(AnonymityConfig(enabled=False))
    client = SafeHttpClient(policy, mgr)
    assert client.anonymity is mgr
    asyncio.run(client.close())
