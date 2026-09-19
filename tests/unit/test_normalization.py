from __future__ import annotations

from spiderforge.crawler.normalization import canonicalize


def test_lowercases_host_and_scheme():
    assert canonicalize("HTTPS://EXAMPLE.COM/Path") == "https://example.com/Path"


def test_drops_default_port():
    assert canonicalize("https://example.com:443/x") == "https://example.com/x"


def test_strips_fragment():
    assert canonicalize("https://example.com/x#sec") == "https://example.com/x"


def test_sorts_query():
    a = canonicalize("https://example.com/?b=2&a=1")
    b = canonicalize("https://example.com/?a=1&b=2")
    assert a == b


def test_strips_tracking_params():
    a = canonicalize("https://example.com/p?utm_source=x&id=7")
    b = canonicalize("https://example.com/p?id=7")
    assert a == b


def test_collapses_duplicate_slashes():
    assert canonicalize("https://example.com//a///b") == "https://example.com/a/b"


def test_preserves_query_values():
    a = canonicalize("https://example.com/?q=1")
    b = canonicalize("https://example.com/?q=2")
    assert a != b