"""Crawler URL utilities tests."""

from __future__ import annotations

import pytest

from spiderforge.crawler.url_utils import (
    extract_query_params,
    is_http_url,
    normalize_and_validate,
    path_without_query,
    should_skip_by_extension,
)


# ═══════════════════════════════════════════════════════════════
#  Static extension skipping
# ═══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("url", [
    "http://x.com/style.css",
    "http://x.com/app.js",
    "http://x.com/img.png",
    "http://x.com/font.woff2",
    "http://x.com/video.mp4",
    "http://x.com/docs/report.pdf",
    "http://x.com/app.min.js",
    "http://x.com/style.min.css",
])
def test_static_extensions_are_skipped(url):
    assert should_skip_by_extension(url) is True


@pytest.mark.parametrize("url", [
    "http://x.com/",
    "http://x.com/index.jsp",
    "http://x.com/search.php",
    "http://x.com/api/v1/users",
    "http://x.com/path/no-extension",
])
def test_dynamic_urls_are_not_skipped(url):
    assert should_skip_by_extension(url) is False


# ═══════════════════════════════════════════════════════════════
#  Scheme validation
# ═══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("url,expected", [
    ("http://x.com/", True),
    ("https://x.com/", True),
    ("ftp://x.com/", False),
    ("file:///etc/passwd", False),
    ("javascript:alert(1)", False),
    ("mailto:user@x.com", False),
    ("data:text/html,<h1>x</h1>", False),
])
def test_is_http_url(url, expected):
    assert is_http_url(url) is expected


# ═══════════════════════════════════════════════════════════════
#  normalize_and_validate
# ═══════════════════════════════════════════════════════════════

def test_normalize_absolute_url():
    out = normalize_and_validate("http://x.com/a", base_url="http://x.com/")
    assert out is not None
    assert out.startswith("http://x.com/a")


def test_normalize_relative_url():
    out = normalize_and_validate("/b", base_url="http://x.com/a")
    assert out is not None
    assert out == "http://x.com/b"


def test_normalize_relative_parent():
    out = normalize_and_validate("../b", base_url="http://x.com/a/c")
    assert out is not None
    assert out == "http://x.com/b"


def test_normalize_strips_fragment():
    out = normalize_and_validate("http://x.com/a#section", base_url="http://x.com/")
    assert out is not None
    assert "#" not in out


def test_normalize_returns_none_for_javascript():
    out = normalize_and_validate("javascript:alert(1)", base_url="http://x.com/")
    assert out is None


def test_normalize_returns_none_for_data_uri():
    out = normalize_and_validate("data:text/html,<h1>x</h1>", base_url="http://x.com/")
    assert out is None


def test_normalize_returns_none_for_empty():
    assert normalize_and_validate("", base_url="http://x.com/") is None
    assert normalize_and_validate("   ", base_url="http://x.com/") is None


def test_normalize_returns_none_for_pure_fragment():
    assert normalize_and_validate("#section", base_url="http://x.com/") is None


def test_normalize_skips_png():
    out = normalize_and_validate("/logo.png", base_url="http://x.com/")
    assert out is None


# ═══════════════════════════════════════════════════════════════
#  Query parameter extraction
# ═══════════════════════════════════════════════════════════════

def test_extract_query_params_single():
    assert extract_query_params("http://x.com/?a=1") == ["a"]


def test_extract_query_params_multiple():
    assert extract_query_params("http://x.com/?a=1&b=2&c=3") == ["a", "b", "c"]


def test_extract_query_params_dedup():
    assert extract_query_params("http://x.com/?a=1&a=2&a=3") == ["a"]


def test_extract_query_params_empty():
    assert extract_query_params("http://x.com/") == []


def test_extract_query_params_blank_values():
    assert extract_query_params("http://x.com/?a=&b=1") == ["a", "b"]


# ═══════════════════════════════════════════════════════════════
#  path_without_query
# ═══════════════════════════════════════════════════════════════

def test_path_without_query():
    assert path_without_query("http://x.com/a?b=1&c=2") == "http://x.com/a"


def test_path_without_query_no_query():
    assert path_without_query("http://x.com/a") == "http://x.com/a"