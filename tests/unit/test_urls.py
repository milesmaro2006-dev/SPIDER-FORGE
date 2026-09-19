from spiderforge.utils.urls import normalize_url, same_origin


def test_normalize_strips_default_port():
    assert normalize_url("https://example.com:443/a") == "https://example.com/a"


def test_normalize_strips_fragment():
    assert normalize_url("https://example.com/a#x") == "https://example.com/a"


def test_normalize_sorts_query():
    a = normalize_url("https://example.com/?b=2&a=1")
    b = normalize_url("https://example.com/?a=1&b=2")
    assert a == b


def test_same_origin():
    assert same_origin("https://a.example.com/x", "https://a.example.com/y")
    assert not same_origin("https://a.example.com/", "https://b.example.com/")