from __future__ import annotations

from spiderforge.discovery.javascript import analyze_js


def test_extracts_urls_and_paths():
    js = """
    fetch("/api/users");
    axios.get("/api/v1/items?x=1");
    const u = "https://api.example.com/v2/things";
    """
    f = analyze_js("https://x.test/app.js", js)
    assert any("/api/users" in e for e in f.endpoints)
    assert any("/api/v1/items" in e for e in f.endpoints)
    assert any("api.example.com/v2/things" in e for e in f.endpoints)
    assert f.confidence >= 0.6


def test_extracts_ws_and_maps():
    js = """
    const ws = new WebSocket("wss://x.test/ws");
    //# sourceMappingURL=bundle.js.map
    """
    f = analyze_js("https://x.test/app.js", js)
    assert "wss://x.test/ws" in f.websockets
    assert "bundle.js.map" in f.source_maps


def test_extracts_interesting_strings():
    js = 'const k = "api_key"; const s = "secret";'
    f = analyze_js("https://x.test/app.js", js)
    assert "api_key" in f.interesting_strings
    assert "secret" in f.interesting_strings


def test_extracts_query_params():
    js = 'fetch("/api/search?q=x&limit=10&page=2");'
    f = analyze_js("https://x.test/app.js", js)
    assert "q" in f.parameters
    assert "limit" in f.parameters
    assert "page" in f.parameters