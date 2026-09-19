from __future__ import annotations

from spiderforge.crawler.parser import parse_html


def test_parse_links_and_scripts():
    html = """
    <html><head>
      <title>Hello</title>
      <script src="/a.js"></script>
      <script src="https://cdn.example.com/lib.js"></script>
    </head><body>
      <a href="/p1">p1</a>
      <a href="https://other.test/p2">p2</a>
      <a href="mailto:x@y.z">mail</a>
      <a href="#top">frag</a>
      <iframe src="/frame"></iframe>
      <meta http-equiv="refresh" content="0; url=/jump">
    </body></html>
    """
    page = parse_html(html, "https://x.test/root/")
    assert page.title == "Hello"
    assert "https://x.test/p1" in page.links
    assert "https://other.test/p2" in page.links
    assert "https://x.test/frame" in page.links
    assert "https://x.test/jump" in page.links
    assert "https://x.test/a.js" in page.scripts
    assert "https://cdn.example.com/lib.js" in page.scripts
    assert not any(l.startswith("mailto:") for l in page.links)


def test_parse_forms():
    html = """
    <form action="/login" method="post">
      <input name="username" type="text" required>
      <input name="password" type="password" required>
      <textarea name="bio"></textarea>
    </form>
    """
    page = parse_html(html, "https://x.test/")
    assert len(page.forms) == 1
    form = page.forms[0]
    assert form.method == "POST"
    assert form.action == "https://x.test/login"
    names = [f.name for f in form.fields]
    assert names == ["username", "password", "bio"]
    assert all(f.required for f in form.fields[:2])


def test_parse_form_defaults():
    html = "<form><input name='q'></form>"
    page = parse_html(html, "https://x.test/page")
    form = page.forms[0]
    assert form.method == "GET"
    assert form.action == "https://x.test/page"