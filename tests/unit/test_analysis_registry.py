from __future__ import annotations

from spiderforge.analysis.loader import load_builtin_modules
from spiderforge.analysis.registry import registry


def test_registry_has_all_modules() -> None:
    load_builtin_modules()
    names = set(registry.names())
    expected = {
        "headers", "cookies", "cors", "redirects",
        "xss", "sqli", "ssrf", "ssti", "cmdi",
        "path_traversal", "file_upload", "idor",
    }
    assert expected.issubset(names)


def test_registry_select_include() -> None:
    load_builtin_modules()
    mods = registry.select(include=["xss", "sqli"])
    assert {m.name for m in mods} == {"xss", "sqli"}


def test_registry_select_exclude() -> None:
    load_builtin_modules()
    mods = registry.select(exclude=["xss"])
    assert "xss" not in {m.name for m in mods}


def test_registry_by_category() -> None:
    load_builtin_modules()
    by_cat = registry.by_category()
    assert "injection" in by_cat
    assert "configuration" in by_cat