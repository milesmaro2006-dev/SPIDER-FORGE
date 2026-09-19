"""Regression test: no direct httpx.AsyncClient outside SafeHttpClient.

Every production HTTP request MUST go through SafeHttpClient so that
scope, SSRF, redirect, TLS, rate-limit, and response-size policies
are consistently enforced.

This test walks the AST of every Python file under spiderforge/ and
rejects any ``httpx.AsyncClient(...)`` construction outside the
single approved network layer.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


# Files allowed to construct httpx.AsyncClient directly.
ALLOWED_FILES = {
    "spiderforge/network/client.py",
}


def _project_root() -> Path:
    """Return the repository root (parent of tests/)."""
    return Path(__file__).resolve().parent.parent.parent


def _iter_python_files():
    root = _project_root() / "spiderforge"
    for py in root.rglob("*.py"):
        yield py


def _find_httpx_async_client(source: str) -> list[int]:
    """Return line numbers where ``httpx.AsyncClient(...)`` appears."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    hits: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr != "AsyncClient":
            continue
        if not isinstance(func.value, ast.Name):
            continue
        if func.value.id != "httpx":
            continue
        hits.append(node.lineno)
    return hits


def test_no_direct_httpx_async_client():
    """No module outside SafeHttpClient may construct httpx.AsyncClient."""
    violations: list[tuple[str, int]] = []
    for py_file in _iter_python_files():
        rel = py_file.relative_to(_project_root()).as_posix()
        if rel in ALLOWED_FILES:
            continue
        source = py_file.read_text(encoding="utf-8")
        for line_no in _find_httpx_async_client(source):
            violations.append((rel, line_no))

    if violations:
        msg_lines = ["Direct httpx.AsyncClient construction detected:"]
        for path, line in violations:
            msg_lines.append(f"  {path}:{line}")
        msg_lines.append(
            "\nAll outbound HTTP must go through "
            "spiderforge.network.client.SafeHttpClient."
        )
        pytest.fail("\n".join(msg_lines))


def test_no_verify_false():
    """No module may pass verify=False to httpx (TLS bypass must be explicit)."""
    violations: list[tuple[str, int]] = []
    for py_file in _iter_python_files():
        rel = py_file.relative_to(_project_root()).as_posix()
        source = py_file.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords or []:
                if kw.arg != "verify":
                    continue
                if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    violations.append((rel, node.lineno))

    # SafeHttpClient itself passes verify=self.policy.verify_tls — that's a
    # variable, not the constant False, so it won't match. Good.
    if violations:
        msg = "\n".join(f"  {p}:{l}" for p, l in violations)
        pytest.fail(f"verify=False found in production code:\n{msg}")


def test_no_follow_redirects_true():
    """No production module may enable follow_redirects=True."""
    violations: list[tuple[str, int]] = []
    for py_file in _iter_python_files():
        rel = py_file.relative_to(_project_root()).as_posix()
        source = py_file.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords or []:
                if kw.arg != "follow_redirects":
                    continue
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    violations.append((rel, node.lineno))

    if violations:
        msg = "\n".join(f"  {p}:{l}" for p, l in violations)
        pytest.fail(
            f"follow_redirects=True found — redirects must be manual: \n{msg}"
        )