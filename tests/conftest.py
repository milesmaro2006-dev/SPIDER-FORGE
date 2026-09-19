"""Shared pytest fixtures for SpiderForge v3 tests.

Every test runs against an isolated, temporary SQLite database.
Tests never touch ~/.spiderforge or the network.
"""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Iterator
from unittest.mock import patch

import pytest

from spiderforge.database import engine as db_engine


# ═══════════════════════════════════════════════════════════════
#  Isolated database (autouse — defensive)
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def isolated_db(tmp_path: Path, monkeypatch) -> Iterator[Path]:
    """Give every test a fresh, isolated SQLite DB."""
    db_file = tmp_path / "spiderforge_test.db"
    monkeypatch.setattr(db_engine, "_ENGINE", None)
    monkeypatch.setattr(db_engine, "_SESSION_FACTORY", None)
    monkeypatch.setattr(db_engine, "_DB_PATH", None)
    db_engine.init_db(db_file)
    yield db_file
    try:
        db_engine.get_engine().dispose()
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════
#  DNS mock helpers
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def dns_mock():
    """Fixture that lets tests inject a fake DNS resolution table."""

    class _DnsMock:
        def __init__(self) -> None:
            self._table: dict[str, list[str]] = {}

        def set(self, hostname: str, ips: list[str]) -> None:
            self._table[hostname.lower()] = ips

        def clear(self) -> None:
            self._table.clear()

        def _fake_getaddrinfo(self, host, port, *args, **kwargs):
            key = (host or "").lower()
            ips = self._table.get(key)
            if ips is None:
                raise socket.gaierror(socket.EAI_NONAME, f"no mock for {host}")
            results = []
            for ip in ips:
                if ":" in ip:
                    results.append((
                        socket.AF_INET6, socket.SOCK_STREAM, 6, "",
                        (ip, port, 0, 0),
                    ))
                else:
                    results.append((
                        socket.AF_INET, socket.SOCK_STREAM, 6, "",
                        (ip, port),
                    ))
            return results

    mock = _DnsMock()
    with patch("socket.getaddrinfo", side_effect=mock._fake_getaddrinfo):
        yield mock


# ═══════════════════════════════════════════════════════════════
#  Scope / policy helpers
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def basic_scope():
    """A ScopePolicy for example.com and its subdomains."""
    from spiderforge.network.policies import ScopePolicy
    return ScopePolicy(
        target_host="example.com",
        allowed_domains={"example.com", "*.example.com"},
    )


@pytest.fixture
def basic_policy(basic_scope):
    """A NetworkPolicy suitable for tests.

    Allows any port for localhost so pytest-httpserver's dynamic ports work.
    """
    from spiderforge.network.policies import (
        DestinationSafetyPolicy,
        NetworkPolicy,
    )

    dp = DestinationSafetyPolicy(
        allow_private_targets=True,
        allow_any_port_for_local=True,
    )
    return NetworkPolicy(
        scope_policy=basic_scope,
        destination_policy=dp,
        verify_tls=False,
        rate_limit_rps=0,
    )