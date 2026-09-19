"""Base scanner contract for SpiderForge v3."""

from __future__ import annotations

import asyncio
import difflib
import re as _re
import time
from abc import ABC, abstractmethod
from urllib.parse import urlparse

from spiderforge.findings.models import Finding
from spiderforge.network.client import SafeHttpClient


class BaseScanner(ABC):
    """Abstract base class for all vulnerability scanners."""

    def __init__(self, client: SafeHttpClient) -> None:
        self.client = client

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable scanner name."""

    @property
    @abstractmethod
    def category(self) -> str:
        """Vulnerability category (e.g., 'sqli', 'xss')."""

    @abstractmethod
    async def scan(self, url: str) -> list[Finding]:
        """Perform scan against the target URL and return canonical findings."""

    # ─────────────────────────────────────────────────────────
    #  Shared helpers
    # ─────────────────────────────────────────────────────────

    @staticmethod
    def extract_host(url: str) -> str:
        """Return the bare hostname (no port) for a given URL."""
        return urlparse(url).netloc.split(":")[0]

    async def timed_get(
        self,
        url: str,
        *,
        timeout: float | None = None,
    ) -> tuple[object | None, float, str | None]:
        """Perform a GET and measure wall-clock time.

        Returns (response, elapsed_seconds, error).
        """
        start = time.perf_counter()
        try:
            coro = self.client.get(url)
            if timeout is not None:
                resp = await asyncio.wait_for(coro, timeout=timeout)
            else:
                resp = await coro
            elapsed = time.perf_counter() - start
            return resp, elapsed, None
        except asyncio.TimeoutError:
            elapsed = time.perf_counter() - start
            return None, elapsed, "timeout"
        except Exception as exc:  # noqa: BLE001
            elapsed = time.perf_counter() - start
            return None, elapsed, f"{type(exc).__name__}: {exc}"

    @staticmethod
    def _strip_dynamic_noise(text: str) -> str:
        """Remove comments, scripts, styles, and transient timestamps to isolate stable DOM content."""
        if not text:
            return ""
        t = _re.sub(r"<!--.*?-->", "", text, flags=_re.DOTALL)
        t = _re.sub(r"<script.*?>.*?</script>", "", t, flags=_re.DOTALL | _re.IGNORECASE)
        t = _re.sub(r"<style.*?>.*?</style>", "", t, flags=_re.DOTALL | _re.IGNORECASE)
        t = _re.sub(r"\s+", " ", t).strip()
        t = _re.sub(r"\b[a-f0-9]{32,64}\b", "", t, flags=_re.IGNORECASE)
        t = _re.sub(r"\b\d{6,}\b", "", t)
        return t

    @classmethod
    def response_diff(cls, baseline: str, probe: str) -> float:
        """Return a normalized 0.0–1.0 difference score using dynamic noise stripping."""
        if baseline is None or probe is None:
            return 1.0
        if baseline == probe:
            return 0.0

        b_clean = cls._strip_dynamic_noise(baseline)
        p_clean = cls._strip_dynamic_noise(probe)

        bl = len(b_clean)
        pl = len(p_clean)

        if bl == 0 and pl == 0:
            return 0.0
        if bl == 0 or pl == 0:
            return 1.0

        max_len = max(bl, pl)
        len_delta = abs(bl - pl) / max_len
        if len_delta > 0.4:
            return round(min(1.0, len_delta), 4)

        sample_b = b_clean[:4000]
        sample_p = p_clean[:4000]

        matcher = difflib.SequenceMatcher(None, sample_b, sample_p)
        ratio = matcher.quick_ratio()

        score = (1.0 - ratio) * 0.7 + (len_delta * 0.3)
        return round(float(score), 4)

    @staticmethod
    def normalize_url(url: str) -> str:
        """Return a URL with a stable form for caching/comparison."""
        try:
            p = urlparse(url)
            return f"{p.scheme}://{p.netloc}{p.path}"
        except Exception:
            return url


# ═══════════════════════════════════════════════════════════════
#  Shared SQL error signatures
# ═══════════════════════════════════════════════════════════════

SQL_ERROR_SIGNATURES = [
    _re.compile(r"SQL syntax.*MySQL", _re.I),
    _re.compile(r"Warning.*mysql_.*", _re.I),
    _re.compile(r"PostgreSQL.*ERROR", _re.I),
    _re.compile(r"Driver.*SQL[\-\_\ ]*Server", _re.I),
    _re.compile(r"ORA-[0-9]{4,5}", _re.I),
    _re.compile(r"SQLite/JDBCDriver", _re.I),
    _re.compile(r"System\.Data\.SQLite\.SQLiteException", _re.I),
    _re.compile(r"quoted string not properly terminated", _re.I),
    _re.compile(r"You have an error in your SQL syntax", _re.I),
    _re.compile(r"Unclosed quotation mark after the character string", _re.I),
    _re.compile(r"Microsoft OLE DB Provider for SQL Server", _re.I),
    _re.compile(r"ODBC SQL Server Driver", _re.I),
]
