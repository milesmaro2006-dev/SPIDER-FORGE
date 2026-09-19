from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from spiderforge.scope.matcher import _is_ip, _is_private_ip, match_pattern
from spiderforge.scope.models import ScopeConfig


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    matched_pattern: str | None = None


def _extract_host(target: str) -> str:
    if "://" in target:
        return (urlsplit(target).hostname or "").lower()
    stripped = target.split("/", 1)[0]
    if "@" in stripped:
        stripped = stripped.rsplit("@", 1)[1]
    if ":" in stripped and stripped.count(":") == 1:
        stripped = stripped.split(":", 1)[0]
    return stripped.lower()


class ScopeValidator:
    """Central authority: every outbound request must pass through here."""

    def __init__(self, config: ScopeConfig):
        self._config = config

    @property
    def config(self) -> ScopeConfig:
        return self._config

    def is_allowed(self, target: str) -> bool:
        return self.check(target).allowed

    def check(self, target: str) -> ScopeDecision:
        host = _extract_host(target)
        if not host:
            return ScopeDecision(False, "no_host")

        # Network policy (IP-based only)
        if _is_ip(host):
            if _is_private_ip(host) and not getattr(self._config.network, "allow_private_ips", False):
                return ScopeDecision(False, "private_ip_blocked")
            if not _is_private_ip(host) and not getattr(self._config.network, "allow_public_ips", True):
                return ScopeDecision(False, "public_ip_blocked")

        # Exclusions always win
        for pat in getattr(self._config, "exclude", []):
            if match_pattern(host, pat):
                return ScopeDecision(False, "excluded", pat)

        # Inclusions
        for pat in getattr(self._config, "include", []):
            if match_pattern(host, pat):
                return ScopeDecision(True, "included", pat)

        return ScopeDecision(False, "not_in_include_list")
