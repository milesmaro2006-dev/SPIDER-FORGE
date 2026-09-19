"""TLS fingerprint (ja3) capability — honest detection, no fake success."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("spiderforge.anonymity.fingerprint")


KNOWN_PROFILES: tuple[str, ...] = (
    "chrome99", "chrome100", "chrome101", "chrome104", "chrome107",
    "chrome110", "chrome116", "chrome119", "chrome120", "chrome123",
    "chrome124", "chrome131",
    "safari15_3", "safari15_5", "safari17_0", "safari17_2_ios",
    "edge99", "edge101", "firefox133",
)


@dataclass
class TLSFingerprint:
    profile: str = ""
    available: bool = False
    engine: str | None = None
    version: str | None = None
    reason: str | None = None
    profiles: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "available": self.available,
            "engine": self.engine,
            "version": self.version,
            "reason": self.reason,
            "profiles": list(self.profiles),
        }


_CACHE: TLSFingerprint | None = None


def tls_fingerprint_capability(
    profile: str = "",
    *,
    force: bool = False,
) -> TLSFingerprint:
    global _CACHE
    if _CACHE is not None and not force and (not profile or _CACHE.profile == profile):
        return _CACHE

    try:
        import curl_cffi  # type: ignore
    except ImportError:
        cap = TLSFingerprint(
            profile=profile,
            available=False,
            engine=None,
            version=None,
            reason=(
                "curl_cffi is not installed. "
                "Install with: pipx inject spiderforge curl_cffi"
            ),
            profiles=[],
        )
        _CACHE = cap
        return cap
    except Exception as exc:  # noqa: BLE001
        cap = TLSFingerprint(
            profile=profile,
            available=False,
            engine="curl_cffi",
            version=None,
            reason=f"curl_cffi import failed: {type(exc).__name__}: {exc}",
            profiles=[],
        )
        _CACHE = cap
        return cap

    version = getattr(curl_cffi, "__version__", "unknown")

    if profile and profile not in KNOWN_PROFILES:
        cap = TLSFingerprint(
            profile=profile,
            available=False,
            engine="curl_cffi",
            version=version,
            reason=(
                f"unknown profile {profile!r}; "
                f"known: {', '.join(KNOWN_PROFILES)}"
            ),
            profiles=list(KNOWN_PROFILES),
        )
        _CACHE = cap
        return cap

    cap = TLSFingerprint(
        profile=profile,
        available=True,
        engine="curl_cffi",
        version=version,
        reason=None,
        profiles=list(KNOWN_PROFILES),
    )
    _CACHE = cap
    return cap


def reset_cache() -> None:
    global _CACHE
    _CACHE = None
