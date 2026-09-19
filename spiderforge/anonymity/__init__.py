"""Anonymity / privacy features for SpiderForge."""

from spiderforge.anonymity.cookies import CookieJarManager
from spiderforge.anonymity.doh import (
    DoHResolver,
    DoHResult,
    DoHUnavailableError,
    cross_check,
)
from spiderforge.anonymity.fingerprint import (
    KNOWN_PROFILES,
    TLSFingerprint,
    tls_fingerprint_capability,
)
from spiderforge.anonymity.headers import sanitize_headers
from spiderforge.anonymity.manager import AnonymityManager, AnonymityStatus
from spiderforge.anonymity.pacing import PacingController
from spiderforge.anonymity.proxy import build_proxy_url, validate_proxy_url
from spiderforge.anonymity.user_agents import USER_AGENT_POOL, UserAgentRotator

__all__ = [
    "AnonymityManager",
    "AnonymityStatus",
    "CookieJarManager",
    "DoHResolver",
    "DoHResult",
    "DoHUnavailableError",
    "KNOWN_PROFILES",
    "PacingController",
    "TLSFingerprint",
    "USER_AGENT_POOL",
    "UserAgentRotator",
    "build_proxy_url",
    "cross_check",
    "sanitize_headers",
    "tls_fingerprint_capability",
    "validate_proxy_url",
]
