"""SpiderForge Safe Network Layer."""

from spiderforge.network.client import SafeHttpClient, SafeResponse
from spiderforge.network.exceptions import (
    DNSRebindingDetectedError,
    DNSResolutionError,
    InvalidSchemeError,
    ProxyConnectionError,
    RedirectLimitExceededError,
    ResponseSizeExceededError,
    SafeNetworkError,
    ScopeViolationError,
    SSRFBlockedError,
)
from spiderforge.network.policies import DestinationSafetyPolicy, NetworkPolicy, ScopePolicy

__all__ = [
    "SafeHttpClient",
    "SafeResponse",
    "SafeNetworkError",
    "SSRFBlockedError",
    "ScopeViolationError",
    "DNSResolutionError",
    "RedirectLimitExceededError",
    "ResponseSizeExceededError",
    "InvalidSchemeError",
    "DNSRebindingDetectedError",
    "ProxyConnectionError",
    "NetworkPolicy",
    "ScopePolicy",
    "DestinationSafetyPolicy",
]
