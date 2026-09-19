"""Network security exceptions for SpiderForge."""


class SafeNetworkError(Exception):
    """Base exception for all safe network operations."""


class SSRFBlockedError(SafeNetworkError):
    """Raised when an address resolves to a restricted/private destination."""


class ScopeViolationError(SafeNetworkError):
    """Raised when a destination is outside the authorized target scope."""


class DNSResolutionError(SafeNetworkError):
    """Raised when DNS resolution fails or returns unexpected records."""


class RedirectLimitExceededError(SafeNetworkError):
    """Raised when redirect chain exceeds the configured threshold."""


class ResponseSizeExceededError(SafeNetworkError):
    """Raised when response body exceeds maximum allowed bytes."""


class InvalidSchemeError(SafeNetworkError):
    """Raised when an unapproved scheme (e.g., file://, ftp://) is encountered."""


class DNSRebindingDetectedError(SafeNetworkError):
    """Raised when the actual peer IP differs from the validated DNS set."""


class ProxyConnectionError(SafeNetworkError):
    """Raised when the configured anonymity proxy is unreachable.

    This is a **fatal** error — it fires before any scan work begins so
    the user gets a clear message instead of a false "no findings" result.
    """
