from __future__ import annotations


class SpiderForgeError(Exception):
    """Base exception for all SpiderForge errors."""


class ScopeViolation(SpiderForgeError):
    """Raised when an outbound request targets an out-of-scope host."""


class ReconError(SpiderForgeError):
    """Recon-specific failure."""


class FetchError(SpiderForgeError):
    """A URL could not be fetched."""


class CrawlFailureError(SpiderForgeError):
    """Raised when every attempted URL during the crawl failed.

    This is a **fatal** signal: it means the target (or the proxy in
    front of it) is unreachable, so the scanner phase cannot produce
    meaningful results. The engine converts this into
    ``AssessmentResult.error_msg``.
    """
