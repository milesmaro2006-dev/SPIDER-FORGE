"""Secret Redaction Engine for SpiderForge v3.

Ensures tokens, passwords, cookies, and keys are scrubbed before persistence or reporting.
"""

import re
from typing import Any


class SecretRedactor:
    """Detects and redacts sensitive credentials and authorization material."""

    # Headers whose values must be sanitized
    SENSITIVE_HEADERS = {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
    }

    # High-entropy secret patterns in strict precedence order
    PATTERNS: list[tuple[re.Pattern, str]] = [
        # 1. Bearer and Basic headers / values
        (re.compile(r"(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*", re.IGNORECASE), r"\1[REDACTED]"),
        (re.compile(r"(Basic\s+)[A-Za-z0-9\+\/]+=*", re.IGNORECASE), r"\1[REDACTED]"),
        # 2. Standalone JWT signatures (three base64 segments)
        (re.compile(r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"), r"[REDACTED_JWT]"),
        # 3. Key-value pairs in query strings / forms
        (re.compile(r"((?:password|passwd|pwd|secret|api_key|access_token)=)([^&\s]+)", re.IGNORECASE), r"\1[REDACTED]"),
        # 4. JSON key-value pairs (excluding already redacted tokens)
        (re.compile(r"([\"'](?:password|passwd|pwd|secret|api_key|access_token)[\"']\s*:\s*[\"'])([^\"']+)([\"'])", re.IGNORECASE), r"\1[REDACTED]\3"),
    ]

    @classmethod
    def redact_headers(cls, headers: dict[str, Any]) -> dict[str, str]:
        """Redact sensitive HTTP header values."""
        sanitized: dict[str, str] = {}
        for key, value in headers.items():
            k_lower = key.lower().strip()
            str_val = str(value)
            if k_lower in cls.SENSITIVE_HEADERS:
                if k_lower in {"cookie", "set-cookie"}:
                    sanitized[key] = re.sub(r"(=)[^;]+", r"=[REDACTED]", str_val)
                elif "bearer" in str_val.lower():
                    sanitized[key] = "Bearer [REDACTED]"
                elif "basic" in str_val.lower():
                    sanitized[key] = "Basic [REDACTED]"
                else:
                    sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = cls.redact_text(str_val)
        return sanitized

    @classmethod
    def redact_text(cls, text: str) -> str:
        """Scan string content and mask known secret patterns."""
        if not text:
            return ""
        sanitized = text
        for pattern, replacement in cls.PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized

    @classmethod
    def sanitize_evidence_bundle(cls, bundle: dict[str, Any]) -> dict[str, Any]:
        """Sanitize an entire evidence payload dictionary."""
        cleaned = dict(bundle)
        if "request_headers" in cleaned and isinstance(cleaned["request_headers"], dict):
            cleaned["request_headers"] = cls.redact_headers(cleaned["request_headers"])
        if "response_headers" in cleaned and isinstance(cleaned["response_headers"], dict):
            cleaned["response_headers"] = cls.redact_headers(cleaned["response_headers"])
        if "request_body" in cleaned and isinstance(cleaned["request_body"], str):
            cleaned["request_body"] = cls.redact_text(cleaned["request_body"])
        if "response_body" in cleaned and isinstance(cleaned["response_body"], str):
            cleaned["response_body"] = cls.redact_text(cleaned["response_body"])
        return cleaned
