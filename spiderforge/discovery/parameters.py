from __future__ import annotations

import base64
import re

from spiderforge.discovery.models import ParameterProfile

_NUMERIC_RE = re.compile(r"^-?\d+(?:\.\d+)?$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2})?")
_BOOL_VALUES = {"true", "false", "1", "0", "yes", "no", "on", "off"}
_HASH_MD5 = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)
_HASH_SHA1 = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_HASH_SHA256 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_PATH_RE = re.compile(r"^(?:/|\.\.?/)")


def _is_base64(value: str) -> bool:
    if len(value) < 8 or len(value) % 4 != 0:
        return False
    if not re.match(r"^[A-Za-z0-9+/]+={0,2}$", value):
        return False
    try:
        decoded = base64.b64decode(value, validate=True)
        return len(decoded) > 0
    except Exception:
        return False


def infer_type(values: list[str]) -> tuple[str, float]:
    """Infer a parameter's likely type from sample values.

    Returns ``(type_name, confidence)``.
    """
    if not values:
        return "unknown", 0.0

    checks: list[tuple[str, callable]] = [
        ("numeric", lambda v: bool(_NUMERIC_RE.match(v))),
        ("uuid", lambda v: bool(_UUID_RE.match(v))),
        ("email", lambda v: bool(_EMAIL_RE.match(v))),
        ("date", lambda v: bool(_DATE_RE.match(v))),
        ("boolean", lambda v: v.lower() in _BOOL_VALUES),
        ("md5", lambda v: bool(_HASH_MD5.match(v))),
        ("sha1", lambda v: bool(_HASH_SHA1.match(v))),
        ("sha256", lambda v: bool(_HASH_SHA256.match(v))),
        ("url", lambda v: bool(_URL_RE.match(v))),
        ("path", lambda v: bool(_PATH_RE.match(v))),
        ("base64", _is_base64),
    ]

    non_empty = [v for v in values if v != ""]
    if not non_empty:
        return "empty", 0.3

    total = len(non_empty)
    best_type = "string"
    best_ratio = 0.0

    for name, fn in checks:
        matches = sum(1 for v in non_empty if fn(v))
        ratio = matches / total
        if ratio > best_ratio:
            best_ratio = ratio
            best_type = name

    # Require some threshold to be meaningful
    if best_ratio < 0.5:
        return "string", 0.5
    # Confidence is how consistent the matches are
    confidence = 0.4 + 0.6 * best_ratio
    return best_type, round(confidence, 2)


def profile_parameter(
    url: str,
    name: str,
    source: str,
    values: list[str],
    method: str = "GET",
) -> ParameterProfile:
    ptype, conf = infer_type(values)
    return ParameterProfile(
        url=url,
        name=name,
        source=source,
        method=method,
        inferred_type=ptype,
        sample_values=values[:5],
        confidence=conf,
    )
