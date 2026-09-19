"""Header sanitization — strip identity-leaking headers, adjust Referer."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from urllib.parse import urlparse


def sanitize_headers(
    headers: Mapping[str, str],
    *,
    target_url: str = "",
    strip_identity: bool = True,
    stripped_names: Sequence[str] | None = None,
    strip_referrer: bool = False,
    referrer_policy: str = "same-origin",
    custom_referrer: str = "",
) -> dict[str, str]:
    """Return a cleaned copy of ``headers``.

    Removes headers that commonly leak the caller's identity
    (X-Forwarded-For, Via, Forwarded, etc.) and optionally rewrites or
    removes the ``Referer`` header.

    Never mutates the input mapping.
    """
    out: dict[str, str] = dict(headers.items())

    if strip_identity:
        names = stripped_names or ()
        lowered = {name.strip().lower() for name in names}
        if lowered:
            for key in list(out.keys()):
                if key.strip().lower() in lowered:
                    del out[key]

    if strip_referrer:
        out.pop("Referer", None)
        out.pop("referer", None)
        policy = (referrer_policy or "none").lower()

        if policy == "same-origin" and target_url:
            try:
                parsed = urlparse(target_url)
                origin = f"{parsed.scheme}://{parsed.netloc}"
                if origin and origin != "://":
                    out["Referer"] = origin + "/"
            except Exception:
                pass
        elif policy == "custom" and custom_referrer:
            out["Referer"] = custom_referrer

    return out
