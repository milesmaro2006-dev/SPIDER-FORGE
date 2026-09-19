from __future__ import annotations

import hashlib


def sha256_hex(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", errors="replace"))
        h.update(b"\x00")
    return h.hexdigest()


def fingerprint(*parts: str) -> str:
    return sha256_hex(*parts)[:32]
