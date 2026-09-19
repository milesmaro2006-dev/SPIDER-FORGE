from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha1_bytes(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def hash_file(path: Path) -> dict[str, str]:
    h = hashlib.sha256()
    h1 = hashlib.sha1()
    m = hashlib.md5()
    size = 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
            h1.update(chunk)
            m.update(chunk)
            size += len(chunk)
    return {
        "sha256": h.hexdigest(),
        "sha1": h1.hexdigest(),
        "md5": m.hexdigest(),
        "size": size,
    }
