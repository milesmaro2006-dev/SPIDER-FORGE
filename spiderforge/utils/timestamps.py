from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(dt: datetime | None = None) -> str:
    return (dt or utcnow()).isoformat()


def scan_id(prefix: str = "scan") -> str:
    return f"{prefix}-{utcnow().strftime('%Y%m%d-%H%M%S')}"
