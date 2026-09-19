from __future__ import annotations

from enum import Enum


class ConfidenceBand(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


def band(value: float) -> ConfidenceBand:
    if value >= 0.95:
        return ConfidenceBand.CONFIRMED
    if value >= 0.75:
        return ConfidenceBand.HIGH
    if value >= 0.5:
        return ConfidenceBand.MEDIUM
    return ConfidenceBand.LOW


def clamp(value: float) -> float:
    return max(0.0, min(1.0, value))
