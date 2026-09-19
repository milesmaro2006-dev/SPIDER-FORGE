from __future__ import annotations

from spiderforge.findings.models import FindingStatus

# Allowed transitions
_TRANSITIONS: dict[FindingStatus, set[FindingStatus]] = {
    FindingStatus.DISCOVERED: {FindingStatus.UNCONFIRMED, FindingStatus.FALSE_POSITIVE, FindingStatus.CONFIRMED},
    FindingStatus.UNCONFIRMED: {FindingStatus.CONFIRMED, FindingStatus.FALSE_POSITIVE, FindingStatus.REPORTED},
    FindingStatus.CONFIRMED: {FindingStatus.REPORTED, FindingStatus.FALSE_POSITIVE, FindingStatus.FIXED},
    FindingStatus.FALSE_POSITIVE: {FindingStatus.UNCONFIRMED},
    FindingStatus.REPORTED: {FindingStatus.FIXED, FindingStatus.RETEST_PENDING},
    FindingStatus.FIXED: {FindingStatus.RETEST_PENDING, FindingStatus.RETEST_PASSED, FindingStatus.RETEST_FAILED},
    FindingStatus.RETEST_PENDING: {FindingStatus.RETEST_PASSED, FindingStatus.RETEST_FAILED},
    FindingStatus.RETEST_PASSED: set(),
    FindingStatus.RETEST_FAILED: {FindingStatus.RETEST_PENDING},
}


def can_transition(current: FindingStatus, target: FindingStatus) -> bool:
    return target in _TRANSITIONS.get(current, set())


def transition(current: FindingStatus, target: FindingStatus) -> FindingStatus:
    if not can_transition(current, target):
        raise ValueError(f"invalid transition: {current.value} → {target.value}")
    return target
