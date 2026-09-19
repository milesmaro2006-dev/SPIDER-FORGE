from __future__ import annotations

import pytest

from spiderforge.findings.lifecycle import can_transition, transition
from spiderforge.findings.models import FindingStatus


def test_valid_transition():
    assert can_transition(FindingStatus.UNCONFIRMED, FindingStatus.CONFIRMED)
    assert transition(FindingStatus.UNCONFIRMED, FindingStatus.CONFIRMED) == FindingStatus.CONFIRMED


def test_invalid_transition_raises():
    with pytest.raises(ValueError):
        transition(FindingStatus.DISCOVERED, FindingStatus.FIXED)


def test_false_positive_can_be_undone():
    assert can_transition(FindingStatus.FALSE_POSITIVE, FindingStatus.UNCONFIRMED)