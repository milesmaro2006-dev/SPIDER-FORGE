from __future__ import annotations

from spiderforge.findings.cvss import PRESETS, CvssV31, score_for


def test_base_score_full_rce():
    # Classic AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0
    c = PRESETS["cmdi"]
    assert c.base_score() == 10.0
    assert c.severity() == "critical"


def test_base_score_reflected_xss():
    c = PRESETS["reflected_xss"]
    score = c.base_score()
    # CVSS 3.1 vector AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1
    assert score == 6.1
    assert c.severity() == "medium"


def test_base_score_sqli():
    c = PRESETS["sqli"]
    # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
    assert c.base_score() == 9.8
    assert c.severity() == "critical"


def test_no_impact_score_zero():
    c = CvssV31()
    c.confidentiality = c.integrity = c.availability = c.impact_none() if hasattr(c, "impact_none") else c.confidentiality
    # Force none
    from spiderforge.findings.cvss import Impact

    c.confidentiality = Impact.NONE
    c.integrity = Impact.NONE
    c.availability = Impact.NONE
    assert c.base_score() == 0.0
    assert c.severity() == "none"


def test_vector_format():
    v = PRESETS["sqli"].vector()
    assert v.startswith("CVSS:3.1/")
    assert "AV:N" in v and "AC:L" in v


def test_score_for_known_category():
    assert score_for("xss.reflected") is not None
    assert score_for("sqli.error") is not None
    assert score_for("nonsense") is None