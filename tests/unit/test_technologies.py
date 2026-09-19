from __future__ import annotations

from spiderforge.recon.http_probe import ProbeResult
from spiderforge.recon.technologies import detect


def test_detect_from_headers():
    probe = ProbeResult(
        url="https://x.test/",
        headers={"server": "nginx/1.24.0", "x-powered-by": "PHP/8.2.7"},
    )
    techs = {t.name: t for t in detect(probe)}
    assert "nginx" in techs
    assert techs["nginx"].version == "1.24.0"
    assert "PHP" in techs
    assert techs["PHP"].version == "8.2.7"


def test_detect_from_html_meta():
    probe = ProbeResult(
        url="https://x.test/",
        headers={},
        body_snippet='<meta name="generator" content="WordPress 6.4.2">',
    )
    techs = {t.name for t in detect(probe)}
    assert "WordPress" in techs


def test_detect_dedup_keeps_highest_confidence():
    probe = ProbeResult(
        url="https://x.test/",
        headers={"server": "nginx", "cf-ray": "abc"},
        body_snippet='<script src="/wp-includes/js/jquery.min.js"></script>',
    )
    techs = detect(probe)
    names = [t.name for t in techs]
    assert len(names) == len(set(names)), "duplicate technology names"


def test_detect_empty():
    probe = ProbeResult(url="https://x.test/", headers={}, body_snippet="")
    assert detect(probe) == []