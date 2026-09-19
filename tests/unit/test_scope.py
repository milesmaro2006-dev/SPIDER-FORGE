from spiderforge.scope.models import ScopeConfig
from spiderforge.scope.validator import ScopeValidator


def _v(include, exclude=None, allow_private=True, allow_public=True):
    return ScopeValidator(
        ScopeConfig(
            include=include,
            exclude=exclude or [],
            network={
                "allow_private_ips": allow_private,
                "allow_public_ips": allow_public,
            },
        )
    )


def test_exact_host():
    v = _v(["example.com"])
    assert v.is_allowed("https://example.com/")
    assert v.is_allowed("https://example.com/path")


def test_bare_host_matches_subdomain():
    v = _v(["example.com"])
    assert v.is_allowed("https://api.example.com/")


def test_wildcard_matches_subdomain_only():
    v = _v(["*.example.com"])
    assert v.is_allowed("https://api.example.com/")
    assert not v.is_allowed("https://example.com/")


def test_exclusion_wins():
    v = _v(["example.com"], ["admin.example.com"])
    assert v.is_allowed("https://api.example.com/")
    assert not v.is_allowed("https://admin.example.com/")


def test_out_of_scope():
    v = _v(["example.com"])
    assert not v.is_allowed("https://other.net/")


def test_private_ip_blocked():
    v = _v(["example.com"], allow_private=False)
    assert not v.is_allowed("http://127.0.0.1/")
    assert not v.is_allowed("http://10.0.0.5/")


def test_cidr_match():
    v = _v(["10.0.0.0/8"])
    assert v.is_allowed("http://10.1.2.3/")
    assert not v.is_allowed("http://11.1.2.3/")