from __future__ import annotations

from spiderforge.discovery.endpoints import merge_endpoints, path_template
from spiderforge.discovery.parameters import infer_type
from spiderforge.discovery.models import Endpoint


def test_path_template_numeric():
    assert path_template("https://x.test/users/123/orders/456") == "/users/{id}/orders/{id}"


def test_path_template_uuid():
    u = "https://x.test/items/550e8400-e29b-41d4-a716-446655440000"
    assert path_template(u) == "/items/{uuid}"


def test_merge_endpoints_dedup():
    eps = [
        Endpoint(url="https://x.test/users/1", method="GET", parameters=["a"]),
        Endpoint(url="https://x.test/users/2", method="GET", parameters=["b"]),
        Endpoint(url="https://x.test/users/3", method="POST", parameters=["c"]),
    ]
    merged = merge_endpoints(eps)
    keys = {(e.method, e.path_template) for e in merged}
    assert ("GET", "/users/{id}") in keys
    assert ("POST", "/users/{id}") in keys
    # Params merged on the GET entry
    get_entry = next(e for e in merged if e.method == "GET")
    assert set(get_entry.parameters) == {"a", "b"}


def test_infer_type_numeric():
    assert infer_type(["1", "2", "3"])[0] == "numeric"


def test_infer_type_uuid():
    t, _ = infer_type(["550e8400-e29b-41d4-a716-446655440000"])
    assert t == "uuid"


def test_infer_type_email():
    assert infer_type(["a@b.com"])[0] == "email"


def test_infer_type_bool():
    assert infer_type(["true", "false"])[0] == "boolean"


def test_infer_type_string_fallback():
    assert infer_type(["hello", "world"])[0] == "string"


def test_infer_type_empty():
    assert infer_type([])[0] == "unknown"