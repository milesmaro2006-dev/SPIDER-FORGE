from __future__ import annotations

from pathlib import Path

import yaml

from spiderforge.scope.models import ScopeConfig


def load_scope(path: Path) -> ScopeConfig:
    if not path.exists():
        raise FileNotFoundError(f"Scope file not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Scope file must be a mapping: {path}")

    # Support both flat and nested layout: include/exclude either at top
    # level or under a "scope:" key.
    if "scope" in data and isinstance(data["scope"], dict):
        scope_block = data["scope"]
        merged = {**data, **scope_block}
        merged.pop("scope", None)
        data = merged

    return ScopeConfig.model_validate(data)


def default_scope_for(host: str) -> ScopeConfig:
    """Create a minimal scope covering one host and its subdomains."""
    return ScopeConfig(
        project={"name": host},
        include=[host, f"*.{host}"],
        exclude=[],
    )
