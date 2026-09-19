from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from spiderforge.config.defaults import DEFAULT_CONFIG_FILE, PROFILES
from spiderforge.config.models import SpiderForgeConfig


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if key in out and isinstance(out[key], dict) and isinstance(value, dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: Path | None = None, profile: str | None = None) -> SpiderForgeConfig:
    """Load config from YAML (if present), apply a named profile, validate."""
    data: dict[str, Any] = {}

    config_path = path or DEFAULT_CONFIG_FILE
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f) or {}
            if not isinstance(loaded, dict):
                raise ValueError(f"Config file must be a mapping: {config_path}")
            data = loaded

    if os.environ.get("SPIDERFORGE_LOG_LEVEL"):
        data.setdefault("logging", {})["level"] = os.environ["SPIDERFORGE_LOG_LEVEL"]

    if profile:
        if profile not in PROFILES:
            raise ValueError(f"Unknown profile {profile!r}. Known: {list(PROFILES)}")
        data = _deep_merge(data, PROFILES[profile])

    return SpiderForgeConfig.model_validate(data)
