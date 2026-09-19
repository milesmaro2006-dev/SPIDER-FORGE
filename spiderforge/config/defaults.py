from __future__ import annotations

from pathlib import Path

APP_NAME = "spiderforge"
DEFAULT_CONFIG_DIR = Path.home() / ".config" / APP_NAME
DEFAULT_DATA_DIR = Path.home() / ".spiderforge"
DEFAULT_WORKSPACES_DIR = DEFAULT_DATA_DIR / "workspaces"
DEFAULT_DB_PATH = DEFAULT_DATA_DIR / "spiderforge.db"
DEFAULT_LOG_DIR = DEFAULT_DATA_DIR / "logs"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.yaml"

PROFILES: dict[str, dict] = {
    "fast": {
        "scanner": {"concurrency": 40, "timeout": 10.0, "max_depth": 2, "aggressive": False},
    },
    "balanced": {
        "scanner": {"concurrency": 20, "timeout": 20.0, "max_depth": 5, "aggressive": False},
    },
    "aggressive": {
        "scanner": {"concurrency": 60, "timeout": 20.0, "max_depth": 8, "aggressive": True},
        "recon": {"subdomains": True, "ports": True, "technologies": True},
    },
}
