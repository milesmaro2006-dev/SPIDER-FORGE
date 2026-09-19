from __future__ import annotations

import logging
import sys
from pathlib import Path

from spiderforge.config.defaults import DEFAULT_LOG_DIR

_CONFIGURED = False


def setup_logging(level: str = "INFO", log_dir: Path | None = None, quiet: bool = False) -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return

    target_dir = log_dir or DEFAULT_LOG_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    log_file = target_dir / "spiderforge.log"

    root = logging.getLogger("spiderforge")
    root.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    root.addHandler(fh)

    if not quiet:
        sh = logging.StreamHandler(sys.stderr)
        sh.setLevel(getattr(logging, level.upper(), logging.INFO))
        sh.setFormatter(fmt)
        root.addHandler(sh)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"spiderforge.{name}")
