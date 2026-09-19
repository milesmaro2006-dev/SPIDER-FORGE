# spiderforge/cli/_utils.py
"""Helpers for calling Typer command functions programmatically.

Typer stores `Option(...)` / `Argument(...)` defaults as `OptionInfo` /
`ArgumentInfo` objects at function-definition time. When the command is
invoked programmatically (direct call or via ``ctx.invoke``), parameters
that were not explicitly passed keep those wrapper objects instead of
the real values, which breaks downstream code (e.g. httpx headers).
"""

from __future__ import annotations

from typing import Any, TypeVar

from typer.models import ArgumentInfo, OptionInfo

T = TypeVar("T")


def resolve(value: Any, default: T | None = None) -> Any:
    """Return the real runtime value of a Typer parameter.

    - ``OptionInfo`` / ``ArgumentInfo`` → unwrap to ``.default`` (or ``default``).
    - ``None``                          → return the supplied ``default``.
    - anything else                     → return as-is.
    """
    if isinstance(value, (OptionInfo, ArgumentInfo)):
        inner = value.default
        return default if inner is None else inner
    if value is None:
        return default
    return value
