from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FormField:
    name: str
    type: str = "text"
    value: str | None = None
    required: bool = False
    placeholder: str | None = None


@dataclass
class Form:
    action: str
    method: str = "GET"
    fields: list[FormField] = field(default_factory=list)
    source_url: str = ""
    enctype: str = "application/x-www-form-urlencoded"


@dataclass
class ParameterRecord:
    url: str
    name: str
    source: str  # "url" | "form"
    method: str = "GET"
