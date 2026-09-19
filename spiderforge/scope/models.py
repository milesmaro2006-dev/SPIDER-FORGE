"""Scope configuration models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class NetworkPolicy(BaseModel):
    allow_private_ips: bool = False
    allow_public_ips: bool = True


class ProjectMeta(BaseModel):
    name: str = "default"


class ScopeConfig(BaseModel):
    project: ProjectMeta = Field(default_factory=ProjectMeta)
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
