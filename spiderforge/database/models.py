"""SQLAlchemy ORM models for SpiderForge persistence.

Kept in sync with the canonical Pydantic Finding model
(spiderforge.findings.models.Finding).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    scans: Mapped[list[Scan]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_uid: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)

    target: Mapped[str] = mapped_column(String(2048))
    profile: Mapped[str] = mapped_column(String(32), default="balanced")
    status: Mapped[str] = mapped_column(String(32), default="created", index=True)

    # JSON blobs (deterministic serialization)
    scope_config: Mapped[str] = mapped_column(Text, default="{}")
    configuration: Mapped[str] = mapped_column(Text, default="{}")

    # Lifecycle
    started_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Summary counters (denormalized for fast listing)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    discovered_urls_count: Mapped[int] = mapped_column(Integer, default=0)

    workspace_path: Mapped[str] = mapped_column(String(2048), default="")

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )

    project: Mapped[Project] = relationship(back_populates="scans")
    findings: Mapped[list[FindingRow]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)

    # Canonical identity
    finding_uid: Mapped[str] = mapped_column(String(64), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)

    # Classification
    title: Mapped[str] = mapped_column(String(512))
    category: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    status: Mapped[str] = mapped_column(String(32), default="discovered", index=True)

    # Optional scoring
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Target
    url: Mapped[str] = mapped_column(String(2048))
    host: Mapped[str] = mapped_column(String(255), default="", index=True)
    method: Mapped[str] = mapped_column(String(16), default="GET")
    parameter: Mapped[str | None] = mapped_column(String(255), nullable=True)
    payload_applied: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Description
    description: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    references_json: Mapped[str] = mapped_column(Text, default="[]")

    # Metadata
    scanner_name: Mapped[str] = mapped_column(String(64), default="")

    # Evidence (redacted list, JSON serialized)
    evidence_json: Mapped[str] = mapped_column(Text, default="[]")

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )

    scan: Mapped[Scan] = relationship(back_populates="findings")
