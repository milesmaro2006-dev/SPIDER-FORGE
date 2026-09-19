"""Canonical Finding and Evidence models for SpiderForge v3."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ═══════════════════════════════════════════════════════════════
#  Enums
# ═══════════════════════════════════════════════════════════════

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


_CONFIDENCE_NUMERIC: dict[str, float] = {
    "CONFIRMED": 0.95,
    "HIGH": 0.85,
    "MEDIUM": 0.60,
    "LOW": 0.35,
    "CANDIDATE": 0.50,
}


# Severity ordering — used to compare tiers (higher = more severe).
_SEVERITY_RANK: dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class Confidence(str, Enum):
    """Confidence level."""

    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CANDIDATE = "CANDIDATE"

    def to_float(self) -> float:
        return _CONFIDENCE_NUMERIC.get(self.value, 0.50)

    def __float__(self) -> float:
        return self.to_float()

    def __format__(self, spec: str) -> str:
        if spec and spec[-1] in "fegGEF%":
            return format(self.to_float(), spec)
        return self.value

    def __str__(self) -> str:
        return self.value


class FindingStatus(str, Enum):
    DISCOVERED = "discovered"
    UNCONFIRMED = "unconfirmed"
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    REPORTED = "reported"
    FIXED = "fixed"
    RETEST_PENDING = "retest_pending"
    RETEST_PASSED = "retest_passed"
    RETEST_FAILED = "retest_failed"


# ═══════════════════════════════════════════════════════════════
#  Severity ↔ CVSS mapping (FIRST.org standard)
# ═══════════════════════════════════════════════════════════════

def _severity_from_cvss(score: float) -> Severity:
    """Map a CVSS 3.1 base score to a severity tier (FIRST.org standard)."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return Severity.INFO
    if s >= 9.0:
        return Severity.CRITICAL
    if s >= 7.0:
        return Severity.HIGH
    if s >= 4.0:
        return Severity.MEDIUM
    if s > 0.0:
        return Severity.LOW
    return Severity.INFO


# ═══════════════════════════════════════════════════════════════
#  Evidence
# ═══════════════════════════════════════════════════════════════

class FindingEvidence(BaseModel):
    """Structured, redacted technical evidence."""

    model_config = ConfigDict(extra="allow")

    kind: str = "http"
    request_url: str = ""
    http_method: str = "GET"
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str | None = None
    response_status: int = 200
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str | None = None
    payload: str | None = None
    screenshot_path: str | None = None
    note: str | None = None
    evidence_hash: str = ""

    @model_validator(mode="before")
    @classmethod
    def _remap_legacy_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        d = dict(data)

        if "request" in d and "request_url" not in d:
            d["request_url"] = d.pop("request")

        if "response" in d and "response_body" not in d:
            resp = d.pop("response")
            if isinstance(resp, dict):
                d.setdefault("request_url", resp.get("request_url") or "")
                if "response_status" not in d and resp.get("response_status") is not None:
                    d["response_status"] = resp.get("response_status")
                if "response_headers" not in d and isinstance(resp.get("response_headers"), dict):
                    d["response_headers"] = resp.get("response_headers")
                body = resp.get("response_body")
                d["response_body"] = body if body is None or isinstance(body, str) else str(body)
            elif resp is None or isinstance(resp, str):
                d["response_body"] = resp
            else:
                d["response_body"] = str(resp)

        if "notes" in d and "note" not in d:
            d["note"] = d.pop("notes")
        if "headers" in d and "response_headers" not in d:
            d["response_headers"] = d.pop("headers")
        d.setdefault("request_url", "")
        if d.get("request_url") is not None and not isinstance(d.get("request_url"), str):
            d["request_url"] = str(d["request_url"])
        return d

    def model_post_init(self, __context: Any) -> None:
        if not self.evidence_hash:
            seed = "|".join([
                self.kind,
                self.request_url,
                self.http_method,
                self.request_body or "",
                str(self.response_status),
                self.response_body or "",
                self.payload or "",
                self.screenshot_path or "",
                self.note or "",
            ])
            self.evidence_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest()


Evidence = FindingEvidence


# ═══════════════════════════════════════════════════════════════
#  Finding
# ═══════════════════════════════════════════════════════════════

class Finding(BaseModel):
    """Canonical vulnerability and observation model."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    fingerprint: str = ""

    title: str
    category: str
    severity: Severity
    confidence: Confidence = Confidence.MEDIUM

    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwe_id: str | None = None
    owasp_category: str | None = None

    url: str
    host: str = ""
    http_method: str = "GET"
    parameter: str | None = None
    payload_applied: str | None = None

    description: str = ""
    impact: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    scanner_name: str = ""
    status: FindingStatus = FindingStatus.DISCOVERED

    evidence: list[FindingEvidence] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("confidence", mode="before")
    @classmethod
    def _coerce_confidence(cls, v: Any) -> Any:
        if isinstance(v, (int, float)):
            f = float(v)
            if f >= 0.9:
                return Confidence.CONFIRMED
            if f >= 0.75:
                return Confidence.HIGH
            if f >= 0.5:
                return Confidence.MEDIUM
            return Confidence.LOW
        return v

    @field_validator("evidence", mode="before")
    @classmethod
    def _coerce_evidence(cls, v: Any) -> Any:
        if v is None:
            return []
        if isinstance(v, (FindingEvidence, dict)):
            return [v]
        return v

    @property
    def method(self) -> str:
        return self.http_method

    @property
    def confidence_score(self) -> float:
        return self.confidence.to_float()

    def model_post_init(self, __context: Any) -> None:
        if not self.host:
            try:
                from urllib.parse import urlparse
                self.host = (urlparse(self.url).hostname or "").lower()
            except Exception:
                pass

        if not self.fingerprint:
            normalized_url = self.url.split("?")[0].rstrip("/").lower()
            param_key = (self.parameter or "").lower().strip()
            normalized_title = self.title.strip().lower()
            seed = "|".join([
                self.category.lower(),
                self.host.lower(),
                normalized_url,
                self.http_method.upper(),
                param_key,
                self.scanner_name.lower(),
                normalized_title,
            ])
            self.fingerprint = hashlib.sha256(seed.encode("utf-8")).hexdigest()

        # Auto-apply classification (CWE / OWASP / CVSS)
        try:
            from spiderforge.findings.classification import apply_classification
            apply_classification(self)
        except Exception:
            pass

        # Severity escalation from CVSS (never downgrades)
        if self.cvss_score is not None:
            cvss_tier = _severity_from_cvss(self.cvss_score)
            current_rank = _SEVERITY_RANK.get(self.severity.value, 0)
            cvss_rank = _SEVERITY_RANK.get(cvss_tier.value, 0)
            if cvss_rank > current_rank:
                self.severity = cvss_tier

    def add_evidence(self, ev: FindingEvidence) -> None:
        self.evidence.append(ev)
        self.updated_at = datetime.now(timezone.utc)
