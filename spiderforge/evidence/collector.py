"""Evidence collector integrating canonical findings and automatic secret redaction."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from spiderforge.evidence.redactor import SecretRedactor
from spiderforge.findings.models import Finding, FindingEvidence


# Inherit from the concrete platform path flavour (``PosixPath`` on
# Linux/macOS, ``WindowsPath`` on Windows) rather than from
# ``pathlib.Path`` directly. Subclassing ``Path`` on Python 3.11–3.13
# leaves ``_flavour`` undefined on the subclass, so instantiating it
# raises::
#
#     AttributeError: type object 'Artifact' has no attribute '_flavour'
#
# ``type(Path())`` returns the concrete flavour and inherits
# ``_flavour`` correctly on every supported interpreter.
_PathBase: type[Path] = type(Path())


class Artifact(_PathBase):  # type: ignore[misc, valid-type]
    """A Path pointing to an evidence artifact enriched with sha256 hash and metadata."""

    sha256: str = ""
    kind: str = "note"

    def __new__(cls, *args: Any, **kwargs: Any) -> Artifact:
        return super().__new__(cls, *args)

    @property
    def path(self) -> Path:
        return Path(self)


class EvidenceCollector:
    """Collects, redacts, and cryptographically hashes scan evidence."""

    def __init__(self, base_dir: Path | None = None) -> None:
        self.base_dir: Path | None = (
            Path(base_dir) if base_dir is not None else None
        )
        if self.base_dir is not None:
            self.base_dir.mkdir(parents=True, exist_ok=True)

    # ── Stateless factory ─────────────────────────────────────────

    @staticmethod
    def create_evidence(
        request_url: str,
        http_method: str = "GET",
        request_headers: dict[str, Any] | None = None,
        request_body: str | None = None,
        response_status: int = 200,
        response_headers: dict[str, Any] | None = None,
        response_body: str | None = None,
        payload: str | None = None,
        note: str | None = None,
    ) -> FindingEvidence:
        clean_req_headers = SecretRedactor.redact_headers(request_headers or {})
        clean_res_headers = SecretRedactor.redact_headers(response_headers or {})
        clean_req_body = (
            SecretRedactor.redact_text(request_body) if request_body else None
        )
        clean_res_body = (
            SecretRedactor.redact_text(response_body) if response_body else None
        )

        return FindingEvidence(
            request_url=request_url,
            http_method=http_method,
            request_headers=clean_req_headers,
            request_body=clean_req_body,
            response_status=response_status,
            response_headers=clean_res_headers,
            response_body=clean_res_body,
            payload=payload,
            note=note,
        )

    # ── Stateful helpers ──────────────────────────────────────────

    def capture_text(
        self,
        finding: Finding,
        *,
        name: str,
        content: str,
        kind: str = "note",
    ) -> Artifact | None:
        if self.base_dir is None:
            return None
        target_dir = self.base_dir / "findings" / finding.id
        target_dir.mkdir(parents=True, exist_ok=True)
        out = target_dir / name
        out.write_text(content, encoding="utf-8")
        h = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
        art = Artifact(out)
        art.sha256 = h
        art.kind = kind
        return art

    def capture_bytes(
        self,
        finding: Finding,
        *,
        name: str,
        content: bytes,
        kind: str = "binary",
    ) -> Artifact | None:
        if self.base_dir is None:
            return None
        target_dir = self.base_dir / "findings" / finding.id
        target_dir.mkdir(parents=True, exist_ok=True)
        out = target_dir / name
        out.write_bytes(content)
        h = hashlib.sha256(content).hexdigest()
        art = Artifact(out)
        art.sha256 = h
        art.kind = kind
        return art

    def export_findings(
        self,
        findings: list[Finding],
        *,
        name: str = "findings.json",
    ) -> Path | None:
        if self.base_dir is None:
            return None
        out = self.base_dir / name
        out.write_text(
            json.dumps(
                [f.model_dump(mode="json") for f in findings],
                indent=2,
                ensure_ascii=False,
                default=str,
            ),
            encoding="utf-8",
        )
        return out

    # ── Hashing helpers ───────────────────────────────────────────

    @staticmethod
    def sha256_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
