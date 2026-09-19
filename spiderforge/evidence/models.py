from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EvidenceArtifact:
    kind: str  # request | response | body | screenshot | note | raw
    path: str
    sha256: str = ""
    size: int = 0
    content_type: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceBundle:
    finding_id: str
    dir: str
    artifacts: list[EvidenceArtifact] = field(default_factory=list)

    def add(self, artifact: EvidenceArtifact) -> None:
        self.artifacts.append(artifact)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "dir": self.dir,
            "artifacts": [
                {
                    "kind": a.kind,
                    "path": a.path,
                    "sha256": a.sha256,
                    "size": a.size,
                    "content_type": a.content_type,
                    "meta": a.meta,
                }
                for a in self.artifacts
            ],
        }
