"""Finding model — the atomic unit OrthoSec produces.

A Finding is a deterministic, evidence-backed fact. The intel (LLM) layer may
*annotate* a Finding with business context but must never create one.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any


class Severity(enum.Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

    @property
    def label(self) -> str:
        return self.name

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclass
class Finding:
    """One deterministic security observation about a target AI system."""

    detector: str            # detector id that produced this
    rule_id: str             # stable, e.g. "ORTHO-SECRET-001"
    title: str               # short human title
    severity: Severity
    owasp_llm: str           # OWASP LLM Top-10 id, e.g. "LLM01"
    atlas: list[str]         # MITRE ATLAS technique ids, e.g. ["AML.T0051"]
    file: str                # relative path to evidence
    line: int                # 1-based line; 0 if file-level
    evidence: str            # the exact snippet / reason
    remediation: str         # concrete fix guidance
    confidence: float = 0.8  # 0..1 detector confidence

    # Filled in later by the intel layer. Deterministic core leaves them None.
    business_impact: str | None = None
    exec_note: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}" if self.line else self.file

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d
