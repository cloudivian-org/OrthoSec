"""Posture scoring — turn a list of Findings into a defensible 0-100 number.

Executives want one number; engineers want it to be non-gameable and stable.
Model: start at 100, subtract severity-weighted, confidence-scaled penalties with
diminishing returns per category so a hundred low findings can't tank the score
harder than one critical. Deterministic and unit-tested.
"""
from __future__ import annotations

import math
from collections import defaultdict

from orthosec.core.finding import Finding, Severity

_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 20.0,
    Severity.MEDIUM: 8.0,
    Severity.LOW: 3.0,
    Severity.INFO: 0.5,
}

# Diminishing-returns factor: nth finding in a category counts (DECAY ** n).
_DECAY = 0.6


def posture_score(findings: list[Finding]) -> int:
    """Return an integer 0..100. 100 == no findings."""
    if not findings:
        return 100

    # Group by (owasp category, severity) so repeated same-class issues decay.
    buckets: dict[tuple[str, Severity], int] = defaultdict(int)
    penalty = 0.0
    # Sort so the most severe within a bucket takes full weight first.
    for f in sorted(findings, key=lambda x: x.severity.value, reverse=True):
        key = (f.owasp_llm, f.severity)
        n = buckets[key]
        buckets[key] += 1
        weight = _SEVERITY_WEIGHT[f.severity] * (_DECAY ** n)
        penalty += weight * _clamp01(f.confidence)

    score = 100.0 * math.exp(-penalty / 100.0)
    return max(0, min(100, round(score)))


def grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))
