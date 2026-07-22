"""Deterministic compliance mapping — no LLM required.

Answers the recurring board question: "which regulations does this expose us to?"
by resolving each finding's OWASP category to concrete framework controls.
"""
from __future__ import annotations

from collections import defaultdict

from orthosec.core.finding import Finding
from orthosec.core.taxonomy import COMPLIANCE, OWASP_TO_COMPLIANCE


def compliance_exposure(findings: list[Finding]) -> dict[str, list[dict]]:
    """framework -> list of {control, description, triggered_by:[rule_ids]}."""
    hits: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
    for f in findings:
        for framework, control in OWASP_TO_COMPLIANCE.get(f.owasp_llm, []):
            hits[framework][control].add(f.rule_id)

    out: dict[str, list[dict]] = {}
    for framework, controls in hits.items():
        rows = []
        for control, rule_ids in sorted(controls.items()):
            rows.append({
                "control": control,
                "description": COMPLIANCE.get(framework, {}).get(control, ""),
                "triggered_by": sorted(rule_ids),
            })
        out[framework] = rows
    return out
