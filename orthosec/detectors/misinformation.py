"""Detect unverified model output returned to users (advisory).

OWASP LLM09 (Misinformation).
Static analysis cannot judge whether output is *true* — so this is an ADVISORY,
INFO-level heuristic, not a defect: a user-facing function that returns raw model
output with no grounding, citation, verification, or disclaimer anywhere nearby.
The remedy is to add grounding/citations or a confidence/disclaimer, not to "fix"
a specific line. Tightly gated to avoid noise; Python-only.
"""
from __future__ import annotations

from typing import Iterable

from orthosec.core.finding import Finding, Severity
from orthosec.core.scanner import ScanContext
from orthosec.detectors import register
from orthosec.analysis.pyast import safe_parse, misinformation_sinks


@register
class MisinformationDetector:
    id = "misinformation"
    name = "Unverified model output to users (advisory)"
    owasp_llm = "LLM09"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.files:
            if path.suffix.lower() != ".py":
                continue
            text = ctx.read(path)
            if not text:
                continue
            tree = safe_parse(text)
            if tree is None:
                continue
            lines = text.splitlines()
            for s in misinformation_sinks(tree, lines):
                yield Finding(
                    detector=self.id, rule_id="ORTHO-MISINFO-001",
                    title="Unverified model output returned to users — no grounding (advisory)",
                    severity=Severity.INFO, owasp_llm="LLM09", atlas=[],
                    file=ctx.rel(path), line=s.line, evidence=s.snippet,
                    remediation=(
                        "Add grounding for user-facing answers: cite retrieved sources, "
                        "verify against a trusted source, or surface a confidence / disclaimer. "
                        "Don't present raw model output as authoritative fact."),
                    confidence=0.4)
