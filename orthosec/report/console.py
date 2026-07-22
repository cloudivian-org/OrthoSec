"""Human-readable terminal report — stdlib only, ANSI colors with plain fallback.

The engineer-facing view: posture score, findings grouped by severity with
evidence and remediation, then the executive briefing appended at the end.
"""
from __future__ import annotations

import sys

from orthosec.core.finding import Severity
from orthosec.core.scanner import ScanResult
from orthosec.core.taxonomy import owasp_name

_COLOR = sys.stdout.isatty()
_C = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[90m"


def _c(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}" if _COLOR else text


def _grade_color(grade: str) -> str:
    return {"A": "\033[1;32m", "B": "\033[32m", "C": "\033[33m",
            "D": "\033[31m", "F": "\033[1;31m"}.get(grade, "")


def render(result: ScanResult, exec_summary: str | None = None) -> str:
    out: list[str] = []
    out.append(_c("  OrthoSec — AI Security Architect", _BOLD))
    out.append(f"  Target: {result.root}")
    out.append("")
    grade = _c(f" {result.grade} ", _grade_color(result.grade) + "\033[7m" if _COLOR else "")
    out.append(f"  Posture score: {_c(str(result.score) + '/100', _BOLD)}   Grade: {grade}")

    counts = result.by_severity()
    if counts:
        parts = []
        for sev in Severity:
            if sev.name in counts:
                parts.append(_c(f"{counts[sev.name]} {sev.name.lower()}", _C[sev]))
        out.append("  " + "   ".join(parts))
    else:
        out.append(_c("  No findings. Clean scan.", "\033[32m"))
    out.append("")

    for f in result.findings:
        tag = _c(f"[{f.severity.name}]", _C[f.severity])
        out.append(f"  {tag} {_c(f.title, _BOLD)}")
        out.append(f"      {f.location}")
        out.append(f"      OWASP {f.owasp_llm} ({owasp_name(f.owasp_llm)})"
                   + (f"  ·  ATLAS {', '.join(f.atlas)}" if f.atlas else ""))
        if f.evidence:
            out.append(f"      evidence: {f.evidence}")
        if f.business_impact:
            out.append(f"      business: {f.business_impact}")
        out.append(f"      fix: {f.remediation}")
        out.append(f"      {_c(f.rule_id, _DIM)}")
        out.append("")

    if result.errors:
        out.append(_c("  Detector errors:", "\033[31m"))
        for e in result.errors:
            out.append(f"    {e}")
        out.append("")

    if exec_summary:
        out.append(_c("  ── Executive Briefing ─────────────────────────────", _BOLD))
        for line in exec_summary.splitlines():
            out.append(f"  {line}")
        out.append("")

    return "\n".join(out)
