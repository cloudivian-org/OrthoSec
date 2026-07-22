"""Human-readable terminal report — stdlib only, ANSI colors with plain fallback.

Profile-aware: the same findings render differently per audience. An engineer
sees every issue with evidence + fix; a CISO sees posture, dollar risk, and
compliance exposure with the line-level detail suppressed.
"""
from __future__ import annotations

import sys

from orthosec.core.finding import Severity
from orthosec.core.scanner import ScanResult
from orthosec.core.taxonomy import owasp_name
from orthosec.intel.business_risk import business_risk
from orthosec.intel.compliance import compliance_exposure
from orthosec.profiles import Profile, get_profile

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


def render(result: ScanResult, exec_summary: str | None = None,
           profile: Profile | str | None = None) -> str:
    if profile is None or isinstance(profile, str):
        profile = get_profile(profile or "engineer")

    out: list[str] = []
    out.append(_c("  OrthoSec — AI Security Architect", _BOLD)
               + _c(f"   ·   view: {profile.label}", _DIM))
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

    shown = [f for f in result.findings if f.severity.value >= profile.severity_floor.value]

    if profile.show_findings:
        for f in shown:
            tag = _c(f"[{f.severity.name}]", _C[f.severity])
            out.append(f"  {tag} {_c(f.title, _BOLD)}")
            out.append(f"      {f.location}")
            out.append(f"      OWASP {f.owasp_llm} ({owasp_name(f.owasp_llm)})"
                       + (f"  ·  ATLAS {', '.join(f.atlas)}" if f.atlas else ""))
            if profile.show_evidence and f.evidence:
                out.append(f"      evidence: {f.evidence}")
            if profile.show_business and f.business_impact:
                out.append(f"      business: {f.business_impact}")
            if profile.show_remediation:
                out.append(f"      fix: {f.remediation}")
            out.append(f"      {_c(f.rule_id, _DIM)}")
            out.append("")
        hidden = len(result.findings) - len(shown)
        if hidden:
            out.append(_c(f"  ({hidden} finding(s) below the {profile.severity_floor.name} "
                          f"floor for this view — use --profile engineer to see all)", _DIM))
            out.append("")
    else:
        # Aggregate-only view (CISO): risk drivers, no per-line detail.
        out.append(_c("  Risk drivers:", _BOLD))
        for d in business_risk(shown)["risk_drivers"][:5]:
            out.append(f"    • [{d['owasp']} / {d['max_severity']}] {d['consequence']} "
                       + _c(f"({d['count']} finding(s))", _DIM))
        out.append("")

    if profile.show_business:
        br = business_risk(shown)
        out.append(_c("  Business risk:", _BOLD))
        out.append(f"    Annualized loss exposure (order-of-magnitude): "
                   f"${br['ale_low_usd']:,}–${br['ale_high_usd']:,}")
        out.append(_c(f"    {br['basis']}", _DIM))
        out.append("")

    if profile.show_compliance:
        comp = compliance_exposure(shown)
        if comp:
            out.append(_c("  Regulatory exposure:", _BOLD))
            for framework, rows in comp.items():
                controls = ", ".join(r["control"] for r in rows)
                out.append(f"    {framework.replace('_', ' ')}: {controls}")
            out.append("")

    if result.errors:
        out.append(_c("  Detector errors:", "\033[31m"))
        for e in result.errors:
            out.append(f"    {e}")
        out.append("")

    if exec_summary:
        out.append(_c(f"  ── Briefing for {profile.label} " + "─" * 20, _BOLD))
        for line in exec_summary.splitlines():
            out.append(f"  {line}")
        out.append("")

    return "\n".join(out)
