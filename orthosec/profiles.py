"""Audience profiles — one scan, many lenses.

The same deterministic findings are reframed for whoever is reading. An AI/ML
engineer wants evidence + remediation on every issue; a CISO wants posture,
dollar risk, and regulatory exposure with the line-level noise suppressed. A
profile controls what the console shows, the severity floor, and how the LLM
narrative is framed — without ever changing the underlying facts.
"""
from __future__ import annotations

from dataclasses import dataclass

from orthosec.core.finding import Severity


@dataclass(frozen=True)
class Profile:
    id: str
    label: str
    audience: str
    severity_floor: Severity      # hide findings below this
    show_findings: bool           # per-finding detail vs. aggregate only
    show_evidence: bool
    show_remediation: bool
    show_business: bool
    show_compliance: bool
    narrative_focus: str          # steers the LLM briefing


PROFILES: dict[str, Profile] = {
    # AI/ML engineer — the default. Wants every issue with a fix. Bottom-up adopter.
    "engineer": Profile(
        id="engineer",
        label="AI/ML Engineer",
        audience="the engineer who ships and fixes the AI system",
        severity_floor=Severity.LOW,
        show_findings=True,
        show_evidence=True,
        show_remediation=True,
        show_business=False,
        show_compliance=False,
        narrative_focus=(
            "Prioritize by exploitability and fix effort. Be concrete and technical: "
            "which code, which change, in what order. Skip business/compliance framing."
        ),
    ),
    # Security / AppSec engineer — threat rigor. Wants attack framing + ATLAS + CI signal.
    "appsec": Profile(
        id="appsec",
        label="Security / AppSec Engineer",
        audience="a security engineer threat-modeling the AI system",
        severity_floor=Severity.LOW,
        show_findings=True,
        show_evidence=True,
        show_remediation=True,
        show_business=True,
        show_compliance=False,
        narrative_focus=(
            "Frame each risk as an attack path: entry point, technique (cite MITRE ATLAS), "
            "blast radius, and the control that breaks the chain. Note what to gate in CI."
        ),
    ),
    # CISO / security leader — board-facing. Posture, dollar risk, regulation. No line noise.
    "ciso": Profile(
        id="ciso",
        label="CISO / Security Leader",
        audience="a security executive briefing leadership or the board",
        severity_floor=Severity.MEDIUM,
        show_findings=False,
        show_evidence=False,
        show_remediation=False,
        show_business=True,
        show_compliance=True,
        narrative_focus=(
            "Lead with the bottom line: are we exposed, how bad, what's the blast radius. "
            "Quantify with the risk bands, map to regulatory obligations, and give a "
            "prioritized action plan with rough effort. No code-level detail."
        ),
    ),
    # AI product / eng leader — risk vs. shipping velocity. Top risks + quick wins.
    "product": Profile(
        id="product",
        label="AI Product / Eng Leader",
        audience="a product or engineering leader balancing risk against ship velocity",
        severity_floor=Severity.MEDIUM,
        show_findings=True,
        show_evidence=False,
        show_remediation=True,
        show_business=True,
        show_compliance=True,
        narrative_focus=(
            "Balance risk against velocity. Separate 'must-fix-before-ship' from "
            "'fast-follow'. Call out quick wins (high risk, low effort) explicitly."
        ),
    ),
}

DEFAULT_PROFILE = "engineer"


def get_profile(profile_id: str) -> Profile:
    return PROFILES.get(profile_id, PROFILES[DEFAULT_PROFILE])
