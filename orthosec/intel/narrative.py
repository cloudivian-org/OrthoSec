"""Executive narrative + free-form Q&A — the LLM layer.

Grounding contract (non-negotiable for a security product):
  * The LLM is handed ONLY the deterministic findings + scores as facts.
  * It may summarize, prioritize, translate to business language, and answer
    exec questions — but it must never invent a finding that isn't in the data.
  * With no API key or SDK installed, this degrades to a deterministic template
    so the core product still works offline.

Uses the Anthropic SDK (Claude). Model defaults to claude-opus-4-8; override with
the ORTHOSEC_MODEL env var. Adaptive thinking + high effort for careful reasoning.
"""
from __future__ import annotations

import json
import os
import textwrap

from orthosec.core.finding import Finding
from orthosec.core.scanner import ScanResult
from orthosec.intel.business_risk import business_risk
from orthosec.intel.compliance import compliance_exposure

DEFAULT_MODEL = os.environ.get("ORTHOSEC_MODEL", "claude-opus-4-8")

_SYSTEM = textwrap.dedent(
    """\
    You are OrthoSec's AI Security Architect — you translate deterministic AI-security
    findings into board-ready business context. You serve two audiences at once:
    engineers who need precise, actionable remediation, and executives who need risk
    framed in business and regulatory terms.

    HARD RULES:
    - Ground every statement in the findings JSON provided. Never invent a finding,
      file, or vulnerability that is not in the data.
    - If the data does not support an answer, say so plainly.
    - Quantify with the provided scores/bands; never fabricate specific dollar figures
      beyond the supplied ranges.
    - Be direct. Lead with the outcome. No filler.
    """
)


def _facts_payload(result: ScanResult) -> dict:
    return {
        "posture_score": result.score,
        "grade": result.grade,
        "severity_counts": result.by_severity(),
        "business_risk": business_risk(result.findings),
        "compliance_exposure": compliance_exposure(result.findings),
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.name,
                "owasp_llm": f.owasp_llm,
                "atlas": f.atlas,
                "location": f.location,
                "evidence": f.evidence,
                "remediation": f.remediation,
            }
            for f in result.findings[:200]  # cap payload size
        ],
    }


def _client_or_none():
    if not os.environ.get("ANTHROPIC_API_KEY") and not os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return None
    try:
        import anthropic  # optional dependency (orthosec[intel])
    except ImportError:
        return None
    try:
        return anthropic.Anthropic()
    except Exception:
        return None


def executive_summary(result: ScanResult) -> str:
    """Board-ready narrative. Falls back to a deterministic template offline."""
    client = _client_or_none()
    facts = _facts_payload(result)
    if client is None:
        return _fallback_summary(result, facts)

    prompt = (
        "Here are the deterministic scan facts as JSON:\n\n"
        f"{json.dumps(facts, indent=2)}\n\n"
        "Write an executive security briefing with these sections:\n"
        "1. Bottom line (2-3 sentences: are we exposed, how badly, what's the blast radius).\n"
        "2. Top 3 risk drivers, each with the business consequence and the technical cause.\n"
        "3. Regulatory exposure (map to the compliance controls in the facts).\n"
        "4. Recommended actions, prioritized, with rough effort.\n"
        "Keep it under 400 words. Ground everything in the facts."
    )
    try:
        resp = client.messages.create(
            model=DEFAULT_MODEL,
            max_tokens=4096,
            system=_SYSTEM,
            thinking={"type": "adaptive"},
            output_config={"effort": "high"},
            messages=[{"role": "user", "content": prompt}],
        )
        return _text_of(resp)
    except Exception as exc:  # never let the exec layer break the scan
        return _fallback_summary(result, facts) + f"\n\n[LLM narrative unavailable: {exc}]"


def answer_question(result: ScanResult, question: str) -> str:
    """Free-form executive Q&A, grounded on findings."""
    client = _client_or_none()
    facts = _facts_payload(result)
    if client is None:
        return (
            "Free-form Q&A needs the intel layer (pip install 'orthosec[intel]' and set "
            "ANTHROPIC_API_KEY). Deterministic facts are still available in the JSON report."
        )
    prompt = (
        f"Scan facts JSON:\n\n{json.dumps(facts, indent=2)}\n\n"
        f"Executive question: {question}\n\n"
        "Answer using only these facts. If the facts don't cover it, say what additional "
        "scanning would be needed."
    )
    try:
        resp = client.messages.create(
            model=DEFAULT_MODEL,
            max_tokens=4096,
            system=_SYSTEM,
            thinking={"type": "adaptive"},
            output_config={"effort": "high"},
            messages=[{"role": "user", "content": prompt}],
        )
        return _text_of(resp)
    except Exception as exc:
        return f"[Q&A unavailable: {exc}]"


def _text_of(resp) -> str:
    return "".join(b.text for b in resp.content if getattr(b, "type", None) == "text").strip()


def _fallback_summary(result: ScanResult, facts: dict) -> str:
    """Deterministic exec summary when the LLM layer is unavailable."""
    br = facts["business_risk"]
    lines = [
        f"AI Security Posture: {result.score}/100 (grade {result.grade}).",
        f"Findings: {sum(result.by_severity().values())} across "
        f"{len(facts['compliance_exposure'])} regulatory frameworks.",
        f"Estimated annualized loss exposure (order-of-magnitude band): "
        f"${br['ale_low_usd']:,}–${br['ale_high_usd']:,}. {br['basis']}",
        "",
        "Top risk drivers:",
    ]
    for d in br["risk_drivers"][:3]:
        lines.append(f"  • [{d['owasp']} / {d['max_severity']}] {d['consequence']}")
    lines += ["", "Set ANTHROPIC_API_KEY + install orthosec[intel] for full board-ready narrative and Q&A."]
    return "\n".join(lines)
