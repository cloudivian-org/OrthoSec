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
from orthosec.profiles import Profile, get_profile

DEFAULT_MODEL = "claude-opus-4-8"

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


def _resolve_client_and_model():
    """Pick the LLM backend from the environment. Returns (client, model) or (None, None).

    Provider precedence:
      1. Azure AI Foundry (Anthropic-compatible Messages API) — AZURE_API_KEY + AZURE_BASE_URL.
         Model comes from ORTHOSEC_MODEL, else the first id in AZURE_MODELS.
      2. First-party Anthropic API — ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN.
    """
    try:
        import anthropic  # optional dependency (orthosec[intel])
    except ImportError:
        return None, None

    azure_key = os.environ.get("AZURE_API_KEY")
    azure_url = os.environ.get("AZURE_BASE_URL")
    if azure_key and azure_url:
        model = os.environ.get("ORTHOSEC_MODEL") or _first_azure_model()
        try:
            client = anthropic.Anthropic(
                api_key=azure_key,
                base_url=azure_url,
                # Azure Cognitive Services gateways authenticate with an `api-key`
                # header; send it alongside the SDK's default x-api-key.
                default_headers={"api-key": azure_key},
            )
            return client, model
        except Exception:
            return None, None

    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        model = os.environ.get("ORTHOSEC_MODEL", DEFAULT_MODEL)
        try:
            return anthropic.Anthropic(), model
        except Exception:
            return None, None

    return None, None


def _first_azure_model() -> str:
    ids = [m.strip() for m in os.environ.get("AZURE_MODELS", "").split(",") if m.strip()]
    return ids[0] if ids else "claude-sonnet-4-6"


def executive_summary(result: ScanResult, profile: Profile | str | None = None) -> str:
    """Audience-tuned narrative. Falls back to a deterministic template offline."""
    if profile is None or isinstance(profile, str):
        profile = get_profile(profile or "engineer")
    client, model = _resolve_client_and_model()
    facts = _facts_payload(result)
    if client is None:
        return _fallback_summary(result, facts)

    prompt = (
        "Here are the deterministic scan facts as JSON:\n\n"
        f"{json.dumps(facts, indent=2)}\n\n"
        f"Write a security briefing for {profile.audience}.\n"
        f"Focus: {profile.narrative_focus}\n\n"
        "Keep it under 400 words. Ground everything in the facts — never invent a finding."
    )
    try:
        resp = _call(client, model, prompt)
        return _text_of(resp)
    except Exception as exc:  # never let the exec layer break the scan
        return _fallback_summary(result, facts) + f"\n\n[LLM narrative unavailable: {exc}]"


def answer_question(result: ScanResult, question: str) -> str:
    """Free-form executive Q&A, grounded on findings."""
    client, model = _resolve_client_and_model()
    facts = _facts_payload(result)
    if client is None:
        return (
            "Free-form Q&A needs the intel layer (pip install 'orthosec[intel]' and set "
            "ANTHROPIC_API_KEY or AZURE_API_KEY). Deterministic facts are still in the JSON report."
        )
    prompt = (
        f"Scan facts JSON:\n\n{json.dumps(facts, indent=2)}\n\n"
        f"Executive question: {question}\n\n"
        "Answer using only these facts. If the facts don't cover it, say what additional "
        "scanning would be needed."
    )
    try:
        resp = _call(client, model, prompt)
        return _text_of(resp)
    except Exception as exc:
        return f"[Q&A unavailable: {exc}]"


def _call(client, model: str, prompt: str):
    """Make the request. Retry without thinking/effort if the provider rejects them
    (some gateways serve older API surfaces that 400 on adaptive thinking/effort)."""
    base = dict(model=model, max_tokens=4096, system=_SYSTEM,
                messages=[{"role": "user", "content": prompt}])
    try:
        return client.messages.create(
            thinking={"type": "adaptive"}, output_config={"effort": "high"}, **base
        )
    except Exception:
        return client.messages.create(**base)


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
