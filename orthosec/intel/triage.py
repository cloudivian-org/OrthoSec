"""Optional model-backed confidence tiering for deterministic findings.

The deterministic engine is the trusted, reproducible floor. When a model backend is
configured AND `ORTHOSEC_CONFIDENCE=1`, this pass asks the model to corroborate each
finding against its code context and assigns a **confidence tier**:

  * "confirmed"     — the model agrees it's a real, reachable issue (tier up).
  * "deterministic" — unchanged (model uncertain, or corroboration disabled/unavailable).
  * (a model that thinks it's a false positive does NOT remove or downgrade the finding —
     the deterministic result stands; we only attach an advisory note for the human.)

Additive and fail-open: a model error leaves every finding exactly as the deterministic
engine produced it. Never removes a finding, never invents one. This is the "models
confirm, deterministic decides" half of the confidence-tier design.
"""
from __future__ import annotations

import json
import os
from pathlib import Path


def enabled() -> bool:
    return (os.environ.get("ORTHOSEC_CONFIDENCE", "") or "").strip().lower() in ("1", "true", "yes", "on")


def _max_findings() -> int:
    try:
        return int(os.environ.get("ORTHOSEC_CONFIDENCE_MAX", "40"))
    except ValueError:
        return 40


_SYSTEM = (
    "You are a security triage assistant. You are given ONE deterministic static-analysis "
    "finding and the code around it. Judge only whether the finding is a real, reachable "
    "security issue in THIS code. You cannot add or remove findings — only assess this one. "
    'Reply with a single compact JSON object: {"verdict": "confirmed"|"uncertain"|'
    '"false_positive", "reason": "<one short sentence>"}.'
)


def _context(root: str, finding, radius: int = 6) -> str:
    try:
        p = Path(root) / finding.file
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return finding.evidence or ""
    if not finding.line:
        return "\n".join(lines[:radius * 2])
    lo = max(0, finding.line - 1 - radius)
    hi = min(len(lines), finding.line + radius)
    out = []
    for i in range(lo, hi):
        marker = ">>" if (i + 1) == finding.line else "  "
        out.append(f"{marker} {i + 1}: {lines[i]}")
    return "\n".join(out)


def _parse_verdict(text: str):
    try:
        start, end = text.index("{"), text.rindex("}") + 1
        obj = json.loads(text[start:end])
    except (ValueError, json.JSONDecodeError):
        low = text.lower()
        if "confirmed" in low:
            return "confirmed", ""
        if "false" in low:
            return "false_positive", ""
        return "uncertain", ""
    v = str(obj.get("verdict", "uncertain")).strip().lower()
    if v not in ("confirmed", "uncertain", "false_positive"):
        v = "uncertain"
    return v, str(obj.get("reason", "")).strip()[:200]


def corroborate(findings, root: str) -> None:
    """Assign confidence tiers to `findings` in place using a model. No-op when disabled
    or no model backend is available. Never raises (fails open)."""
    if not enabled() or not findings:
        return
    try:
        from orthosec.intel.narrative import _resolve_client_and_model, _call, _text_of
        client, model = _resolve_client_and_model()
    except Exception:
        return
    if client is None:
        return

    for f in findings[:_max_findings()]:
        try:
            prompt = (
                f"FINDING:\n- rule: {f.rule_id}\n- title: {f.title}\n"
                f"- severity: {f.severity.name}\n- OWASP: {f.owasp_llm}\n"
                f"- location: {f.location}\n- evidence: {f.evidence}\n\n"
                f"CODE (>> marks the finding line):\n{_context(root, f)}\n"
            )
            resp = _call(client, model, prompt, system=_SYSTEM, max_tokens=200)
            verdict, reason = _parse_verdict(_text_of(resp))
        except Exception:
            continue  # fail open — leave this finding as deterministic

        if verdict == "confirmed":
            f.confidence_tier = "confirmed"
            f.confidence = min(1.0, max(f.confidence, 0.9))
            if reason:
                f.metadata["model_confidence"] = f"confirmed: {reason}"
        elif verdict == "false_positive":
            # Deterministic result stands — only surface the model's doubt for a human.
            f.metadata["model_confidence"] = f"model flagged as possible false positive: {reason}"
        # "uncertain" -> leave tier as deterministic, no note
