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


# --------------------------------------------------------------------------- #
# Model-led DISCOVERY — surface additional candidate findings the deterministic
# engine missed. These are ALWAYS advisory: clearly labelled, excluded from the
# posture score and the --fail-on gate, and deduped against deterministic findings.
# The deterministic set is never touched. Opt-in, capped, fail-open.
# --------------------------------------------------------------------------- #

_CODE_EXT = {".py", ".ts", ".tsx", ".jsx", ".js", ".go", ".java", ".kt", ".cs", ".rb", ".php", ".rs"}
_SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", "__pycache__", ".venv", "venv"}

_DISCOVER_SYSTEM = (
    "You are a security reviewer. Find real, code-grounded security vulnerabilities in the "
    "file below that a pattern-based static analyzer might MISS (logic flaws, auth/authz "
    "gaps, unsafe data flows, injection, SSRF, insecure crypto, secrets). Do not invent "
    "issues. Return ONLY a JSON array; each item: "
    '{"title": "...", "line": <int>, "severity": "critical|high|medium|low", '
    '"owasp": "LLM0X or empty", "evidence": "the offending code", "fix": "one sentence"}. '
    "Return [] if there is nothing real."
)


def discover_enabled() -> bool:
    return (os.environ.get("ORTHOSEC_DISCOVER", "") or "").strip().lower() in ("1", "true", "yes", "on")


def _discover_max_files() -> int:
    try:
        return int(os.environ.get("ORTHOSEC_DISCOVER_MAX_FILES", "8"))
    except ValueError:
        return 8


def _code_files(root: str, limit: int):
    picked = []
    for dp, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            if Path(fn).suffix.lower() in _CODE_EXT:
                p = Path(dp) / fn
                try:
                    if 0 < p.stat().st_size <= 24_000:      # skip empty / very large files
                        picked.append(p)
                except OSError:
                    pass
    picked.sort(key=lambda p: p.stat().st_size)             # cheapest first, deterministic order
    return picked[:limit]


def _sev(name: str):
    from orthosec.core.finding import Severity
    return {"critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "low": Severity.LOW}.get(str(name).strip().lower(), Severity.MEDIUM)


def _near_existing(existing_by_file, relpath, line) -> bool:
    for ln in existing_by_file.get(relpath, ()):
        if abs(ln - line) <= 2:                             # already covered deterministically
            return True
    return False


def discover(root: str, existing) -> list:
    """Return advisory (model-discovered) Findings not already covered deterministically.
    No-op when disabled or no model backend. Never raises (fails open)."""
    if not discover_enabled():
        return []
    try:
        from orthosec.intel.narrative import _resolve_client_and_model, _call, _text_of
        from orthosec.core.finding import Finding
        client, model = _resolve_client_and_model()
    except Exception:
        return []
    if client is None:
        return []

    existing_by_file: dict = {}
    for f in existing:
        existing_by_file.setdefault(f.file, set()).add(f.line)

    out = []
    rootp = Path(root)
    for p in _code_files(root, _discover_max_files()):
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
            rel = str(p.relative_to(rootp)) if rootp in p.parents or p == rootp else p.name
            prompt = f"FILE: {rel}\n```\n{src[:12000]}\n```\n"
            resp = _call(client, model, prompt, system=_DISCOVER_SYSTEM, max_tokens=1200)
            items = _parse_items(_text_of(resp))
        except Exception:
            continue                                        # fail open per file
        for it in items:
            if not isinstance(it, dict):
                continue
            try:
                line = int(it.get("line") or 0)
            except (TypeError, ValueError):
                line = 0
            if _near_existing(existing_by_file, rel, line):
                continue
            title = str(it.get("title") or "").strip()[:120]
            if not title:
                continue
            out.append(Finding(
                detector="model-discovery", rule_id="MODEL-DISC-001",
                title=title, severity=_sev(it.get("severity")),
                owasp_llm=str(it.get("owasp") or "").strip(), atlas=[],
                file=rel, line=line, evidence=str(it.get("evidence") or "").strip()[:200],
                remediation=str(it.get("fix") or "Review this candidate issue.").strip()[:300],
                confidence=0.5, confidence_tier="advisory",
                metadata={"engine": "model-discovery", "model": model},
            ))
    return out


def _parse_items(text: str) -> list:
    try:
        start, end = text.index("["), text.rindex("]") + 1
        obj = json.loads(text[start:end])
        return obj if isinstance(obj, list) else []
    except (ValueError, json.JSONDecodeError):
        return []
