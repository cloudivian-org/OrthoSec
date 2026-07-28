"""Optional Semgrep engine — a deterministic complement to OrthoSec's own detectors.

Semgrep is a mature, fully deterministic static-analysis engine with a large rule
ecosystem. OrthoSec's built-in detectors focus on LLM dataflow (untrusted input →
prompt, model output → sink, tool reachability); Semgrep broadens coverage to general
code-security patterns (command injection, TLS bypass, auth mistakes, …) *without*
adding any probabilistic false-positive risk — the results are as deterministic as the
rules, mapped straight onto OrthoSec's findings, score, and report.

**Opt-in and zero-cost when off.** It runs only when `ORTHOSEC_SEMGREP` is truthy AND
the `semgrep` binary is installed (`pip install orthosec[semgrep]`); otherwise the
detector returns nothing and the scan is unchanged. Point `ORTHOSEC_SEMGREP_CONFIG` at
a bigger ruleset (`p/security-audit`, a path, …) to go beyond the bundled starter rules.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from orthosec.core.finding import Finding, Severity
from orthosec.detectors import register

_BUNDLED_RULES = Path(__file__).resolve().parent.parent / "rules" / "semgrep"

_SEV = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
# Coarse map of a Semgrep result to the nearest OWASP LLM category (best-effort — general
# security findings don't always map cleanly; unmatched ones are left uncategorized).
_OWASP_MAP = [
    (re.compile(r"(?i)(secret|api[_-]?key|password|credential|\btoken\b|jwt|auth)"), "LLM02"),
    (re.compile(r"(?i)(pickle|deserial|yaml\.?load|marshal|unsafe.?load|torch\.load)"), "LLM03"),
    (re.compile(r"(?i)(command.?inj|os\.system|subprocess|shell|sql|sqli|xss|template.?inj|"
                r"path.?travers|ssrf|eval|exec|verify=false|debug=true|tempfile|injection)"), "LLM05"),
]


def _enabled() -> bool:
    return (os.environ.get("ORTHOSEC_SEMGREP", "") or "").strip().lower() in ("1", "true", "yes", "on")


def _config() -> str:
    return os.environ.get("ORTHOSEC_SEMGREP_CONFIG") or str(_BUNDLED_RULES)


def _collect_results(ctx) -> list:
    """Run semgrep over the scan root and return its raw result dicts (empty on any issue)."""
    binp = shutil.which("semgrep")
    if binp is None:
        return []
    try:
        rule_timeout = str(int(float(os.environ.get("ORTHOSEC_SEMGREP_TIMEOUT", "60"))))
    except ValueError:
        rule_timeout = "60"
    cmd = [binp, "--json", "--quiet", "--disable-version-check", "--metrics=off",
           "--timeout", rule_timeout, "--config", _config(), str(ctx.root)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        if not proc.stdout:
            return []
        return (json.loads(proc.stdout) or {}).get("results", []) or []
    except Exception:
        return []


def _owasp_for(text: str) -> str:
    for pat, code in _OWASP_MAP:
        if pat.search(text):
            return code
    return ""


def _to_finding(ctx, r: dict) -> Finding | None:
    check = str(r.get("check_id") or "semgrep")
    extra = r.get("extra") or {}
    start = r.get("start") or {}
    meta = extra.get("metadata") or {}

    line = int(start.get("line") or 0)
    message = str(extra.get("message") or check).strip()
    severity = _SEV.get(str(extra.get("severity", "WARNING")).upper(), Severity.MEDIUM)
    evidence = (str(extra.get("lines") or "").strip() or message)[:200]

    owasp = str(meta.get("owasp") or "").strip()
    if not owasp.startswith("LLM"):
        owasp = _owasp_for(f"{check} {message} {json.dumps(meta)}")

    refs = meta.get("references") or []
    remediation = (str(meta.get("fix") or extra.get("fix") or "").strip()
                   or (f"See {refs[0]}" if refs else "Review and remediate per the Semgrep rule guidance."))

    p = Path(str(r.get("path") or ""))
    rel = ctx.rel(p) if p.parts else "?"

    title = message.split("\n")[0][:120]
    return Finding(
        detector="semgrep", rule_id=f"SEMGREP:{check.split('.')[-1][:60]}",
        title=title, severity=severity, owasp_llm=owasp, atlas=[],
        file=rel, line=line, evidence=evidence, remediation=remediation, confidence=0.75,
        metadata={"semgrep_check_id": check, "engine": "semgrep"},
    )


@register
class SemgrepDetector:
    id = "semgrep"
    name = "Semgrep static analysis (optional, deterministic)"
    owasp_llm = "LLM05"

    def scan(self, ctx) -> Iterable[Finding]:
        if not _enabled():
            return
        seen: set = set()
        for r in _collect_results(ctx):
            f = _to_finding(ctx, r)
            if f is None:
                continue
            key = (f.rule_id, f.file, f.line)
            if key in seen:
                continue
            seen.add(key)
            yield f
