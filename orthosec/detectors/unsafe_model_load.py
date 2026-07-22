"""Detect unsafe model / artifact deserialization and supply-chain risk.

OWASP LLM03 (Supply Chain) / LLM04 (Data and Model Poisoning).
Loading a pickle-backed model (torch.load, joblib, pickle) or fetching weights
from an unpinned remote source executes arbitrary code at load time — the classic
'malicious model on the hub' supply-chain attack.
"""
from __future__ import annotations

import re
from typing import Iterable

from orthosec.core.finding import Finding, Severity
from orthosec.core.scanner import ScanContext
from orthosec.detectors import register

_UNSAFE_LOAD = {
    "pickle deserialization": re.compile(r"(?i)\b(pickle\.load|pickle\.loads|cPickle)\b"),
    "torch.load (pickle-backed)": re.compile(r"(?i)\btorch\.load\s*\("),
    "joblib.load": re.compile(r"(?i)\bjoblib\.load\s*\("),
    "yaml.load (unsafe)": re.compile(r"(?i)\byaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)"),
    "keras/h5 lambda layer": re.compile(r"(?i)\bLambda\s*\("),
}
# from_pretrained without trust boundary or revision pin is weaker but worth noting.
_UNPINNED_HUB = re.compile(r"(?i)from_pretrained\s*\(\s*['\"][^'\"]+['\"]\s*\)")
_SAFE_HINT = re.compile(r"(?i)(safetensors|weights_only\s*=\s*True|SafeLoader|revision\s*=)")


@register
class UnsafeModelLoadDetector:
    id = "unsafe-model-load"
    name = "Unsafe model / artifact deserialization"
    owasp_llm = "LLM03"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.files:
            if path.suffix.lower() not in {".py", ".ipynb"}:
                continue
            text = ctx.read(path)
            if not text:
                continue
            lines = text.splitlines()
            for lineno, line in enumerate(lines, start=1):
                for kind, pat in _UNSAFE_LOAD.items():
                    if not pat.search(line):
                        continue
                    window = "\n".join(lines[max(0, lineno - 2):lineno + 2])
                    if _SAFE_HINT.search(window):
                        continue
                    yield Finding(
                        detector=self.id,
                        rule_id="ORTHO-SUPPLY-001",
                        title=f"{kind} — code executes at load time",
                        severity=Severity.HIGH,
                        owasp_llm="LLM03",
                        atlas=["AML.T0010", "AML.T0018"],
                        file=ctx.rel(path),
                        line=lineno,
                        evidence=line.strip()[:200],
                        remediation=(
                            "Prefer safetensors; for torch use weights_only=True; for yaml use "
                            "SafeLoader. Only load artifacts from trusted, integrity-checked sources."
                        ),
                        confidence=0.7,
                    )
                if _UNPINNED_HUB.search(line) and not _SAFE_HINT.search(line):
                    yield Finding(
                        detector=self.id,
                        rule_id="ORTHO-SUPPLY-002",
                        title="Model pulled from hub without a pinned revision",
                        severity=Severity.LOW,
                        owasp_llm="LLM03",
                        atlas=["AML.T0010"],
                        file=ctx.rel(path),
                        line=lineno,
                        evidence=line.strip()[:200],
                        remediation="Pin revision=<commit-sha> so a repointed remote can't swap weights.",
                        confidence=0.5,
                    )
