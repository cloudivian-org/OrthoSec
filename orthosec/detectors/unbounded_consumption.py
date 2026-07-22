"""Detect unbounded resource consumption around LLM usage.

OWASP LLM10 (Unbounded Consumption) — a.k.a. denial-of-wallet / DoS.
An LLM call with no output cap, or an unbounded loop driving LLM/agent calls,
lets an attacker (or a runaway prompt) burn tokens without limit — cost blowout
and availability loss.
"""
from __future__ import annotations

import re
from typing import Iterable

from orthosec.core.finding import Finding, Severity
from orthosec.core.scanner import ScanContext
from orthosec.detectors import register
from orthosec.detectors._signals import strip_comments

# A model completion/generation call.
_LLM_CALL = re.compile(
    r"(?i)(chat\.completions\.create|responses\.create|messages\.create|"
    r"\.generate\s*\(|\.complete\s*\(|\.acreate\s*\(|\.chat\s*\()"
)
_HAS_CAP = re.compile(r"(?i)(max_tokens|max_output_tokens|maxtokens|max_completion_tokens)")
_LOOP = re.compile(r"^\s*while\s+True\s*:")
_LOOP_BOUND = re.compile(r"(?i)\b(break|max_iter|max_steps|max_turns|max_iterations|return)\b")


@register
class UnboundedConsumptionDetector:
    id = "unbounded-consumption"
    name = "Unbounded consumption / denial-of-wallet"
    owasp_llm = "LLM10"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.files:
            if path.suffix.lower() not in {".py", ".js", ".ts", ".tsx"}:
                continue
            raw = ctx.read(path)
            if not raw or not _LLM_CALL.search(raw):
                continue
            lines = strip_comments(raw).splitlines()
            raw_lines = raw.splitlines()

            for lineno, line in enumerate(lines, start=1):
                # 1. LLM call with no output cap in its argument span.
                if _LLM_CALL.search(line):
                    span = "\n".join(lines[lineno - 1:lineno + 8])
                    if not _HAS_CAP.search(span):
                        yield Finding(
                            detector=self.id,
                            rule_id="ORTHO-CONSUME-001",
                            title="LLM call without an output-token cap",
                            severity=Severity.MEDIUM,
                            owasp_llm="LLM10",
                            atlas=[],
                            file=ctx.rel(path),
                            line=lineno,
                            evidence=raw_lines[lineno - 1].strip()[:200],
                            remediation=(
                                "Set max_tokens (and a request timeout). Cap per-user/token "
                                "budgets and rate-limit to prevent denial-of-wallet."
                            ),
                            confidence=0.55,
                        )
                # 2. Unbounded loop driving LLM/agent calls with no exit bound.
                if _LOOP.search(line):
                    window = "\n".join(lines[lineno - 1:lineno + 20])
                    if _LLM_CALL.search(window) and not _LOOP_BOUND.search(window):
                        yield Finding(
                            detector=self.id,
                            rule_id="ORTHO-CONSUME-002",
                            title="Unbounded loop around LLM/agent calls (no exit bound)",
                            severity=Severity.MEDIUM,
                            owasp_llm="LLM10",
                            atlas=[],
                            file=ctx.rel(path),
                            line=lineno,
                            evidence=raw_lines[lineno - 1].strip()[:160],
                            remediation=(
                                "Bound the loop: max iterations/steps, a wall-clock deadline, and a "
                                "token budget. Fail closed when a limit is hit."
                            ),
                            confidence=0.5,
                        )
