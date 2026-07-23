"""Detect system-prompt leakage.

OWASP LLM07 (System Prompt Leakage).
The system prompt encodes instructions, guardrails, and sometimes secrets. Writing
it to logs or stdout exposes it — to anyone with log access, and to prompt-extraction
attacks if the same data is reflected. (Secrets *embedded* in a prompt are covered
separately by prompt-hardening `ORTHO-PI-002`.)

Python uses AST dataflow: a system-prompt-named value followed into a logging/print
call. JS/TS uses regex (console.log of a system-prompt-shaped variable).
"""
from __future__ import annotations

import re
from typing import Iterable

from orthosec.core.finding import Finding, Severity
from orthosec.core.scanner import ScanContext
from orthosec.detectors import register
from orthosec.detectors._signals import strip_comments
from orthosec.analysis.pyast import safe_parse, prompt_leak_sinks

_JS_SYS = re.compile(r"(?i)(system_?prompt|system_?message|system_?instruction)")
_JS_LOG = re.compile(r"(?i)(console\.(log|error|warn|info|debug)|logger\.\w+)\s*\(")

_FIX = ("Don't log or echo the system prompt. Redact it from logs; keep instructions "
        "and any embedded secrets server-side and out of any user-reachable output.")


@register
class PromptLeakageDetector:
    id = "prompt-leakage"
    name = "System prompt leakage"
    owasp_llm = "LLM07"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.files:
            suffix = path.suffix.lower()
            text = ctx.read(path)
            if not text:
                continue
            if suffix == ".py":
                yield from self._scan_python(ctx, path, text)
            elif suffix in {".js", ".ts", ".tsx"}:
                yield from self._scan_regex(ctx, path, text)

    def _scan_python(self, ctx, path, text) -> Iterable[Finding]:
        tree = safe_parse(text)
        if tree is None:
            return
        lines = text.splitlines()
        for s in prompt_leak_sinks(tree, lines):
            yield self._finding(ctx, path, s.line, s.snippet)

    def _scan_regex(self, ctx, path, text) -> Iterable[Finding]:
        lines = strip_comments(text).splitlines()
        raw = text.splitlines()
        for lineno, line in enumerate(lines, start=1):
            if _JS_LOG.search(line) and _JS_SYS.search(line):
                yield self._finding(ctx, path, lineno, raw[lineno - 1].strip()[:200])

    def _finding(self, ctx, path, line, evidence) -> Finding:
        return Finding(
            detector=self.id, rule_id="ORTHO-PROMPTLEAK-001",
            title="System prompt written to logs / stdout (leakage)",
            severity=Severity.MEDIUM, owasp_llm="LLM07", atlas=["AML.T0051.001"],
            file=ctx.rel(path), line=line, evidence=evidence,
            remediation=_FIX, confidence=0.6)
