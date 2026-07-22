"""Analyze system prompts for missing injection defenses.

OWASP LLM01 (Prompt Injection) / LLM07 (System Prompt Leakage).
A system prompt that embeds untrusted input with no trust boundary is the primary
injection surface of an LLM app; a secret baked into a prompt leaks under a
prompt-extraction attack.

Python uses AST taint: it traces untrusted input (user params, input(), request.*)
into a system-prompt construction, respecting nearby trust-boundary language. Other
file types (.txt/.md/.prompt/.js/.yaml/...) use regex.
"""
from __future__ import annotations

import re
from typing import Iterable

from orthosec.core.finding import Finding, Severity
from orthosec.core.scanner import ScanContext
from orthosec.detectors import register
from orthosec.analysis.pyast import (safe_parse, injection_sinks,
                                     interprocedural_injection_sinks)
from orthosec.analysis.project import cross_file_injection_sinks

# System-prompt shape + unsanitized-concat + hardening (regex path for non-Python).
_SYS_ASSIGN = re.compile(r"(?i)(system_prompt|system_message|system_instruction|SYSTEM_PROMPT)\s*[:=]")
_ROLE_SYSTEM = re.compile(r"""(?i)['"]role['"]\s*:\s*['"]system['"]""")
_CONCAT_INJECTION = re.compile(
    r"""(?xi)
    (f['"].*\{[^}]*(user|input|query|question|message|content|request)[^}]*\}.*['"]) |
    (['"].*['"]\s*\+\s*\w*(user|input|query|question|message|request)\w*) |
    (\.format\([^)]*(user|input|query|message)) |
    (%\s*\([^)]*(user|input|query)[^)]*\))
    """)
_HARDENING = re.compile(
    r"(?i)(untrusted|do not follow|ignore any instructions|delimited by|<user_input>|"
    r"treat .* as data|never reveal|do not disclose your (system )?prompt)")
_SECRET_IN_PROMPT = re.compile(r"(?i)(api[_-]?key|password|secret|token)\s*[:=]\s*\S")

_PI001_FIX = (
    "Separate instructions from data: place user input inside explicit delimiters, "
    "instruct the model to treat it as data, and add an output/instruction-override guard.")


@register
class PromptHardeningDetector:
    id = "prompt-hardening"
    name = "System prompt injection surface"
    owasp_llm = "LLM01"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.files:
            suffix = path.suffix.lower()
            text = ctx.read(path)
            if not text:
                continue
            if suffix == ".py":
                yield from self._scan_python(ctx, path, text)
            elif suffix in {".js", ".ts", ".prompt", ".yaml", ".yml", ".json"}:
                # .md/.txt excluded: docs/data files produce prompt-ish false positives.
                yield from self._scan_regex(ctx, path, text)

    def _scan_python(self, ctx, path, text) -> Iterable[Finding]:
        tree = safe_parse(text)
        if tree is None:
            yield from self._scan_regex(ctx, path, text)
            return
        lines = text.splitlines()
        seen_lines: set[int] = set()
        found = (injection_sinks(tree, lines)
                 + interprocedural_injection_sinks(tree, lines)
                 + cross_file_injection_sinks(ctx, path, tree, lines))
        for s in found:
            if s.line in seen_lines:
                continue
            seen_lines.add(s.line)
            yield Finding(
                detector=self.id, rule_id="ORTHO-PI-001",
                title="Untrusted input reaches a system prompt without a trust boundary",
                severity=Severity.HIGH, owasp_llm="LLM01",
                atlas=["AML.T0051", "AML.T0051.000"],
                file=ctx.rel(path), line=s.line, evidence=s.snippet,
                remediation=_PI001_FIX, confidence=0.7,
            )
        # Secret embedded in a system prompt — kept as a lexical check.
        yield from self._secret_in_prompt(ctx, path, lines)

    def _scan_regex(self, ctx, path, text) -> Iterable[Finding]:
        lines = text.splitlines()
        has_prompt = any(_SYS_ASSIGN.search(l) or _ROLE_SYSTEM.search(l) for l in lines)
        if not has_prompt and path.suffix.lower() not in {".prompt", ".txt", ".md"}:
            return
        for lineno, line in enumerate(lines, start=1):
            if _CONCAT_INJECTION.search(line):
                window = "\n".join(lines[max(0, lineno - 4):lineno + 3])
                if _HARDENING.search(window):
                    continue
                yield Finding(
                    detector=self.id, rule_id="ORTHO-PI-001",
                    title="Untrusted input concatenated into prompt without trust boundary",
                    severity=Severity.HIGH, owasp_llm="LLM01",
                    atlas=["AML.T0051", "AML.T0051.000"],
                    file=ctx.rel(path), line=lineno, evidence=line.strip()[:200],
                    remediation=_PI001_FIX, confidence=0.65,
                )
        yield from self._secret_in_prompt(ctx, path, lines)

    def _secret_in_prompt(self, ctx, path, lines) -> Iterable[Finding]:
        for lineno, line in enumerate(lines, start=1):
            if (_SYS_ASSIGN.search(line) or _ROLE_SYSTEM.search(line)) and _SECRET_IN_PROMPT.search(line):
                yield Finding(
                    detector=self.id, rule_id="ORTHO-PI-002",
                    title="Secret embedded inside a system prompt",
                    severity=Severity.HIGH, owasp_llm="LLM07",
                    atlas=["AML.T0051.001"],
                    file=ctx.rel(path), line=lineno, evidence=line.strip()[:160],
                    remediation=("Never put credentials in a prompt — prompt-leak attacks will "
                                 "extract them. Inject secrets at the tool/API layer instead."),
                    confidence=0.7,
                )
