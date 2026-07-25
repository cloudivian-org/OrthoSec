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
_ROLE_ANY = re.compile(r"""(?i)['"]role['"]\s*:\s*['"](\w+)['"]""")
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


def _enclosing_role(lines, lineno):
    """Role of the message dict a line sits in, by scanning backward to the nearest
    `"role": "<x>"` marker within a small window. Returns the role string, or None
    if no nearby role marker (not inside a chat-message dict)."""
    for i in range(lineno - 1, max(0, lineno - 8) - 1, -1):
        m = _ROLE_ANY.search(lines[i])
        if m:
            return m.group(1).lower()
    return None
# Log / print / exception lines interpolate user input for diagnostics, not into a
# prompt — the regex fallback must not read them as prompt injection (AST already skips).
_LOG_LINE = re.compile(
    r"(?i)(^|[^\w.])(logger|logging|log|print|console|warnings?|traceback|"
    r"sys\.std(out|err)|pprint)\s*\.?\s*\w*\s*\(")

# LLM01 via tree-sitter: file suffix -> analyzer module exposing injection_findings().
_JS_FAMILY = {".ts", ".tsx", ".jsx", ".js"}
_TS_LANG = {".ts": "ts_ast", ".tsx": "ts_ast", ".jsx": "ts_ast", ".js": "ts_ast",
            ".go": "go_ast", ".java": "java_ast", ".kt": "kotlin_ast",
            ".cs": "csharp_ast", ".rb": "ruby_ast", ".php": "php_ast"}

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
            elif suffix in _TS_LANG:
                yield from self._scan_treesitter(ctx, path, text)
            elif suffix in {".prompt", ".yaml", ".yml", ".json"}:
                # .md/.txt excluded: docs/data files produce prompt-ish false positives.
                yield from self._scan_regex(ctx, path, text)

    def _scan_treesitter(self, ctx, path, text) -> Iterable[Finding]:
        """LLM01 (untrusted input -> system prompt) via the per-language tree-sitter AST,
        with regex fallback for JS-family when the grammar / analyzer isn't available."""
        suffix = path.suffix.lower()
        import importlib
        mod = importlib.import_module(f"orthosec.analysis.{_TS_LANG[suffix]}")
        inj = getattr(mod, "injection_findings", None)
        if inj is not None and mod.available():
            # Only ts_ast distinguishes tsx; others take (text) only.
            hits = inj(text, tsx=suffix in (".tsx", ".jsx", ".js")) if suffix in _JS_FAMILY else inj(text)
            if hits is not None:
                raw = text.splitlines()
                for ln, _cap in hits:
                    yield Finding(
                        detector=self.id, rule_id="ORTHO-PI-001",
                        title="Untrusted input reaches a system prompt without a trust boundary",
                        severity=Severity.HIGH, owasp_llm="LLM01",
                        atlas=["AML.T0051", "AML.T0051.000"],
                        file=ctx.rel(path), line=ln,
                        evidence=raw[ln - 1].strip()[:200] if 0 < ln <= len(raw) else "",
                        remediation=_PI001_FIX, confidence=0.7)
                return
        if suffix in _JS_FAMILY:            # regex fallback only makes sense for JS-ish syntax
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
                metadata={"trace": s.trace} if s.trace else {},
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
                # A log/print or a raised-exception message interpolating user input is a
                # diagnostic string, not a prompt.
                if _LOG_LINE.search(line) or line.lstrip().startswith("raise "):
                    continue
                # Untrusted input inside a `"role": "user"` message is expected — the
                # injection risk is untrusted -> SYSTEM prompt. Skip when the nearest
                # enclosing role marker is non-system (the AST path already does this;
                # this keeps the regex fallback from firing on user-message f-strings).
                if _enclosing_role(lines, lineno) not in (None, "system"):
                    continue
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
