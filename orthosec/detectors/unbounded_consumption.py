"""Detect unbounded resource consumption around LLM usage.

OWASP LLM10 (Unbounded Consumption) — a.k.a. denial-of-wallet / DoS.
An LLM call with no output cap, or an unbounded loop driving LLM/agent calls,
lets an attacker (or a runaway prompt) burn tokens without limit.

Python uses AST: only real calls to an LLM completion method count — a mock
assignment (`mock.messages.create = fn`), a string literal (`"responses.create"`),
or a docstring mention is not a call and is ignored. JS/TS uses regex.
"""
from __future__ import annotations

import ast
import re
from typing import Iterable

from orthosec.core.finding import Finding, Severity
from orthosec.core.scanner import ScanContext
from orthosec.detectors import register
from orthosec.detectors._signals import strip_comments
from orthosec.analysis.pyast import safe_parse, _seg, _chain

# LLM completion methods (with the object chain that disambiguates a plain .create).
_COMPLETION_CHAINS = {("completions", "create"), ("messages", "create"),
                      ("responses", "create")}
_COMPLETION_METHODS = {"generate", "acreate", "complete"}
_CAP_KEYS = {"max_tokens", "max_output_tokens", "maxtokens", "max_completion_tokens"}

# regex path (JS/TS)
_JS_CALL = re.compile(r"(?i)(chat\.completions\.create|responses\.create|messages\.create)\s*\(")
_JS_CAP = re.compile(r"(?i)(max_tokens|max_output_tokens|maxTokens)")

_CAP_FIX = ("Set max_tokens (and a request timeout). Cap per-user/token budgets and "
            "rate-limit to prevent denial-of-wallet.")
_LOOP_FIX = ("Bound the loop: max iterations/steps, a wall-clock deadline, and a token "
             "budget. Fail closed when a limit is hit.")


def _is_llm_completion(call: ast.Call) -> bool:
    if not isinstance(call.func, ast.Attribute):
        return False
    obj, meth = _chain(call.func)
    if (obj, meth) in _COMPLETION_CHAINS:
        return True
    return meth in _COMPLETION_METHODS and obj not in ("", "self")


def _is_explicit_chain(call: ast.Call) -> bool:
    """True for a direct provider call (chat.completions.create / messages.create /
    responses.create) where a per-call cap clearly matters; False for a bare
    llm.complete()/generate() where the cap is often on the client object."""
    return isinstance(call.func, ast.Attribute) and _chain(call.func) in _COMPLETION_CHAINS


def _has_cap(call: ast.Call) -> bool:
    return any(kw.arg in _CAP_KEYS for kw in call.keywords)


@register
class UnboundedConsumptionDetector:
    id = "unbounded-consumption"
    name = "Unbounded consumption / denial-of-wallet"
    owasp_llm = "LLM10"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.files:
            suffix = path.suffix.lower()
            text = ctx.read(path)
            if not text:
                continue
            if suffix in {".py", ".ipynb"}:
                yield from self._scan_python(ctx, path, text)
            elif suffix in {".js", ".ts", ".tsx"}:
                yield from self._scan_regex(ctx, path, text)

    def _scan_python(self, ctx, path, text) -> Iterable[Finding]:
        tree = safe_parse(text)
        if tree is None:
            return
        lines = text.splitlines()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _is_llm_completion(node) and not _has_cap(node):
                yield self._cap_finding(ctx, path, node.lineno, lines, _is_explicit_chain(node))
            elif isinstance(node, ast.While) and _is_true(node.test):
                calls = [n for n in ast.walk(node)
                         if isinstance(n, ast.Call) and _is_llm_completion(n)]
                has_break = any(isinstance(n, ast.Break) for n in ast.walk(node))
                has_return = any(isinstance(n, ast.Return) for n in ast.walk(node))
                if calls and not has_break and not has_return:
                    yield Finding(
                        detector=self.id, rule_id="ORTHO-CONSUME-002",
                        title="Unbounded loop around LLM/agent calls (no exit bound)",
                        severity=Severity.MEDIUM, owasp_llm="LLM10", atlas=[],
                        file=ctx.rel(path), line=node.lineno,
                        evidence=_snip(lines, node.lineno), remediation=_LOOP_FIX,
                        confidence=0.55,
                    )

    def _cap_finding(self, ctx, path, line, lines, explicit) -> Finding:
        note = "" if explicit else "  (per-call cap; may be set on the client)"
        return Finding(
            detector=self.id, rule_id="ORTHO-CONSUME-001",
            title="LLM call without an output-token cap" + note,
            severity=Severity.MEDIUM if explicit else Severity.LOW,
            owasp_llm="LLM10", atlas=[], file=ctx.rel(path), line=line,
            evidence=_snip(lines, line), remediation=_CAP_FIX,
            confidence=0.6 if explicit else 0.45,
        )

    def _scan_regex(self, ctx, path, text) -> Iterable[Finding]:
        lines = strip_comments(text).splitlines()
        raw = text.splitlines()
        for lineno, line in enumerate(lines, start=1):
            if _JS_CALL.search(line):
                window = "\n".join(lines[lineno - 1:lineno + 8])
                if not _JS_CAP.search(window):
                    yield Finding(
                        detector=self.id, rule_id="ORTHO-CONSUME-001",
                        title="LLM call without an output-token cap", severity=Severity.MEDIUM,
                        owasp_llm="LLM10", atlas=[], file=ctx.rel(path), line=lineno,
                        evidence=raw[lineno - 1].strip()[:200], remediation=_CAP_FIX,
                        confidence=0.55,
                    )


def _is_true(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _snip(lines, line):
    return lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""
