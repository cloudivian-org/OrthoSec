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

# Generic path for languages without a tree-sitter unbounded analyzer (Java/Kotlin/C#/
# Ruby/PHP/Rust). SDK method chains differ per language, so each has its own tight
# completion-call pattern (the official OpenAI/Anthropic SDK spelling for that language)
# and cap-keyword set. A cap anywhere in the call's forward window suppresses the finding.
_LLM10_BY_SUFFIX = {
    # OpenAI: client.chat().completions().create(...) · Anthropic: client.messages().create(...)
    ".java": (re.compile(r"\.(completions|messages)\(\)\s*\.\s*create\s*\("),
              re.compile(r"(?i)(max_?tokens|max_?output_?tokens|max_?completion_?tokens)")),
    ".kt": (re.compile(r"\.(completions|messages)\(\)\s*\.\s*create\s*\("),
            re.compile(r"(?i)(max_?tokens|max_?output_?tokens|max_?completion_?tokens)")),
    # OpenAI: chatClient.CompleteChat(...) · Anthropic.SDK: client.Messages.Create(...)
    ".cs": (re.compile(r"(\.CompleteChat(Async)?\s*\(|\.Messages\.Create\s*\()"),
            re.compile(r"(?i)(max_?tokens|maxoutputtokencount|max_?output_?tokens|max_?completion_?tokens)")),
    # ruby-openai: client.chat(parameters: {...}) · anthropic: client.messages.create(...)
    ".rb": (re.compile(r"(\.chat\(\s*parameters|\.messages\.create\s*\()"),
            re.compile(r"(?i)max_tokens")),
    # openai-php: $client->chat()->create([...]) · ->messages()->create([...])
    ".php": (re.compile(r"->\s*(chat|messages)\(\)\s*->\s*create\s*\("),
             re.compile(r"(?i)max_tokens")),
    # async-openai / anthropic-sdk: client.chat().create(req) · client.messages().create(req)
    ".rs": (re.compile(r"\.(chat|messages)\(\)\s*\.\s*create\s*\("),
            re.compile(r"(?i)max_tokens")),
}
_GENERIC_SUFFIXES = set(_LLM10_BY_SUFFIX)

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
        from orthosec.detectors._signals import is_test_path
        for path in ctx.iter_files():
            suffix = path.suffix.lower()
            text = ctx.read(path)
            if not text:
                continue
            if suffix in {".py", ".ipynb"}:
                gen = self._scan_python(ctx, path, text)
            elif suffix in {".js", ".ts", ".tsx", ".jsx", ".go"}:
                gen = self._scan_regex(ctx, path, text)
            elif suffix in _GENERIC_SUFFIXES:
                gen = self._scan_generic(ctx, path, text)
            else:
                continue
            # An uncapped LLM call in test/example code is not a production denial-of-wallet
            # risk — downgrade to INFO so it stays visible but out of the gate, the score,
            # and the noise. (Found by the random-sample harness: LLM10 dominated, in tests.)
            in_test = is_test_path(ctx.rel(path)) or is_test_path(path.name)
            for f in gen:
                if in_test:
                    f.severity = Severity.INFO
                    f.metadata = {**(f.metadata or {}),
                                  "note": "test/example code — not a production consumption risk"}
                yield f

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

    def _scan_generic(self, ctx, path, text) -> Iterable[Finding]:
        """Java/Kotlin/C#/Ruby/PHP/Rust: an SDK completion call with no output cap in its
        argument window. Comments stripped so a commented-out call or a `// max_tokens`
        note doesn't skew the result."""
        call_re, cap_re = _LLM10_BY_SUFFIX[path.suffix.lower()]
        raw = text.splitlines()
        lines = strip_comments(text).splitlines()
        for lineno, line in enumerate(lines, start=1):
            if call_re.search(line):
                # Bidirectional window: builders set the cap ABOVE the call as often as
                # inline. Prefer a miss over a false positive — if a cap is anywhere near,
                # assume it applies.
                window = "\n".join(lines[max(0, lineno - 9):lineno + 8])
                if not cap_re.search(window):
                    yield Finding(
                        detector=self.id, rule_id="ORTHO-CONSUME-001",
                        title="LLM call without an output-token cap", severity=Severity.MEDIUM,
                        owasp_llm="LLM10", atlas=[], file=ctx.rel(path), line=lineno,
                        evidence=raw[lineno - 1].strip()[:200] if 0 < lineno <= len(raw) else "",
                        remediation=_CAP_FIX, confidence=0.55,
                    )

    def _scan_regex(self, ctx, path, text) -> Iterable[Finding]:
        raw = text.splitlines()
        suffix = path.suffix.lower()

        def _emit(ln, conf):
            return Finding(
                detector=self.id, rule_id="ORTHO-CONSUME-001",
                title="LLM call without an output-token cap", severity=Severity.MEDIUM,
                owasp_llm="LLM10", atlas=[], file=ctx.rel(path), line=ln,
                evidence=_snip(raw, ln), remediation=_CAP_FIX, confidence=conf)

        # Go AST via tree-sitter.
        if suffix == ".go":
            from orthosec.analysis import go_ast
            if go_ast.available():
                hits = go_ast.unbounded_findings(text)
                if hits is not None:
                    for ln in hits:
                        yield _emit(ln, 0.68)
            return

        # TypeScript/JSX (and JS) AST via tree-sitter — primary path.
        from orthosec.analysis import ts_ast
        if ts_ast.available() and suffix in (".ts", ".tsx", ".jsx", ".js"):
            hits = ts_ast.unbounded_findings(text, tsx=suffix in (".tsx", ".jsx", ".js"))
            if hits is not None:
                for ln in hits:
                    yield _emit(ln, 0.68)
                return

        if suffix == ".js":
            from orthosec.analysis import js_ast
            if js_ast.available():
                hits = js_ast.unbounded_findings(text)
                if hits is not None:                 # parsed as JS — use AST, not regex
                    for ln in hits:
                        yield _emit(ln, 0.65)
                    return
        lines = strip_comments(text).splitlines()
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
