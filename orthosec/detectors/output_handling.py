"""Detect improper handling of LLM output flowing into dangerous sinks.

OWASP LLM05 (Improper Output Handling).
When model output is passed unsanitized into eval/exec, a shell, raw SQL, or a
template/HTML sink, a successful prompt injection escalates into RCE, SQLi, or XSS
in the *downstream* system — the model becomes a confused deputy.

Python uses AST taint tracking: model output is followed through reassignments
and attribute chains, and a finding fires only when the sink's actual argument is
tainted (not merely when an output-named variable sits nearby). JS/TS uses regex.
"""
from __future__ import annotations

import re
from typing import Iterable

from orthosec.core.finding import Finding, Severity
from orthosec.core.scanner import ScanContext
from orthosec.detectors import register
from orthosec.detectors._signals import mitigation_present, strip_comments
from orthosec.analysis.pyast import (safe_parse, output_taint_sinks,
                                     interprocedural_output_sinks)
from orthosec.analysis.project import cross_file_output_sinks

_REMEDIATION = (
    "Treat model output as untrusted input to the downstream system. Validate "
    "against a schema, escape/parameterize before the sink, and never eval/exec "
    "or string-concatenate it into SQL/HTML/shell."
)

# --- regex path (JS/TS) -----------------------------------------------------
_LLM_OUTPUT = re.compile(
    r"(?i)\b(\w*(?:llm|model|completion|response|answer|reply|generated|assistant)\w*"
    r"|message\.content|choices\[0\]|resp\.content|output_text)\b")
_SINKS = {
    "code execution (eval/exec)": re.compile(r"(?i)\b(eval|exec)\s*\("),
    "shell execution": re.compile(r"(?i)\b(child_process|execSync|spawn\()"),
    # Require a write to innerHTML (assignment), not a read like `.innerHTML).toBe(...)`.
    "HTML injection (XSS)": re.compile(r"(?i)(innerHTML\s*=|dangerouslySetInnerHTML)"),
}
_SANITIZED = re.compile(r"(?i)(sanitiz|escape|bleach|validate|allowlist|whitelist|JSON\.parse)")


@register
class OutputHandlingDetector:
    id = "output-handling"
    name = "Improper LLM output handling"
    owasp_llm = "LLM05"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.files:
            suffix = path.suffix.lower()
            text = ctx.read(path)
            if not text:
                continue
            if suffix == ".py":
                yield from self._scan_python(ctx, path, text)
            elif suffix in {".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt"}:
                yield from self._scan_regex(ctx, path, text)

    def _scan_python(self, ctx, path, text) -> Iterable[Finding]:
        tree = safe_parse(text)
        if tree is None:
            return
        lines = text.splitlines()
        seen_lines: set[int] = set()
        found = (output_taint_sinks(tree, lines)
                 + interprocedural_output_sinks(tree, lines)
                 + cross_file_output_sinks(ctx, path, tree, lines))
        for s in found:
            if s.line in seen_lines:
                continue
            seen_lines.add(s.line)
            yield Finding(
                detector=self.id,
                rule_id="ORTHO-OUTPUT-001",
                title=f"LLM output flows into {s.capability} without sanitization",
                severity=Severity.HIGH,
                owasp_llm="LLM05",
                atlas=["AML.T0051"],
                file=ctx.rel(path),
                line=s.line,
                evidence=s.snippet,
                remediation=_REMEDIATION,
                confidence=0.8,
                metadata={"trace": s.trace} if s.trace else {},
            )

    def _scan_regex(self, ctx, path, text) -> Iterable[Finding]:
        raw_lines = text.splitlines()
        suffix = path.suffix.lower()

        def _emit(ln, cap, conf):
            return Finding(
                detector=self.id, rule_id="ORTHO-OUTPUT-001",
                title=f"LLM output flows into {cap} without sanitization",
                severity=Severity.HIGH, owasp_llm="LLM05", atlas=["AML.T0051"],
                file=ctx.rel(path), line=ln,
                evidence=raw_lines[ln - 1].strip()[:200] if 0 < ln <= len(raw_lines) else "",
                remediation=_REMEDIATION, confidence=conf)

        # Go / Java AST via tree-sitter.
        if suffix == ".go":
            from orthosec.analysis import go_ast
            if go_ast.available():
                hits = go_ast.output_findings(text)
                if hits is not None:
                    for ln, cap in hits:
                        yield _emit(ln, cap, 0.78)
            return
        if suffix == ".java":
            from orthosec.analysis import java_ast
            if java_ast.available():
                hits = java_ast.output_findings(text)
                if hits is not None:
                    for ln, cap in hits:
                        yield _emit(ln, cap, 0.78)
            return
        if suffix == ".kt":
            from orthosec.analysis import kotlin_ast
            if kotlin_ast.available():
                hits = kotlin_ast.output_findings(text)
                if hits is not None:
                    for ln, cap in hits:
                        yield _emit(ln, cap, 0.78)
            return

        # TypeScript/JSX (and JS) AST via tree-sitter — primary, most precise path.
        from orthosec.analysis import ts_ast
        if ts_ast.available() and suffix in (".ts", ".tsx", ".jsx", ".js"):
            hits = ts_ast.output_findings(text, tsx=suffix in (".tsx", ".jsx", ".js"))
            if hits is not None:
                for ln, cap in hits:
                    yield _emit(ln, cap, 0.78)
                return

        if suffix == ".js":
            from orthosec.analysis import js_ast
            if js_ast.available():
                hits = js_ast.output_findings(text)
                if hits is not None:                 # parsed as JS — use AST taint
                    for ln, cap in hits:
                        yield _emit(ln, cap, 0.75)
                    return
        lines = strip_comments(text).splitlines()
        for lineno, line in enumerate(lines, start=1):
            for sink_name, pat in _SINKS.items():
                if not pat.search(line):
                    continue
                window = "\n".join(lines[max(0, lineno - 6):lineno + 1])
                if not _LLM_OUTPUT.search(window):
                    continue
                if mitigation_present(window, _SANITIZED):
                    continue
                yield Finding(
                    detector=self.id,
                    rule_id="ORTHO-OUTPUT-001",
                    title=f"LLM output flows into {sink_name} without sanitization",
                    severity=Severity.HIGH,
                    owasp_llm="LLM05",
                    atlas=["AML.T0051"],
                    file=ctx.rel(path),
                    line=lineno,
                    evidence=raw_lines[lineno - 1].strip()[:200],
                    remediation=_REMEDIATION,
                    confidence=0.6,
                )
