"""Detect over-privileged agent tools / excessive agency.

OWASP LLM06 (Excessive Agency) / LLM05 (Improper Output Handling).
When an LLM can call a tool that runs a shell, writes files, or hits arbitrary
URLs — with no human confirmation — a single successful injection turns into RCE,
data exfiltration, or destructive action. Highest blast radius in agentic systems.

Python uses AST: it resolves which functions are model-invokable tools and finds
dangerous sinks inside them at any line distance (precise, no distance heuristic).
JS/TS falls back to a proximity regex.
"""
from __future__ import annotations

import re
from typing import Iterable

from orthosec.core.finding import Finding, Severity
from orthosec.core.scanner import ScanContext
from orthosec.detectors import register
from orthosec.detectors._signals import mitigation_present
from orthosec.analysis.pyast import (safe_parse, find_tool_functions,
                                     dangerous_sinks, has_confirmation)

# --- regex path (JS/TS) -----------------------------------------------------
_DANGEROUS = {
    "shell/command execution": re.compile(
        r"(?i)\b(child_process|exec\(|execSync|spawn\()"),
    "arbitrary file write/delete": re.compile(
        r"(?i)\b(fs\.writeFile|fs\.unlink|fs\.rm)\b"),
    "arbitrary outbound HTTP": re.compile(r"(?i)\b(fetch\(|axios)\b"),
}
_TOOL_MARKER = re.compile(
    r"(?i)(@tool\b|@function_tool|StructuredTool|['\"]function['\"]\s*:|"
    r"['\"]tools['\"]\s*:|register_tool|mcp\.tool|FunctionDeclaration|new\s+\w*Tool)")
_CONFIRM = re.compile(r"(?i)(confirm|approval|human_in_the_loop|require_approval|allowlist|whitelist)")

_REMEDIATION = (
    "Scope the tool to the minimum capability, add an allowlist, and gate "
    "irreversible/high-impact actions behind human confirmation. Never pass model "
    "output unsanitized into shell/SQL/file sinks."
)


@register
class ToolExposureDetector:
    id = "tool-exposure"
    name = "Excessive agency / over-privileged tools"
    owasp_llm = "LLM06"

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

    # --- Python: AST dataflow -------------------------------------------
    def _scan_python(self, ctx, path, text) -> Iterable[Finding]:
        tree = safe_parse(text)
        if tree is None:
            yield from self._scan_regex(ctx, path, text)  # fallback on syntax error
            return
        tool_fns = find_tool_functions(tree)
        lines = text.splitlines()
        for name, fn in tool_fns.items():
            sinks = dangerous_sinks(fn, lines)
            if not sinks:
                continue
            mitigated = has_confirmation(fn)
            for s in sinks:
                yield Finding(
                    detector=self.id,
                    rule_id="ORTHO-AGENCY-001",
                    title=f"Model-invokable tool '{name}' performs {s.capability} with no confirmation gate",
                    severity=Severity.MEDIUM if mitigated else Severity.CRITICAL,
                    owasp_llm="LLM06",
                    atlas=["AML.T0053"],
                    file=ctx.rel(path),
                    line=s.line,
                    evidence=s.snippet,
                    remediation=_REMEDIATION,
                    confidence=0.6 if mitigated else 0.85,
                )

    # --- JS/TS: proximity regex -----------------------------------------
    def _scan_regex(self, ctx, path, text) -> Iterable[Finding]:
        if not _TOOL_MARKER.search(text):
            return
        lines = text.splitlines()
        file_has_confirm = mitigation_present(text, _CONFIRM)
        for lineno, line in enumerate(lines, start=1):
            for capability, pat in _DANGEROUS.items():
                if not pat.search(line):
                    continue
                window = "\n".join(lines[max(0, lineno - 15):lineno + 5])
                if not _TOOL_MARKER.search(window):
                    continue
                mitigated = file_has_confirm and mitigation_present(window, _CONFIRM)
                yield Finding(
                    detector=self.id,
                    rule_id="ORTHO-AGENCY-001",
                    title=f"Model-invokable tool with {capability} and no confirmation gate",
                    severity=Severity.MEDIUM if mitigated else Severity.CRITICAL,
                    owasp_llm="LLM06",
                    atlas=["AML.T0053"],
                    file=ctx.rel(path),
                    line=lineno,
                    evidence=line.strip()[:200],
                    remediation=_REMEDIATION,
                    confidence=0.55 if mitigated else 0.75,
                )
