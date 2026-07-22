"""Detect over-privileged agent tools / excessive agency.

OWASP LLM06 (Excessive Agency) / LLM05 (Improper Output Handling).
When an LLM can call a tool that runs a shell, writes files, or hits arbitrary
URLs — and there's no human confirmation — a single successful injection turns
into RCE, data exfiltration, or destructive action. This is the highest-blast-
radius class in agentic systems.
"""
from __future__ import annotations

import re
from typing import Iterable

from orthosec.core.finding import Finding, Severity
from orthosec.core.scanner import ScanContext
from orthosec.detectors import register
from orthosec.detectors._signals import mitigation_present

# Sinks that hand the model dangerous real-world capability.
_DANGEROUS = {
    "shell/command execution": re.compile(
        r"(?i)\b(os\.system|subprocess\.(run|call|Popen|check_output)|exec\(|eval\(|"
        r"child_process|shell\s*=\s*True)\b"
    ),
    "arbitrary file write/delete": re.compile(
        r"(?i)\b(open\([^)]*['\"][wa]['\"]|shutil\.rmtree|os\.remove|os\.unlink|"
        r"Path\([^)]*\)\.write_text|fs\.writeFile)\b"
    ),
    "arbitrary outbound HTTP": re.compile(
        r"(?i)\b(requests\.(get|post|put|delete)|httpx\.|urllib\.request|fetch\(|axios)\b"
    ),
    "raw SQL execution": re.compile(r"(?i)\b(cursor\.execute|\.raw\(|text\(|db\.execute)\b"),
}

# Markers that a function is exposed to the model as a callable tool.
_TOOL_MARKER = re.compile(
    r"(?i)(@tool\b|@function_tool|langchain.*Tool|StructuredTool|"
    r"['\"]function['\"]\s*:|['\"]tools['\"]\s*:|register_tool|mcp\.tool|FunctionDeclaration)"
)
# Markers that a human-in-the-loop / confirmation gate exists nearby.
_CONFIRM = re.compile(r"(?i)(confirm|approval|human_in_the_loop|require_approval|allowlist|whitelist)")


@register
class ToolExposureDetector:
    id = "tool-exposure"
    name = "Excessive agency / over-privileged tools"
    owasp_llm = "LLM06"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.files:
            if path.suffix.lower() not in {".py", ".js", ".ts", ".tsx"}:
                continue
            text = ctx.read(path)
            if not text or not _TOOL_MARKER.search(text):
                continue  # file must expose tools at all
            lines = text.splitlines()
            file_has_confirm = mitigation_present(text, _CONFIRM)

            for lineno, line in enumerate(lines, start=1):
                for capability, pat in _DANGEROUS.items():
                    if not pat.search(line):
                        continue
                    # Is this dangerous sink within ~15 lines of a tool marker?
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
                        remediation=(
                            "Scope the tool to the minimum capability, add an allowlist, and "
                            "gate irreversible/high-impact actions behind human confirmation. "
                            "Never pass model output unsanitized into shell/SQL/file sinks."
                        ),
                        confidence=0.55 if mitigated else 0.75,
                    )
