"""Detect improper handling of LLM output flowing into dangerous sinks.

OWASP LLM05 (Improper Output Handling).
When model output is passed unsanitized into eval/exec, a shell, raw SQL, or
rendered as HTML, a successful prompt injection escalates into RCE, SQLi, or XSS
in the *downstream* system — the model becomes a confused deputy.
"""
from __future__ import annotations

import re
from typing import Iterable

from orthosec.core.finding import Finding, Severity
from orthosec.core.scanner import ScanContext
from orthosec.detectors import register
from orthosec.detectors._signals import mitigation_present, strip_comments

# Variable names that commonly hold raw model output.
_LLM_OUTPUT = re.compile(
    r"(?i)\b(\w*(?:llm|model|completion|response|answer|reply|generated|assistant)\w*"
    r"|message\.content|choices\[0\]|resp\.content|output_text)\b"
)
# Dangerous sinks that must not receive unsanitized model output.
_SINKS = {
    "code execution (eval/exec)": re.compile(r"(?i)\b(eval|exec)\s*\("),
    "shell execution": re.compile(r"(?i)\b(os\.system|subprocess\.(run|call|Popen)|shell\s*=\s*True)\b"),
    "raw SQL": re.compile(r"(?i)\b(execute|executemany|cursor\.execute|\.raw)\s*\("),
    "HTML injection (XSS)": re.compile(r"(?i)(innerHTML|dangerouslySetInnerHTML|render_template_string|\|\s*safe\b)"),
    "template render": re.compile(r"(?i)\b(Template|render_template_string)\s*\("),
}
# Signals the output was validated/escaped before the sink.
_SANITIZED = re.compile(
    r"(?i)(sanitiz|escape|bleach|validate|allowlist|whitelist|parameteriz|json\.loads|pydantic|schema)"
)


@register
class OutputHandlingDetector:
    id = "output-handling"
    name = "Improper LLM output handling"
    owasp_llm = "LLM05"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.files:
            if path.suffix.lower() not in {".py", ".js", ".ts", ".tsx", ".jsx"}:
                continue
            text = ctx.read(path)
            if not text:
                continue
            # Behavior detector: match on code only — a sink or output var named in a
            # comment is not a real dataflow. (Secrets detection still scans comments.)
            lines = strip_comments(text).splitlines()
            raw_lines = text.splitlines()
            for lineno, line in enumerate(lines, start=1):
                for sink_name, pat in _SINKS.items():
                    if not pat.search(line):
                        continue
                    # Model output on the same line, or defined within ~5 lines above.
                    window = "\n".join(lines[max(0, lineno - 6):lineno + 1])
                    if not _LLM_OUTPUT.search(window):
                        continue
                    if mitigation_present(window, _SANITIZED):
                        continue  # validated/escaped in code (not merely named in a comment)
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
                        remediation=(
                            "Treat model output as untrusted input to the downstream system. "
                            "Validate against a schema, escape/parameterize before the sink, and "
                            "never eval/exec or string-concatenate it into SQL/HTML/shell."
                        ),
                        confidence=0.6,
                    )
