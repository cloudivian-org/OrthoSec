"""Analyze system prompts for missing injection defenses.

OWASP LLM01 (Prompt Injection) / LLM07 (System Prompt Leakage).
A system prompt that concatenates untrusted input, carries no trust boundary, or
embeds secrets is the primary injection surface of an LLM app.
"""
from __future__ import annotations

import re
from typing import Iterable

from orthosec.core.finding import Finding, Severity
from orthosec.core.scanner import ScanContext
from orthosec.detectors import register

# Heuristic: a string assigned to a system-prompt-shaped variable, or a role:system message.
_SYS_ASSIGN = re.compile(
    r"(?i)(system_prompt|system_message|system_instruction|SYSTEM_PROMPT)\s*[:=]"
)
_ROLE_SYSTEM = re.compile(r"""(?i)['"]role['"]\s*:\s*['"]system['"]""")

# Signals that untrusted input is concatenated straight into a prompt.
_CONCAT_INJECTION = re.compile(
    r"""(?xi)
    (f['"].*\{[^}]*(user|input|query|question|message|content|request)[^}]*\}.*['"]) |   # f-string
    (['"].*['"]\s*\+\s*\w*(user|input|query|question|message|request)\w*) |               # "..." + user
    (\.format\([^)]*(user|input|query|message)) |                                          # .format(user=
    (%\s*\([^)]*(user|input|query)[^)]*\))                                                 # % (user...)
    """
)
# Signals the prompt is hardened (delimiters / explicit trust boundary language).
_HARDENING = re.compile(
    r"(?i)(untrusted|do not follow|ignore any instructions|delimited by|<user_input>|"
    r"treat .* as data|never reveal|do not disclose your (system )?prompt)"
)
_SECRET_IN_PROMPT = re.compile(r"(?i)(api[_-]?key|password|secret|token)\s*[:=]\s*\S")


@register
class PromptHardeningDetector:
    id = "prompt-hardening"
    name = "System prompt injection surface"
    owasp_llm = "LLM01"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.files:
            if path.suffix.lower() not in {".py", ".js", ".ts", ".txt", ".md",
                                           ".prompt", ".yaml", ".yml", ".json"}:
                continue
            text = ctx.read(path)
            if not text:
                continue
            lines = text.splitlines()
            has_prompt = any(_SYS_ASSIGN.search(l) or _ROLE_SYSTEM.search(l) for l in lines)
            if not has_prompt and path.suffix.lower() not in {".prompt", ".txt", ".md"}:
                continue

            for lineno, line in enumerate(lines, start=1):
                # Unsanitized concatenation of user input into a prompt-ish string.
                if _CONCAT_INJECTION.search(line):
                    window = "\n".join(lines[max(0, lineno - 4):lineno + 3])
                    if _HARDENING.search(window):
                        continue  # nearby trust-boundary language -> treat as mitigated
                    yield Finding(
                        detector=self.id,
                        rule_id="ORTHO-PI-001",
                        title="Untrusted input concatenated into prompt without trust boundary",
                        severity=Severity.HIGH,
                        owasp_llm="LLM01",
                        atlas=["AML.T0051", "AML.T0051.000"],
                        file=ctx.rel(path),
                        line=lineno,
                        evidence=line.strip()[:200],
                        remediation=(
                            "Separate instructions from data: place user input inside "
                            "explicit delimiters, instruct the model to treat it as data, "
                            "and add an output/instruction-override guard."
                        ),
                        confidence=0.65,
                    )
                # Secret embedded directly in a prompt string.
                if (_SYS_ASSIGN.search(line) or _ROLE_SYSTEM.search(line)) and _SECRET_IN_PROMPT.search(line):
                    yield Finding(
                        detector=self.id,
                        rule_id="ORTHO-PI-002",
                        title="Secret embedded inside a system prompt",
                        severity=Severity.HIGH,
                        owasp_llm="LLM07",
                        atlas=["AML.T0051.001"],
                        file=ctx.rel(path),
                        line=lineno,
                        evidence=line.strip()[:160],
                        remediation=(
                            "Never put credentials in a prompt — prompt-leak attacks will "
                            "extract them. Inject secrets at the tool/API layer instead."
                        ),
                        confidence=0.7,
                    )
