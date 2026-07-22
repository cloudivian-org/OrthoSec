"""OrthoSec runtime guard — integrate defense at LLM call time, in any Python app.

Static scanning finds risk before deploy; the guard catches it at runtime. Drop
`@guard` on the function that calls your LLM, or call `scan_prompt` / `scan_output`
directly. Zero dependencies, framework-agnostic (OpenAI, Anthropic, LangChain,
custom) — it inspects the strings, not the SDK.

Modes:
  * "monitor" (default) — never raises; reports risks via the on_risk callback.
  * "block" — raises PromptInjectionError on a prompt-injection hit before the
    wrapped call runs; scans output after.

This is deliberately heuristic (fast, offline). It is a runtime tripwire, not a
guarantee — pair it with the static scanner and least-privilege tool design.
"""
from __future__ import annotations

import functools
import re
from dataclasses import dataclass, field

# (label, pattern) — direct/indirect prompt-injection & jailbreak markers in input.
_INJECTION = [
    ("instruction override", re.compile(r"(?i)ignore\s+(all\s+|the\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|context)")),
    ("instruction override", re.compile(r"(?i)disregard\s+(all\s+|the\s+|your\s+)?(previous|above|prior|system)")),
    ("persona hijack", re.compile(r"(?i)you\s+are\s+now\b|new\s+instructions:|from\s+now\s+on\s+you")),
    ("system-prompt exfiltration", re.compile(r"(?i)(reveal|repeat|print|show|leak)\s+(me\s+)?(your\s+)?(system\s+)?(prompt|instructions)")),
    ("jailbreak", re.compile(r"(?i)\b(developer\s+mode|jailbreak|DAN\b|do\s+anything\s+now|unfiltered)\b")),
    ("guardrail bypass", re.compile(r"(?i)\b(bypass|override|turn\s+off|disable)\b.{0,20}\b(safety|guardrail|filter|policy|restriction)")),
    ("delimiter breakout", re.compile(r"</?(system|assistant|instructions)\s*>|```\s*system")),
]
# (label, pattern) — risky content in model OUTPUT before it hits a downstream sink.
_OUTPUT_RISK = [
    ("leaked credential", re.compile(r"\b(sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35})\b")),
    ("executable payload", re.compile(r"(?i)(<script\b|javascript:|onerror\s*=|eval\s*\(|document\.cookie)")),
    ("system-prompt leak", re.compile(r"(?i)(my\s+system\s+prompt\s+is|i\s+was\s+instructed\s+to|the\s+instructions\s+i\s+received)")),
]


class PromptInjectionError(Exception):
    """Raised by @guard(mode='block') when a prompt-injection pattern is detected."""


@dataclass
class GuardResult:
    ok: bool
    risks: list[str] = field(default_factory=list)   # "label: matched snippet"
    where: str = "prompt"                             # "prompt" | "output"

    def __bool__(self) -> bool:
        return self.ok


def _scan(text: str, rules, where: str) -> GuardResult:
    if not isinstance(text, str) or not text:
        return GuardResult(ok=True, where=where)
    risks = []
    for label, pat in rules:
        m = pat.search(text)
        if m:
            risks.append(f"{label}: {m.group(0)[:60]!r}")
    return GuardResult(ok=not risks, risks=risks, where=where)


def scan_prompt(text: str) -> GuardResult:
    """Heuristically scan untrusted input / a rendered prompt for injection."""
    return _scan(text, _INJECTION, "prompt")


def scan_output(text: str) -> GuardResult:
    """Heuristically scan model output for leaks / executable payloads before use."""
    return _scan(text, _OUTPUT_RISK, "output")


def guard(mode: str = "monitor", prompt_arg: str | int | None = None, on_risk=None):
    """Decorate an LLM-calling function to inspect its prompt and output at runtime.

    prompt_arg: name (kwarg) or positional index of the prompt/user-input argument.
                If None, the first str positional arg (and any str kwargs) are scanned.
    on_risk:    callback(GuardResult) invoked for every non-clean scan (both modes).
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            for res in _scan_inputs(args, kwargs, prompt_arg):
                if res.risks:
                    if on_risk:
                        on_risk(res)
                    if mode == "block":
                        raise PromptInjectionError("; ".join(res.risks))

            result = fn(*args, **kwargs)

            out = _coerce_text(result)
            ores = scan_output(out)
            if ores.risks and on_risk:
                on_risk(ores)
            return result
        return wrapper
    return decorator


def _scan_inputs(args, kwargs, prompt_arg):
    if isinstance(prompt_arg, int) and prompt_arg < len(args):
        yield scan_prompt(_coerce_text(args[prompt_arg]))
    elif isinstance(prompt_arg, str) and prompt_arg in kwargs:
        yield scan_prompt(_coerce_text(kwargs[prompt_arg]))
    else:
        for a in args:
            if isinstance(a, str):
                yield scan_prompt(a)
        for v in kwargs.values():
            if isinstance(v, str):
                yield scan_prompt(v)


def _coerce_text(value) -> str:
    if isinstance(value, str):
        return value
    # Best-effort: pull text out of common message/response shapes.
    for attr in ("content", "text"):
        v = getattr(value, attr, None)
        if isinstance(v, str):
            return v
    if isinstance(value, dict):
        for k in ("content", "text", "prompt"):
            if isinstance(value.get(k), str):
                return value[k]
    return str(value) if value is not None else ""
