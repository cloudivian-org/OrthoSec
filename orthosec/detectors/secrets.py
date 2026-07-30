"""Detect hardcoded model/provider credentials in an AI codebase.

OWASP LLM02 (Sensitive Information Disclosure) / LLM03 (Supply Chain).
Leaked provider keys are the single most common real-world AI incident: a key in
git history = someone else billing your model + exfiltrating your prompts/data.
"""
from __future__ import annotations

import re
from typing import Iterable

from orthosec.core.finding import Finding, Severity
from orthosec.core.scanner import ScanContext
from orthosec.detectors import register

# name -> (compiled pattern, note). Patterns favor precision over recall.
_PATTERNS = {
    "OpenAI API key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    "Anthropic API key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    "AWS access key id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "HuggingFace token": re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "Generic assigned secret": re.compile(
        r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]([^'\"\s]{12,})['\"]"
    ),
}

# Values that are variable/env NAMES or references, not actual secrets. Real keys
# carry entropy (digits + mixed case); a pure identifier or a config-word field name
# is not a leak. Catches: openai_api_key, apiKey, OPENAI_API_KEY, ${VAR}, process.env.X,
# env(OPENAI_API_KEY), $(VAR), {{ var }}, %VAR%, <%= x %> (config-template interpolation).
_ENV_NAMEISH = re.compile(
    r"(?i)(^[A-Za-z][A-Za-z_]*$)"                                 # pure identifier, no digits
    r"|(_(name|key|secret|token|password|id|url|host|env|field))$"  # trailing config word
    r"|^(process\.env|os\.environ|import\.meta|\$\{|\$[A-Za-z]|\$\(|env\(|\{\{|%[A-Za-z]|<%|fields?\.|config\.)")

# Obvious placeholders we should not flag as real leaks.
_PLACEHOLDER = re.compile(
    r"(?i)(your|example|placeholder|dummy|xxx|\.\.\.|<[^>]+>|changeme|test|sample|fake|mock|"
    r"invalid|expired|redact|should[-_]?not|foobar|not[-_]?real|replace[-_]?me|abcdef|123456)")
# Test / fixture / example paths — a "secret" here is usually a fake test value.
_TEST_PATH = re.compile(
    r"(?i)((^|/)(tests?|__tests__|fixtures?|mocks?|examples?|samples?|demos?|spec)(/)|"
    r"conftest|_tests?\.|\.test\.|(^|/)test_|\.spec\.|_spec\.|integration_test)")
# Inline test blocks (Rust `#[test]`, Go `func TestX`, JUnit `@Test`, JS `it(`/`describe(`,
# pytest `def test_`): a literal key near one of these is a fixture, not a production leak.
_TEST_MARKER = re.compile(
    r"(?i)(#\[test\]|#\[cfg\(test\)\]|mod tests\b|@Test\b|def test_|func Test[A-Z]|"
    r"\bit\(|\bdescribe\(|\bassert|\bexpect\(|RedactionMode|redact\()")

# Placeholder keys carry no real entropy: a run of one char, a sequential alphabet/digit
# ramp, or very few distinct characters for their length. Real keys look random.
_REPEAT_RUN = re.compile(r"(.)\1{4,}")
_SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop")


def _is_fake_secret(hit: str) -> bool:
    """True for an obvious placeholder key (repeated/sequential/low-diversity chars)."""
    body = re.sub(r"[^A-Za-z0-9]", "", re.split(r"sk-(?:proj|ant)-", hit)[-1])
    if len(body) < 12:
        return False
    if _REPEAT_RUN.search(body):
        return True
    low = body.lower()
    for seq in _SEQUENCES:
        for i in range(len(seq) - 5):
            if seq[i:i + 6] in low:
                return True
    return len(body) >= 16 and len(set(low)) <= 10   # too few distinct chars for the length

# A provider key prefix inside a string literal adjacent to concatenation — the
# classic "split the key to dodge a single-literal regex" evasion.
_SPLIT_KEY = re.compile(r"""['"]sk-(?:ant|proj)-[A-Za-z0-9_-]*['"]\s*\+|\+\s*['"]sk-(?:ant|proj)-""")


@register
class SecretsDetector:
    id = "secrets"
    name = "Hardcoded credentials"
    owasp_llm = "LLM02"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.iter_files():
            text = ctx.read(path)
            if not text:
                continue
            rel = ctx.rel(path)
            lines = text.splitlines()
            path_is_test = bool(_TEST_PATH.search(rel))

            def _in_test(ln: int) -> bool:
                # test path, or an inline test marker in the ~15 lines above (Rust/Go/JVM
                # keep tests in the same source file, so a filename check alone misses them).
                if path_is_test:
                    return True
                lo = max(0, ln - 16)
                return any(_TEST_MARKER.search(lines[i]) for i in range(lo, ln))

            for lineno, line in enumerate(lines, start=1):
                test_ctx = _in_test(lineno)
                suffix = "  (test/example code — likely a fixture, verify)" if test_ctx else ""
                if _SPLIT_KEY.search(line) and not _PLACEHOLDER.search(line):
                    yield Finding(
                        detector=self.id,
                        rule_id="ORTHO-SECRET-002",
                        title="Provider key assembled via string concatenation (possible split secret)" + suffix,
                        severity=Severity.LOW if test_ctx else Severity.HIGH,
                        owasp_llm="LLM02",
                        atlas=["AML.T0055"],
                        file=rel,
                        line=lineno,
                        evidence=line.strip()[:120],
                        remediation=(
                            "A credential split across concatenation is still a hardcoded secret. "
                            "Rotate it and load from an env var / secrets manager."
                        ),
                        confidence=0.5 if test_ctx else 0.75,
                    )
                for kind, pat in _PATTERNS.items():
                    m = pat.search(line)
                    if not m:
                        continue
                    hit = m.group(0)
                    if _PLACEHOLDER.search(hit) or _is_fake_secret(hit):
                        continue
                    generic = kind.startswith("Generic")
                    # Generic matches often catch env-var names, not real secrets.
                    if generic and (_ENV_NAMEISH.search(m.group(2) or "")
                                    or _is_fake_secret(m.group(2) or "")):
                        continue
                    if test_ctx:
                        sev = Severity.LOW
                    else:
                        sev = Severity.MEDIUM if generic else Severity.CRITICAL
                    yield Finding(
                        detector=self.id,
                        rule_id="ORTHO-SECRET-001",
                        title=f"{kind} committed in source" + suffix,
                        severity=sev,
                        owasp_llm="LLM02",
                        atlas=["AML.T0055"],
                        file=rel,
                        line=lineno,
                        evidence=_redact(hit),
                        remediation=(
                            "Remove the secret, rotate it immediately, and load from an "
                            "env var or secrets manager. Purge it from git history."
                        ),
                        confidence=(0.4 if test_ctx else (0.6 if generic else 0.9)),
                    )


def _redact(secret: str) -> str:
    s = secret.strip()
    if len(s) <= 8:
        return s[0] + "***"
    return f"{s[:4]}…{s[-4:]} (redacted)"
