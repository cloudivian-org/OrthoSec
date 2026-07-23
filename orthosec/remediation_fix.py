"""Deterministic code fixes — no LLM, no network, fully reproducible.

For a well-understood subset of findings the correct fix is unambiguous, so we
apply it with a precise text edit instead of asking an LLM to draft a patch. This
keeps the trustworthy path (deterministic core) end-to-end: OrthoSec both *finds*
the issue and *fixes* it without a model in the loop. Anything not covered here
returns None and falls back to the opt-in LLM drafter.

Every fixer:
  - edits exactly one line (the finding's line),
  - is a no-op if the safe form is already present,
  - returns the full new file text, or None if it can't fix safely.
"""
from __future__ import annotations

import re

from orthosec.core.finding import Finding

# torch.load(...) that closes on the same line and has no weights_only kwarg.
_TORCH_LOAD = re.compile(r"\btorch\.load\s*\(")
# yaml.load( without a Loader= (the detector only fires in that case anyway).
_YAML_LOAD = re.compile(r"\byaml\.load\s*\(")


def _matching_paren(s: str, open_idx: int) -> int:
    """Index of the ')' that closes the '(' at open_idx, or -1 if not on this string."""
    depth = 0
    for i in range(open_idx, len(s)):
        if s[i] == "(":
            depth += 1
        elif s[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _fix_torch_load(line: str) -> str | None:
    if "weights_only" in line:
        return None
    m = _TORCH_LOAD.search(line)
    if not m:
        return None
    open_idx = line.index("(", m.start())
    close = _matching_paren(line, open_idx)
    if close == -1:                                   # multi-line call — don't guess
        return None
    inner = line[open_idx + 1:close].strip()
    insert = "weights_only=True" if not inner else ", weights_only=True"
    return line[:close] + insert + line[close:]


def _fix_yaml_load(line: str) -> str | None:
    if "Loader" in line or "safe_load" in line:       # explicit loader / already safe
        return None
    if not _YAML_LOAD.search(line):
        return None
    return _YAML_LOAD.sub("yaml.safe_load(", line, count=1)


# Which fixer to try, per finding. Keyed on a substring of the title so a single
# rule id (ORTHO-SUPPLY-001) can route to different fixers by what it flagged.
def _select(finding: Finding):
    t = finding.title.lower()
    if finding.rule_id == "ORTHO-SUPPLY-001":
        if "torch.load" in t:
            return _fix_torch_load
        if "yaml.load" in t:
            return _fix_yaml_load
    return None


def deterministic_fix(finding: Finding, source: str) -> str | None:
    """Full new file text with a safe, deterministic fix applied to the finding's
    line, or None if no deterministic fixer applies / it can't fix safely."""
    fixer = _select(finding)
    if fixer is None or finding.line <= 0:
        return None
    lines = source.splitlines(keepends=True)
    idx = finding.line - 1
    if idx >= len(lines):
        return None
    raw = lines[idx]
    body = raw.rstrip("\r\n")
    newline = raw[len(body):]                          # preserve the line ending
    fixed = fixer(body)
    if fixed is None or fixed == body:
        return None
    lines[idx] = fixed + newline
    return "".join(lines)


def has_deterministic_fix(finding: Finding) -> bool:
    return _select(finding) is not None
