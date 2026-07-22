"""Shared helper for detecting *mitigation* signals in source.

A recurring trap for a security scanner: a mitigation-keyword regex ("confirm",
"sanitize", "provenance") matches the word inside a COMMENT — often a negated one
like `# no confirmation` or `# no provenance check` — and the detector wrongly
concludes the risk is mitigated. A scanner that reads "no confirmation" as
"confirmation present" produces false negatives, the worst failure mode here.

`mitigation_present` only counts a signal that appears in CODE (comments stripped)
and is not negated on that line.
"""
from __future__ import annotations

import re

# Words that flip a mitigation mention into evidence the control is ABSENT.
NEGATION = re.compile(r"(?i)\b(no|not|without|lacks?|missing|skip|bypass|disabled?|todo|fixme)\b")


def strip_comments(text: str) -> str:
    """Blank out trailing line comments (# and //) so behavior detectors don't fire
    on keywords that appear only in prose. NOTE: secrets detection deliberately does
    NOT use this — a key committed inside a comment is still a leak.
    """
    return "\n".join(line.split("#", 1)[0].split("//", 1)[0] for line in text.splitlines())


def mitigation_present(text: str, pattern: re.Pattern) -> bool:
    """True iff `pattern` matches on a non-comment, non-negated line of `text`."""
    for raw in text.splitlines():
        code = raw.split("#", 1)[0].split("//", 1)[0]
        if pattern.search(code) and not NEGATION.search(code):
            return True
    return False
