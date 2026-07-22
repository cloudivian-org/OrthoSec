"""LLM-drafted remediation patches — the optional 'auto' side of remediation.

The deterministic layer decides WHAT is wrong and the fix plan. This module only
drafts the concrete code change for a specific finding, grounded in that finding
and the surrounding file. Nothing is applied unless the caller opts in (`--auto`),
and the original file is always backed up first.
"""
from __future__ import annotations

import re
import textwrap

from orthosec.core.finding import Finding
from orthosec.intel.narrative import _resolve_client_and_model, _call

_FIX_SYSTEM = textwrap.dedent(
    """\
    You are a secure-coding remediation agent. You are given ONE security finding and
    the full source file it occurs in. Return the COMPLETE corrected file that fixes
    that finding with the MINIMAL change necessary.

    RULES:
    - Change only what is needed to remediate the specific finding. Preserve everything else.
    - Do not add features, refactor unrelated code, or alter behavior beyond the fix.
    - Keep imports/style consistent with the file.
    - Output ONLY the corrected file inside a single ```<lang> code block. No prose.
    """
)

_CODE_BLOCK = re.compile(r"```[a-zA-Z0-9_+-]*\n(.*?)```", re.S)


def suggest_patch(finding: Finding, file_text: str) -> str | None:
    """Return the full corrected file text for `finding`, or None if unavailable."""
    client, model = _resolve_client_and_model()
    if client is None:
        return None
    prompt = (
        f"FINDING:\n"
        f"- rule: {finding.rule_id}\n- title: {finding.title}\n"
        f"- severity: {finding.severity.name}\n- OWASP: {finding.owasp_llm}\n"
        f"- location: {finding.location}\n- remediation guidance: {finding.remediation}\n\n"
        f"FULL FILE ({finding.file}):\n```\n{file_text}\n```\n\n"
        "Return the complete corrected file."
    )
    try:
        resp = _call(client, model, prompt, system=_FIX_SYSTEM, max_tokens=8192)
        text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
    except Exception:
        return None
    m = _CODE_BLOCK.search(text)
    fixed = (m.group(1) if m else text).rstrip("\n") + "\n"
    # Guard: reject an empty or absurdly divergent result.
    if not fixed.strip() or len(fixed) < len(file_text) * 0.4:
        return None
    return fixed
