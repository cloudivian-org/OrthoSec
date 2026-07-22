"""Remediation agents — who fixes what, and how.

Every finding is routed to a specialized remediation agent. Each agent owns a
deterministic fix plan (always available) and declares whether an automated code
fix is safe to attempt. Auto-fix is opt-in and gated: it proposes a minimal patch
(via the intel layer) that a human approves or `--auto` applies with a backup.

This keeps remediation trustworthy: the *plan* is deterministic and reviewable;
the LLM only drafts the concrete patch, never decides what is wrong.
"""
from __future__ import annotations

from dataclasses import dataclass

from orthosec.core.finding import Finding


@dataclass(frozen=True)
class RemediationAgent:
    id: str
    name: str
    summary: str
    auto_available: bool          # is a safe automated code fix feasible?
    steps: list[str]              # deterministic, reviewable fix plan


# Detector id -> the agent that remediates its findings.
AGENTS: dict[str, RemediationAgent] = {
    "prompt-hardening": RemediationAgent(
        id="prompt-boundary",
        name="Prompt Boundary Agent",
        summary="Establishes a trust boundary between instructions and untrusted input.",
        auto_available=True,
        steps=[
            "Move user/tool input out of the instruction string into a clearly delimited block.",
            "Add an explicit instruction: treat delimited content as data, never as commands.",
            "Add an instruction-override guard and a 'do not reveal the system prompt' clause.",
        ],
    ),
    "secrets": RemediationAgent(
        id="secret-rotation",
        name="Secret Rotation Agent",
        summary="Removes committed credentials and moves them to a secrets manager.",
        auto_available=False,  # rotation must happen out-of-band; never auto-edit a live key
        steps=[
            "Rotate the exposed credential immediately at the provider.",
            "Replace the literal with an env var / secrets-manager lookup.",
            "Purge the secret from git history (git filter-repo / BFG).",
        ],
    ),
    "unsafe-model-load": RemediationAgent(
        id="safe-loader",
        name="Safe Loader Agent",
        summary="Switches artifact loading to a memory-safe, integrity-checked path.",
        auto_available=True,
        steps=[
            "Prefer safetensors; for torch pass weights_only=True; for yaml use SafeLoader.",
            "Pin the artifact source to a trusted, integrity-verified revision.",
            "Verify a checksum/signature before loading.",
        ],
    ),
    "output-handling": RemediationAgent(
        id="output-sanitizer",
        name="Output Sanitizer Agent",
        summary="Treats model output as untrusted before it reaches a downstream sink.",
        auto_available=True,
        steps=[
            "Validate model output against a strict schema (types, enum, length).",
            "Escape/parameterize before the sink; never eval/exec or string-concat into SQL/HTML/shell.",
            "Fail closed on validation error.",
        ],
    ),
    "tool-exposure": RemediationAgent(
        id="agency-gate",
        name="Agency Gate Agent",
        summary="Constrains an over-privileged tool and gates high-impact actions.",
        auto_available=True,
        steps=[
            "Scope the tool to the minimum capability it needs; add an allowlist.",
            "Gate irreversible/high-impact actions behind explicit human confirmation.",
            "Never pass model output unsanitized into shell/SQL/file sinks.",
        ],
    ),
    "unbounded-consumption": RemediationAgent(
        id="rate-limiter",
        name="Rate Limiter Agent",
        summary="Bounds token spend and loop depth to stop denial-of-wallet / DoS.",
        auto_available=True,
        steps=[
            "Set max_tokens and a request timeout on every model call.",
            "Bound agent loops with max iterations/steps and a wall-clock deadline.",
            "Enforce per-user token budgets and rate limits; fail closed at the cap.",
        ],
    ),
    "rag-trust": RemediationAgent(
        id="provenance",
        name="Provenance Agent",
        summary="Establishes provenance for everything indexed into the retrieval corpus.",
        auto_available=False,  # source-trust policy is a human decision
        steps=[
            "Restrict ingestion to vetted, trusted sources.",
            "Sanitize fetched/uploaded content before indexing.",
            "Treat retrieved chunks as delimited, non-authoritative data at prompt time.",
        ],
    ),
}

_FALLBACK = RemediationAgent(
    id="review", name="Manual Review Agent",
    summary="No specialized agent; needs manual security review.",
    auto_available=False, steps=["Review the finding and apply the remediation guidance."],
)


def agent_for(finding: Finding) -> RemediationAgent:
    return AGENTS.get(finding.detector, _FALLBACK)


def assign(findings: list[Finding]) -> None:
    """Attach remediation-agent metadata to each finding in place (deterministic)."""
    for f in findings:
        a = agent_for(f)
        f.metadata["agent_id"] = a.id
        f.metadata["agent_name"] = a.name
        f.metadata["agent_summary"] = a.summary
        f.metadata["auto_available"] = a.auto_available
        f.metadata["plan"] = a.steps
