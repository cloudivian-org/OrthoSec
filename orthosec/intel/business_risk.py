"""Deterministic business-risk model — no LLM required.

Translates technical findings into the language executives fund decisions with:
blast radius, exploitability, and a coarse annualized loss-exposure band. The
bands are transparent and configurable — this is a defensible starting frame,
not a precise actuarial figure, and the report labels it as such.
"""
from __future__ import annotations

from orthosec.core.finding import Finding, Severity

# Coarse annualized-loss-exposure band per severity (USD), order-of-magnitude only.
# Rationale surfaced to execs so the number is arguable, not a black box.
_ALE_BAND = {
    Severity.CRITICAL: (250_000, 5_000_000),
    Severity.HIGH: (50_000, 750_000),
    Severity.MEDIUM: (10_000, 100_000),
    Severity.LOW: (1_000, 20_000),
    Severity.INFO: (0, 2_000),
}

# One-line business consequence per OWASP category — the "so what" for leadership.
_CONSEQUENCE = {
    "LLM01": "Attacker steers the model to bypass policy, exfiltrate data, or misuse tools.",
    "LLM02": "Customer or proprietary data leaks; regulatory + breach-notification exposure.",
    "LLM03": "Compromised dependency/model executes attacker code inside your trust boundary.",
    "LLM04": "Poisoned data degrades model integrity and decisions at scale.",
    "LLM05": "Unsafe model output drives downstream systems (XSS, SQLi, RCE).",
    "LLM06": "Agent takes real-world actions attacker directs — financial/operational loss.",
    "LLM07": "System prompt / secrets leak, exposing IP and enabling targeted attacks.",
    "LLM08": "Retrieval corpus manipulation returns attacker-controlled context.",
    "LLM09": "Model emits confidently wrong output — liability, reputational, safety risk.",
    "LLM10": "Uncapped consumption enables cost-blowout / denial-of-wallet.",
}


def business_risk(findings: list[Finding]) -> dict:
    """Aggregate business framing across findings."""
    low = high = 0
    top_consequences: dict[str, dict] = {}
    for f in findings:
        band = _ALE_BAND[f.severity]
        low += band[0]
        high += band[1]
        c = top_consequences.setdefault(
            f.owasp_llm,
            {"owasp": f.owasp_llm, "consequence": _CONSEQUENCE.get(f.owasp_llm, ""),
             "count": 0, "max_severity": Severity.INFO},
        )
        c["count"] += 1
        if f.severity.value > c["max_severity"].value:
            c["max_severity"] = f.severity

    drivers = sorted(top_consequences.values(),
                     key=lambda x: (x["max_severity"].value, x["count"]), reverse=True)
    for d in drivers:
        d["max_severity"] = d["max_severity"].name

    return {
        "ale_low_usd": low,
        "ale_high_usd": high,
        "basis": "Order-of-magnitude severity bands; configurable. Not an actuarial figure.",
        "risk_drivers": drivers,
    }


def annotate_findings(findings: list[Finding]) -> None:
    """Attach a one-line business_impact to each finding in place (deterministic)."""
    for f in findings:
        f.business_impact = _CONSEQUENCE.get(f.owasp_llm)
