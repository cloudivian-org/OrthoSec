"""Risk taxonomy — the shared vocabulary that maps a Finding to industry frames.

Single source of truth for OWASP LLM Top-10 (2025), MITRE ATLAS, and the
compliance controls the intel layer references. Keeping this centralized means
a detector only emits an id (e.g. "LLM01") and every downstream consumer —
scoring, report, compliance, narrative — resolves consistent context.
"""
from __future__ import annotations

# OWASP Top 10 for LLM Applications (2025).
OWASP_LLM = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# MITRE ATLAS techniques referenced by current detectors (subset, extend freely).
ATLAS = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0053": "LLM Plugin Compromise",
    "AML.T0055": "Unsecured Credentials",
    "AML.T0010": "ML Supply Chain Compromise",
    "AML.T0018": "Manipulate AI Model (Poisoning)",
}

# Compliance controls the intel layer maps findings onto. Framework -> {control: desc}.
COMPLIANCE = {
    "EU_AI_ACT": {
        "Art.15": "Accuracy, robustness and cybersecurity of high-risk AI systems",
        "Art.9": "Risk management system",
        "Art.10": "Data and data governance",
    },
    "NIST_AI_RMF": {
        "MANAGE-2.1": "Resources to manage AI risks are allocated",
        "MAP-5.1": "Likelihood and impact of risks are determined",
        "MEASURE-2.7": "AI system security and resilience are evaluated",
    },
    "ISO_42001": {
        "A.8.2": "AI system impact assessment",
        "A.6.2.4": "AI system verification and validation",
    },
    "SOC2": {
        "CC6.1": "Logical access security",
        "CC7.1": "Detection of security events",
    },
}

# Which compliance controls a given OWASP LLM category implicates. Used by the
# deterministic compliance mapper so exec output cites controls without an LLM.
OWASP_TO_COMPLIANCE = {
    "LLM01": [("EU_AI_ACT", "Art.15"), ("NIST_AI_RMF", "MEASURE-2.7"), ("ISO_42001", "A.6.2.4")],
    "LLM02": [("EU_AI_ACT", "Art.10"), ("SOC2", "CC6.1"), ("NIST_AI_RMF", "MAP-5.1")],
    "LLM03": [("EU_AI_ACT", "Art.15"), ("ISO_42001", "A.8.2"), ("NIST_AI_RMF", "MANAGE-2.1")],
    "LLM04": [("EU_AI_ACT", "Art.10"), ("NIST_AI_RMF", "MAP-5.1")],
    "LLM05": [("EU_AI_ACT", "Art.15"), ("SOC2", "CC7.1")],
    "LLM06": [("EU_AI_ACT", "Art.9"), ("NIST_AI_RMF", "MANAGE-2.1"), ("ISO_42001", "A.8.2")],
    "LLM07": [("SOC2", "CC6.1"), ("NIST_AI_RMF", "MEASURE-2.7")],
    "LLM08": [("EU_AI_ACT", "Art.10"), ("ISO_42001", "A.6.2.4")],
    "LLM09": [("NIST_AI_RMF", "MAP-5.1")],
    "LLM10": [("EU_AI_ACT", "Art.15"), ("SOC2", "CC7.1")],
}


def owasp_name(code: str) -> str:
    return OWASP_LLM.get(code, "Unknown")


def atlas_name(code: str) -> str:
    return ATLAS.get(code, "Unknown technique")
