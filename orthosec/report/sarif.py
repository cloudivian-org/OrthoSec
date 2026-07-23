"""SARIF 2.1.0 output — drops OrthoSec findings straight into CI / GitHub code scanning.

This is the adoption flywheel: `orthosec scan --sarif results.sarif` uploaded via
github/codeql-action/upload-sarif surfaces AI-security findings inline on PRs.
"""
from __future__ import annotations

from orthosec.core.finding import Severity
from orthosec.core.scanner import ScanResult
from orthosec.core.taxonomy import owasp_name

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def to_sarif(result: ScanResult, version: str = "0.1.0") -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in result.findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.remediation},
                "properties": {
                    "owasp-llm": f.owasp_llm,
                    "owasp-llm-name": owasp_name(f.owasp_llm),
                    "mitre-atlas": f.atlas,
                    "security-severity": _security_severity(f.severity),
                },
            }
        entry = {
            "ruleId": f.rule_id,
            "level": _LEVEL[f.severity],
            # rank (0-100) = severity band x detector confidence, so CI can sort by risk.
            "rank": round(float(_security_severity(f.severity)) * 10 * f.confidence, 1),
            "message": {"text": f"{f.title}. {f.business_impact or ''} Fix: {f.remediation}".strip()},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": max(1, f.line)},
                }
            }],
            # Stable identity so GitHub code scanning dedupes across runs and line moves.
            "partialFingerprints": {"orthosecFingerprint/v1": f.fingerprint},
            "properties": {"owasp-llm": f.owasp_llm, "atlas": f.atlas, "confidence": f.confidence},
        }
        code_flow = _code_flow(f)
        if code_flow:
            entry["codeFlows"] = [code_flow]
        results.append(entry)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "OrthoSec",
                "informationUri": "https://github.com/cloudivian-org/OrthoSec",
                "version": version,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def _code_flow(f) -> dict | None:
    """A SARIF codeFlow rendering OrthoSec's dataflow trace (source -> sink), so GitHub
    code scanning shows the propagation path, not just the sink line."""
    trace = f.metadata.get("trace") or []
    if not trace:
        return None
    locations = []
    for step in trace:
        locations.append({
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": max(1, step.get("line", f.line))},
                },
                "message": {"text": f"{step.get('role', '')}: {step.get('snippet', '')}".strip()},
            }
        })
    return {"threadFlows": [{"locations": locations}]}


def _security_severity(sev: Severity) -> str:
    # GitHub code scanning maps this 0.0-10.0 float to its severity buckets.
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.5",
        Severity.LOW: "3.0",
        Severity.INFO: "1.0",
    }[sev]
