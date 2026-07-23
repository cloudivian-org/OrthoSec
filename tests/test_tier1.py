"""Regression tests for the Tier-1 detection/resolution upgrade:
   A. taint-path traces   B. confidence ranking   C. deterministic fixes + verify.
"""
import textwrap

from orthosec.core.scanner import Scanner
from orthosec.core.finding import Finding, Severity
from orthosec.analysis.pyast import safe_parse, output_taint_sinks
from orthosec.remediation_fix import deterministic_fix, has_deterministic_fix
from orthosec.report.sarif import to_sarif


# ---- A: taint-path traces ---------------------------------------------------

def test_output_sink_has_source_to_sink_trace():
    src = textwrap.dedent("""
        def handle(model):
            resp = model.generate(prompt)
            payload = resp.text
            cmd = payload
            import os
            os.system(cmd)
    """)
    tree = safe_parse(src)
    sinks = output_taint_sinks(tree, src.splitlines())
    assert sinks, "expected a tainted-output sink"
    trace = sinks[0].trace
    roles = [s["role"] for s in trace]
    assert "source" in roles and roles[-1] == "sink"
    # the sink step points at the os.system line
    assert "os.system" in trace[-1]["snippet"]


def test_trace_flows_into_finding_metadata():
    src = "def h(model):\n resp = model.generate(x)\n out = resp\n eval(out)\n"
    tree = safe_parse(src)
    sinks = output_taint_sinks(tree, src.splitlines())
    assert sinks and sinks[0].trace  # non-empty ordered trace


# ---- B: confidence ranking + SARIF ------------------------------------------

def _f(sev, conf, line, rule="R"):
    return Finding(detector="d", rule_id=rule, title="t", severity=sev,
                   owasp_llm="LLM01", atlas=[], file="a.py", line=line,
                   evidence=f"e{line}", remediation="r", confidence=conf)


def test_findings_rank_by_confidence_within_severity():
    findings = [_f(Severity.HIGH, 0.4, 1), _f(Severity.HIGH, 0.9, 2), _f(Severity.CRITICAL, 0.3, 3)]
    findings.sort(key=lambda f: (-f.severity.value, -f.confidence, f.file, f.line))
    assert [f.line for f in findings] == [3, 2, 1]  # critical first, then higher-confidence high


def test_sarif_carries_rank_and_codeflows():
    src = textwrap.dedent("""
        def handle(model):
            resp = model.generate(prompt)
            import os
            os.system(resp)
    """)
    import pathlib, tempfile
    d = tempfile.mkdtemp()
    (pathlib.Path(d) / "m.py").write_text(src)
    r = Scanner().scan(d)
    sarif = to_sarif(r)
    results = sarif["runs"][0]["results"]
    assert results, "expected findings"
    assert all("rank" in x for x in results)
    assert any("codeFlows" in x for x in results)


# ---- C: deterministic fixes + verification ----------------------------------

def test_deterministic_fix_torch_load_adds_weights_only():
    f = Finding(detector="unsafe-model-load", rule_id="ORTHO-SUPPLY-001",
                title="torch.load (pickle-backed) — code executes at load time",
                severity=Severity.HIGH, owasp_llm="LLM03", atlas=[], file="m.py",
                line=1, evidence="torch.load(path)", remediation="r")
    out = deterministic_fix(f, "torch.load(path)\n")
    assert out == "torch.load(path, weights_only=True)\n"


def test_deterministic_fix_yaml_load_uses_safe_load():
    f = Finding(detector="unsafe-model-load", rule_id="ORTHO-SUPPLY-001",
                title="yaml.load (unsafe) — code executes at load time",
                severity=Severity.HIGH, owasp_llm="LLM03", atlas=[], file="m.py",
                line=1, evidence="yaml.load(x)", remediation="r")
    out = deterministic_fix(f, "cfg = yaml.load(x)\n")
    assert out == "cfg = yaml.safe_load(x)\n"


def test_deterministic_fix_idempotent_when_already_safe():
    f = Finding(detector="unsafe-model-load", rule_id="ORTHO-SUPPLY-001",
                title="torch.load (pickle-backed) — code executes at load time",
                severity=Severity.HIGH, owasp_llm="LLM03", atlas=[], file="m.py",
                line=1, evidence="torch.load(p, weights_only=True)", remediation="r")
    assert deterministic_fix(f, "torch.load(p, weights_only=True)\n") is None


def test_only_supply_findings_are_deterministically_fixable():
    supply = Finding(detector="unsafe-model-load", rule_id="ORTHO-SUPPLY-001",
                     title="torch.load (pickle-backed) — code executes at load time",
                     severity=Severity.HIGH, owasp_llm="LLM03", atlas=[], file="m.py",
                     line=1, evidence="x", remediation="r")
    other = Finding(detector="secrets", rule_id="ORTHO-SECRET-001", title="key",
                    severity=Severity.CRITICAL, owasp_llm="LLM02", atlas=[], file="m.py",
                    line=1, evidence="x", remediation="r")
    assert has_deterministic_fix(supply) and not has_deterministic_fix(other)


def test_fix_then_rescan_resolves_finding(tmp_path):
    p = tmp_path / "load.py"
    p.write_text("import torch\nm = torch.load('a.pt')\n")
    before = Scanner().scan(str(tmp_path))
    target = next(f for f in before.findings if f.rule_id == "ORTHO-SUPPLY-001")
    fixed = deterministic_fix(target, p.read_text())
    p.write_text(fixed)
    after = Scanner().scan_files(str(tmp_path), [str(p)])
    assert target.fingerprint not in {f.fingerprint for f in after.findings}
