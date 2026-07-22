"""Detector + scoring tests — pure stdlib, no external deps, no network.

Run: python -m pytest   (or)   python -m unittest
"""
import unittest
from pathlib import Path

from orthosec.core.scanner import Scanner
from orthosec.core.scoring import posture_score, grade
from orthosec.core.finding import Finding, Severity

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "vulnerable-agent"


class TestScanEndToEnd(unittest.TestCase):
    def setUp(self):
        self.result = Scanner().scan(EXAMPLE)

    def test_finds_issues(self):
        self.assertTrue(self.result.findings, "expected findings in the vulnerable demo")

    def test_owasp_categories_covered(self):
        cats = {f.owasp_llm for f in self.result.findings}
        # The demo intentionally triggers each detector class.
        self.assertIn("LLM01", cats)  # prompt injection
        self.assertIn("LLM06", cats)  # excessive agency (shell tool)
        self.assertIn("LLM03", cats)  # unsafe pickle load
        self.assertIn("LLM05", cats)  # improper output handling (eval on model output)
        self.assertIn("LLM08", cats)  # untrusted RAG ingestion

    def test_every_finding_has_evidence_and_taxonomy(self):
        for f in self.result.findings:
            self.assertTrue(f.file, "finding must cite a file")
            self.assertTrue(f.owasp_llm, "finding must map to OWASP LLM")
            self.assertTrue(f.remediation, "finding must have remediation")

    def test_score_penalized(self):
        self.assertLess(self.result.score, 100)
        self.assertIn(self.result.grade, {"A", "B", "C", "D", "F"})


class TestScoring(unittest.TestCase):
    def test_clean_scan_is_100(self):
        self.assertEqual(posture_score([]), 100)
        self.assertEqual(grade(100), "A")

    def test_critical_tanks_score(self):
        f = _finding(Severity.CRITICAL)
        self.assertLess(posture_score([f]), 70)

    def test_diminishing_returns(self):
        # 100 low findings must not score worse than one critical.
        many_low = [_finding(Severity.LOW) for _ in range(100)]
        one_crit = [_finding(Severity.CRITICAL)]
        self.assertGreater(posture_score(many_low), posture_score(one_crit))


class TestProfiles(unittest.TestCase):
    def test_all_profiles_render(self):
        from orthosec.report import console
        from orthosec.profiles import PROFILES
        from orthosec.intel.business_risk import annotate_findings
        result = Scanner().scan(EXAMPLE)
        annotate_findings(result.findings)
        for pid in PROFILES:
            text = console.render(result, profile=pid)
            self.assertIn("Posture score", text)

    def test_ciso_suppresses_line_evidence(self):
        from orthosec.report import console
        from orthosec.intel.business_risk import annotate_findings
        result = Scanner().scan(EXAMPLE)
        annotate_findings(result.findings)
        ciso = console.render(result, profile="ciso")
        engineer = console.render(result, profile="engineer")
        # CISO view shows compliance; engineer view shows raw evidence lines.
        self.assertIn("Regulatory exposure", ciso)
        self.assertIn("evidence:", engineer)
        self.assertNotIn("evidence:", ciso)


def _finding(sev: Severity) -> Finding:
    return Finding(
        detector="t", rule_id="T-1", title="t", severity=sev,
        owasp_llm="LLM01", atlas=[], file="a.py", line=1,
        evidence="x", remediation="fix it", confidence=1.0,
    )


if __name__ == "__main__":
    unittest.main()
