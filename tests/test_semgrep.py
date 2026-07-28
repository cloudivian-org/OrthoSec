"""Optional Semgrep engine: opt-in, deterministic, zero-cost when off. Mocks the
subprocess boundary so the tests run without the semgrep binary installed."""
import os
import shutil
import subprocess
import types
import unittest
from pathlib import Path

from orthosec.detectors import semgrep_scan
from orthosec.core.finding import Severity


class _Env:
    def __init__(self, **kw):
        self.kw, self.old = kw, {}

    def __enter__(self):
        for k, v in self.kw.items():
            self.old[k] = os.environ.get(k)
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.old.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def _ctx():
    return types.SimpleNamespace(root=Path("/repo"), rel=lambda p: str(p))


def _result(check, path="app.py", line=5, sev="ERROR", msg="bad thing", lines="code()", meta=None):
    return {"check_id": check, "path": path, "start": {"line": line},
            "extra": {"message": msg, "severity": sev, "lines": lines, "metadata": meta or {}}}


class TestGating(unittest.TestCase):
    def test_disabled_by_default(self):
        with _Env(ORTHOSEC_SEMGREP=None):
            self.assertFalse(semgrep_scan._enabled())
            self.assertEqual(list(semgrep_scan.SemgrepDetector().scan(_ctx())), [])

    def test_enabled_flag_values(self):
        for v in ("1", "true", "YES", "on"):
            with _Env(ORTHOSEC_SEMGREP=v):
                self.assertTrue(semgrep_scan._enabled())

    def test_enabled_but_no_binary_is_graceful(self):
        orig = semgrep_scan.shutil.which
        semgrep_scan.shutil.which = lambda _: None
        try:
            with _Env(ORTHOSEC_SEMGREP="1"):
                # _collect_results returns [] when the binary is absent -> no findings, no crash
                self.assertEqual(semgrep_scan._collect_results(_ctx()), [])
        finally:
            semgrep_scan.shutil.which = orig


class TestMapping(unittest.TestCase):
    def setUp(self):
        self._orig = semgrep_scan._collect_results

    def tearDown(self):
        semgrep_scan._collect_results = self._orig

    def _run(self, results):
        semgrep_scan._collect_results = lambda ctx: results
        with _Env(ORTHOSEC_SEMGREP="1"):
            return list(semgrep_scan.SemgrepDetector().scan(_ctx()))

    def test_basic_mapping(self):
        f = self._run([_result("rules.orthosec-subprocess-shell-true",
                                msg="subprocess shell=True", lines="subprocess.run(x, shell=True)",
                                meta={"owasp": "LLM05", "references": ["http://ref"]})])[0]
        self.assertEqual(f.detector, "semgrep")
        self.assertTrue(f.rule_id.startswith("SEMGREP:"))
        self.assertEqual(f.severity, Severity.HIGH)     # ERROR -> HIGH
        self.assertEqual(f.owasp_llm, "LLM05")
        self.assertEqual(f.file, "app.py")
        self.assertEqual(f.line, 5)
        self.assertIn("shell=True", f.evidence)

    def test_severity_levels(self):
        outs = self._run([_result("a", sev="ERROR"), _result("b", sev="WARNING", line=6),
                          _result("c", sev="INFO", line=7)])
        self.assertEqual([o.severity for o in outs],
                         [Severity.HIGH, Severity.MEDIUM, Severity.LOW])

    def test_owasp_fallback_from_text(self):
        secret = self._run([_result("hardcoded-jwt-secret", msg="hardcoded secret token")])[0]
        self.assertEqual(secret.owasp_llm, "LLM02")
        sqli = self._run([_result("sql-injection", msg="possible SQL injection")])[0]
        self.assertEqual(sqli.owasp_llm, "LLM05")

    def test_unmapped_owasp_is_blank_not_crash(self):
        f = self._run([_result("some-generic-rule", msg="a generic style issue", meta={})])[0]
        self.assertEqual(f.owasp_llm, "")               # tolerated downstream (owasp_name -> "Unknown")

    def test_dedup(self):
        r = _result("dup")
        self.assertEqual(len(self._run([r, dict(r)])), 1)


class TestBundledRules(unittest.TestCase):
    def test_ruleset_ships_and_looks_valid(self):
        p = semgrep_scan._BUNDLED_RULES / "ai-security.yaml"
        self.assertTrue(p.exists())
        text = p.read_text()
        self.assertIn("rules:", text)
        self.assertIn("orthosec-subprocess-shell-true", text)

    @unittest.skipUnless(shutil.which("semgrep"), "semgrep not installed")
    def test_ruleset_passes_semgrep_validate(self):
        # catches rule-syntax regressions the mocked tests can't see
        proc = subprocess.run(
            ["semgrep", "--validate", "--config", str(semgrep_scan._BUNDLED_RULES),
             "--disable-version-check", "--metrics=off"],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr[-500:])


if __name__ == "__main__":
    unittest.main()
