"""Model-backed confidence tiering: opt-in, additive, fail-open. Confirms deterministic
findings or attaches an advisory note — never removes or invents a finding."""
import os
import unittest

from orthosec.intel import triage
from orthosec.intel import narrative
from orthosec.core.finding import Finding, Severity


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


def _finding():
    return Finding(detector="output-handling", rule_id="ORTHO-OUTPUT-001",
                   title="model output into shell", severity=Severity.HIGH,
                   owasp_llm="LLM05", atlas=[], file="app.py", line=3,
                   evidence="os.system(out)", remediation="sanitize")


class _Mock:
    """Patch narrative resolve/_call/_text_of so corroborate uses a canned verdict."""
    def __init__(self, verdict_text, resolve=("client", "m"), raise_on_call=False):
        self.verdict_text, self.resolve, self.raise_on_call = verdict_text, resolve, raise_on_call

    def __enter__(self):
        self._save = (narrative._resolve_client_and_model, narrative._call, narrative._text_of)
        narrative._resolve_client_and_model = lambda: self.resolve
        def _call(*a, **k):
            if self.raise_on_call:
                raise RuntimeError("model down")
            return object()
        narrative._call = _call
        narrative._text_of = lambda resp: self.verdict_text
        return self

    def __exit__(self, *a):
        narrative._resolve_client_and_model, narrative._call, narrative._text_of = self._save


class TestGating(unittest.TestCase):
    def test_disabled_by_default(self):
        with _Env(ORTHOSEC_CONFIDENCE=None):
            self.assertFalse(triage.enabled())
            f = _finding()
            triage.corroborate([f], "/root")           # no-op
            self.assertEqual(f.confidence_tier, "deterministic")

    def test_no_backend_leaves_unchanged(self):
        with _Env(ORTHOSEC_CONFIDENCE="1"), _Mock('{"verdict":"confirmed"}', resolve=(None, None)):
            f = _finding()
            triage.corroborate([f], "/root")
            self.assertEqual(f.confidence_tier, "deterministic")


class TestCorroborate(unittest.TestCase):
    def test_confirmed_tiers_up(self):
        with _Env(ORTHOSEC_CONFIDENCE="1"), _Mock('{"verdict":"confirmed","reason":"reachable"}'):
            f = _finding()
            triage.corroborate([f], "/root")
            self.assertEqual(f.confidence_tier, "confirmed")
            self.assertGreaterEqual(f.confidence, 0.9)
            self.assertIn("confirmed", f.metadata.get("model_confidence", ""))

    def test_false_positive_keeps_finding_adds_note(self):
        with _Env(ORTHOSEC_CONFIDENCE="1"), _Mock('{"verdict":"false_positive","reason":"guarded"}'):
            f = _finding()
            triage.corroborate([f], "/root")
            # deterministic result STANDS — not removed, not downgraded below deterministic
            self.assertEqual(f.confidence_tier, "deterministic")
            self.assertIn("possible false positive", f.metadata.get("model_confidence", ""))

    def test_uncertain_no_change(self):
        with _Env(ORTHOSEC_CONFIDENCE="1"), _Mock('{"verdict":"uncertain"}'):
            f = _finding()
            triage.corroborate([f], "/root")
            self.assertEqual(f.confidence_tier, "deterministic")
            self.assertNotIn("model_confidence", f.metadata)

    def test_fail_open_on_model_error(self):
        with _Env(ORTHOSEC_CONFIDENCE="1"), _Mock("", raise_on_call=True):
            f = _finding()
            triage.corroborate([f], "/root")           # must not raise
            self.assertEqual(f.confidence_tier, "deterministic")


class TestParseVerdict(unittest.TestCase):
    def test_json_and_fallback(self):
        self.assertEqual(triage._parse_verdict('{"verdict":"confirmed","reason":"x"}')[0], "confirmed")
        self.assertEqual(triage._parse_verdict("prose... FALSE positive here")[0], "false_positive")
        self.assertEqual(triage._parse_verdict("who knows")[0], "uncertain")


if __name__ == "__main__":
    unittest.main()
