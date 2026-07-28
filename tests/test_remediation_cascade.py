"""Model-first remediation cascade: try strategies in order, re-scan-verify each, keep the
first that resolves the finding, else REVERT and fall back. The re-scan is the auto-catch."""
import os
import tempfile
import unittest
from pathlib import Path

from orthosec import cli
from orthosec.core.scanner import Scanner


def _repo_with_torch_load():
    d = tempfile.mkdtemp()
    Path(d, "model.py").write_text("import torch\ndef load(p):\n    return torch.load(p)\n")
    res = Scanner().scan(Path(d))
    finding = next(f for f in res.findings if f.rule_id == "ORTHO-SUPPLY-001")
    pre = {f.fingerprint for f in res.findings if f.file == finding.file}
    return d, res, finding, pre


class TestCascadeDeterministic(unittest.TestCase):
    def test_deterministic_fix_applied_and_verified(self):
        d, res, finding, pre = _repo_with_torch_load()
        rec = cli._cascade_apply(finding, d, res, pre, verify=True)
        self.assertEqual(rec["status"], "resolved")
        self.assertEqual(rec["strategy"], "deterministic")
        self.assertIn("weights_only=True", Path(d, "model.py").read_text())
        self.assertTrue(Path(d, "model.py.orig").exists())        # backup kept on success


class TestCascadeRevert(unittest.TestCase):
    def test_unverifiable_fix_is_reverted(self):
        d, res, finding, pre = _repo_with_torch_load()
        original = Path(d, "model.py").read_text()
        # a strategy whose "fix" changes the file but does NOT resolve the finding
        self._orig = cli._fix_strategies
        cli._fix_strategies = lambda f, r: [("bogus", lambda src: src + "\n# not a real fix\n")]
        try:
            rec = cli._cascade_apply(finding, d, res, pre, verify=True)
        finally:
            cli._fix_strategies = self._orig
        self.assertEqual(rec["status"], "failed")
        self.assertEqual(Path(d, "model.py").read_text(), original)   # reverted
        self.assertFalse(Path(d, "model.py.orig").exists())           # backup dropped

    def test_first_failing_then_deterministic_succeeds(self):
        d, res, finding, pre = _repo_with_torch_load()
        from orthosec.remediation_fix import deterministic_fix
        self._orig = cli._fix_strategies
        # bogus (won't verify) THEN the real deterministic fix — cascade must fall through
        cli._fix_strategies = lambda f, r: [
            ("bogus", lambda src: src + "\n# noop\n"),
            ("deterministic", lambda src: deterministic_fix(finding, src)),
        ]
        try:
            rec = cli._cascade_apply(finding, d, res, pre, verify=True)
        finally:
            cli._fix_strategies = self._orig
        self.assertEqual(rec["status"], "resolved")
        self.assertEqual(rec["strategy"], "deterministic")
        self.assertIn("weights_only=True", Path(d, "model.py").read_text())


class TestCascadeOrdering(unittest.TestCase):
    """Posture knob: ORTHOSEC_FIX_ORDER=model-first flips deterministic vs models."""

    def setUp(self):
        import orthosec.remediation_fix as rf
        from orthosec.intel import local_backend, narrative, autofix
        self._save = (rf.has_deterministic_fix, local_backend.enabled,
                      local_backend.resolve, narrative._resolve_cloud_client_and_model,
                      autofix.suggest_patch)
        rf.has_deterministic_fix = lambda f: True
        local_backend.enabled = lambda: True
        local_backend.resolve = lambda: (object(), "local")
        narrative._resolve_cloud_client_and_model = lambda: (object(), "cloud")
        autofix.suggest_patch = lambda *a, **k: None

    def tearDown(self):
        import orthosec.remediation_fix as rf
        from orthosec.intel import local_backend, narrative, autofix
        (rf.has_deterministic_fix, local_backend.enabled, local_backend.resolve,
         narrative._resolve_cloud_client_and_model, autofix.suggest_patch) = self._save

    def _labels(self):
        return [lbl for lbl, _ in cli._fix_strategies(object(), ".")]

    def test_default_deterministic_first(self):
        with_env = os.environ.pop("ORTHOSEC_FIX_ORDER", None)
        try:
            labels = self._labels()
        finally:
            if with_env is not None:
                os.environ["ORTHOSEC_FIX_ORDER"] = with_env
        self.assertEqual(labels[0], "deterministic")
        self.assertTrue(any(l.startswith("model:local") for l in labels))
        self.assertTrue(any(l.startswith("model:cloud") for l in labels))

    def test_model_first_posture(self):
        os.environ["ORTHOSEC_FIX_ORDER"] = "model-first"
        try:
            labels = self._labels()
        finally:
            os.environ.pop("ORTHOSEC_FIX_ORDER", None)
        self.assertTrue(labels[0].startswith("model:"))
        self.assertEqual(labels[-1], "deterministic")


if __name__ == "__main__":
    unittest.main()
