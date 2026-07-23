"""Tests for LLM04 detector, SARIF fingerprints, scan_files (diff), and fingerprints."""
import tempfile
import unittest
from pathlib import Path

from orthosec.core.scanner import Scanner
from orthosec.core.finding import Finding, Severity
from orthosec.report.sarif import to_sarif


def _scan(body, name="t.py"):
    d = tempfile.mkdtemp()
    Path(d, name).write_text(body)
    return Scanner().scan(Path(d) / name).findings


class TestLLM04(unittest.TestCase):
    def test_finetuning_flagged(self):
        src = "def f(client, fid):\n    return client.fine_tuning.jobs.create(training_file=fid, model='x')\n"
        self.assertIn("LLM04", {f.owasp_llm for f in _scan(src)})

    def test_train_on_untrusted_flagged(self):
        src = ("import requests\n"
               "def train(model, url):\n"
               "    data = requests.get(url).text\n"
               "    return Trainer(model=model, train_dataset=data)\n")
        self.assertIn("LLM04", {f.owasp_llm for f in _scan(src)})

    def test_train_on_local_not_flagged(self):
        src = ("def train(model):\n"
               "    data = load_vetted_corpus('/data')  # verified local data\n"
               "    return Trainer(model=model, train_dataset=data)\n")
        self.assertNotIn("LLM04", {f.owasp_llm for f in _scan(src)})


class TestSarifFingerprint(unittest.TestCase):
    def test_partial_fingerprints_present(self):
        d = tempfile.mkdtemp()
        Path(d, "a.py").write_text("import pickle\ndef f(p):\n    return pickle.load(open(p,'rb'))\n")
        result = Scanner().scan(d)
        sarif = to_sarif(result)
        res = sarif["runs"][0]["results"]
        self.assertTrue(res)
        for r in res:
            fp = r.get("partialFingerprints", {}).get("orthosecFingerprint/v1")
            self.assertTrue(fp and len(fp) == 16)


class TestScanFiles(unittest.TestCase):
    def test_scan_explicit_file_list(self):
        d = tempfile.mkdtemp()
        Path(d, "a.py").write_text("import pickle\ndef f(p):\n    return pickle.load(open(p,'rb'))\n")
        Path(d, "b.py").write_text("x = 1\n")
        result = Scanner().scan_files(d, [str(Path(d, "a.py"))])   # only a.py
        self.assertTrue(result.findings)
        self.assertTrue(all(f.file == "a.py" for f in result.findings))


class TestFingerprint(unittest.TestCase):
    def test_stable_across_line_change(self):
        a = Finding("d", "R", "t", Severity.HIGH, "LLM03", [], "a.py", 10, "pickle.load(f)", "fix")
        b = Finding("d", "R", "t", Severity.HIGH, "LLM03", [], "a.py", 42, "pickle.load(f)", "fix")
        self.assertEqual(a.fingerprint, b.fingerprint)   # line differs, fingerprint same

    def test_differs_by_file(self):
        a = Finding("d", "R", "t", Severity.HIGH, "LLM03", [], "a.py", 1, "x", "fix")
        b = Finding("d", "R", "t", Severity.HIGH, "LLM03", [], "b.py", 1, "x", "fix")
        self.assertNotEqual(a.fingerprint, b.fingerprint)


if __name__ == "__main__":
    unittest.main()
