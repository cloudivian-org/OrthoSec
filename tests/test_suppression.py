"""Inline suppression + baseline gating tests."""
import json
import tempfile
import unittest
from pathlib import Path

from orthosec import cli
from orthosec.core.scanner import Scanner

_PICKLE = "import pickle\ndef f(p):\n    return pickle.load(open(p, 'rb'))"


def _cats(d):
    return {f.owasp_llm for f in Scanner().scan(d).findings}


class TestInlineSuppression(unittest.TestCase):
    def _write(self, body):
        d = tempfile.mkdtemp()
        Path(d, "a.py").write_text(body)
        return d

    def test_trailing_ignore_suppresses(self):
        d = self._write("import pickle\ndef f(p): return pickle.load(open(p,'rb'))  # orthosec: ignore\n")
        self.assertNotIn("LLM03", _cats(d))

    def test_category_specific(self):
        # ignoring LLM06 does not suppress an LLM03 finding on the same line
        d = self._write("import pickle\ndef f(p): return pickle.load(open(p,'rb'))  # orthosec: ignore LLM06\n")
        self.assertIn("LLM03", _cats(d))

    def test_standalone_comment_above(self):
        d = self._write("import pickle\ndef f(p):\n    # orthosec: ignore LLM03\n    return pickle.load(open(p,'rb'))\n")
        self.assertNotIn("LLM03", _cats(d))

    def test_trailing_ignore_does_not_leak_to_next_line(self):
        d = self._write("import pickle\n"
                        "def a(p): return pickle.load(open(p,'rb'))  # orthosec: ignore\n"
                        "def b(p): return pickle.load(open(p,'rb'))\n")
        self.assertIn("LLM03", _cats(d))  # b is still flagged


class TestBaseline(unittest.TestCase):
    def _proj(self):
        d = tempfile.mkdtemp()
        Path(d, "a.py").write_text(_PICKLE + "\n")
        return d

    def test_write_and_gate(self):
        d = self._proj()
        base = str(Path(d) / "baseline.json")
        rc = cli.main(["scan", d, "--no-exec", "--no-report", "--write-baseline", base])
        self.assertEqual(rc, 0)
        self.assertTrue(Path(base).is_file())
        fps = json.loads(Path(base).read_text())["fingerprints"]
        self.assertTrue(fps)
        # Scanning again with the baseline: all known → gate passes.
        rc2 = cli.main(["scan", d, "--no-exec", "--no-report", "--baseline", base, "--fail-on", "high"])
        self.assertEqual(rc2, 0)

    def test_new_finding_breaks_gate(self):
        d = self._proj()
        base = str(Path(d) / "baseline.json")
        cli.main(["scan", d, "--no-exec", "--no-report", "--write-baseline", base])
        # Introduce a NEW finding in a different file.
        Path(d, "b.py").write_text("import pickle\ndef g(p):\n    return pickle.load(open(p, 'rb'))\n")
        rc = cli.main(["scan", d, "--no-exec", "--no-report", "--baseline", base, "--fail-on", "high"])
        self.assertEqual(rc, 1)  # new finding fails the gate


if __name__ == "__main__":
    unittest.main()
