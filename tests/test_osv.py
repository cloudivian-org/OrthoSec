"""OSV.dev CVE enrichment for pinned AI/ML deps: opt-in, deterministic, fail-open.
The network boundary (osv.query) is mocked so the suite stays offline."""
import os
import tempfile
import unittest
from pathlib import Path

from orthosec import osv
from orthosec.core.scanner import Scanner


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


def _repo(reqs="langchain==0.0.100\nopenai==1.0.0\nnumpy==1.26.0\n"):
    d = tempfile.mkdtemp()
    Path(d, "requirements.txt").write_text(reqs)
    return Path(d)


class TestOsvClient(unittest.TestCase):
    def test_enabled_gating(self):
        with _Env(ORTHOSEC_OSV=None):
            self.assertFalse(osv.enabled())
        with _Env(ORTHOSEC_OSV="1"):
            self.assertTrue(osv.enabled())

    def test_empty_input(self):
        self.assertEqual(osv.query([]), [])

    def test_fail_open_on_network_error(self):
        import urllib.request
        orig = urllib.request.urlopen
        urllib.request.urlopen = lambda *a, **k: (_ for _ in ()).throw(OSError("no net"))
        try:
            self.assertIsNone(osv.query([("PyPI", "langchain", "0.0.100")]))
        finally:
            urllib.request.urlopen = orig


class TestEnrichment(unittest.TestCase):
    def setUp(self):
        self._orig = osv.query

    def tearDown(self):
        osv.query = self._orig

    def _dep003(self, findings):
        return [f for f in findings if f.rule_id == "ORTHO-DEP-003"]

    def test_disabled_by_default(self):
        with _Env(ORTHOSEC_OSV=None):
            osv.query = lambda pkgs: [["CVE-X"] for _ in pkgs]   # would fire if called
            findings = Scanner().scan(_repo()).findings
            self.assertEqual(self._dep003(findings), [])

    def test_vulns_become_findings(self):
        # langchain -> 2 vulns, openai/numpy -> none
        def fake(pkgs):
            return [["GHSA-1", "CVE-2"] if n == "langchain" else [] for _, n, _ in pkgs]
        osv.query = fake
        with _Env(ORTHOSEC_OSV="1"):
            hits = self._dep003(Scanner().scan(_repo()).findings)
        self.assertEqual(len(hits), 1)
        self.assertIn("langchain", hits[0].title)
        self.assertIn("2 known", hits[0].title)
        self.assertEqual(hits[0].severity.name, "HIGH")
        self.assertEqual(hits[0].metadata["osv_ids"], ["GHSA-1", "CVE-2"])

    def test_fail_open_no_findings(self):
        osv.query = lambda pkgs: None                     # network failed
        with _Env(ORTHOSEC_OSV="1"):
            findings = Scanner().scan(_repo()).findings
            self.assertEqual(self._dep003(findings), [])   # no crash, no DEP-003

    def test_only_pinned_deps_queried(self):
        captured = {}
        osv.query = lambda pkgs: (captured.setdefault("pkgs", pkgs), [[] for _ in pkgs])[1]
        with _Env(ORTHOSEC_OSV="1"):
            Scanner().scan(_repo("langchain==0.0.100\nopenai>=1.0.0\ntorch\n")).findings
        names = {n for _, n, _ in captured.get("pkgs", [])}
        self.assertIn("langchain", names)     # pinned
        self.assertNotIn("openai", names)     # range, not exact -> not queried
        self.assertNotIn("torch", names)      # unpinned -> not queried


if __name__ == "__main__":
    unittest.main()
