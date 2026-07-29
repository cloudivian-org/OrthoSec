"""Process-parallel scanning must produce the EXACT same findings as a serial scan.

The parallel scanner shards files across worker processes; each worker emits findings
only for its shard but resolves cross-module context against the full file set. This
test builds a multi-file project — several single-file findings plus one cross-module
(source in handler.py, sink in sink.py) — and asserts the finding set is identical for
serial (jobs=1) and several worker counts. Round-robin sharding puts handler.py and
sink.py in different shards for jobs>=2, so a broken index-sharing path (a lost
cross-module finding) would fail here.
"""
import tempfile
import unittest
from pathlib import Path

from orthosec.core.scanner import Scanner

# A small project with findings spread across many files so round-robin sharding
# actually splits them across workers.
_FILES = {
    # cross-module: LLM output in handler.py flows to a shell sink in sink.py
    "sink.py": "import subprocess\n\ndef run_shell(x):\n    subprocess.run(x, shell=True)\n",
    "handler.py": (
        "from sink import run_shell\n\n"
        "def h(client):\n"
        "    out = client.chat.completions.create(model='x', messages=m).choices[0].message.content\n"
        "    run_shell(out)\n"
    ),
    # single-file findings in distinct files (LLM03 supply-chain load sinks)
    "load_a.py": "import torch\n\ndef a(p):\n    return torch.load(p)\n",
    "load_b.py": "import yaml\n\ndef b(s):\n    return yaml.load(s)\n",
    "load_c.py": "import pickle\n\ndef c(f):\n    return pickle.load(f)\n",
    "load_d.py": "import torch\n\ndef d(p):\n    return torch.load(p)\n",
    "load_e.py": "import yaml\n\ndef e(s):\n    return yaml.load(s)\n",
}


def _keyset(findings):
    return sorted((f.file, f.line, f.rule_id, f.severity.name, f.owasp_llm) for f in findings)


class TestParallelEqualsSerial(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        d = Path(self._dir.name)
        for name, body in _FILES.items():
            (d / name).write_text(body)
        self.root = self._dir.name
        self.serial = _keyset(Scanner(jobs=1).scan(self.root).findings)

    def tearDown(self):
        self._dir.cleanup()

    def test_serial_finds_something(self):
        # Guard: if the fixture stops producing findings, the equality checks below
        # would pass vacuously. Require a non-trivial, multi-file finding set.
        self.assertGreaterEqual(len(self.serial), 5)
        self.assertGreaterEqual(len({k[0] for k in self.serial}), 3)

    def test_parallel_matches_serial(self):
        # jobs is forced (> the auto threshold), so these run through the process pool
        # even though the fixture is tiny.
        for jobs in (2, 3, 6):
            parallel = _keyset(Scanner(jobs=jobs).scan(self.root).findings)
            self.assertEqual(parallel, self.serial, msg=f"jobs={jobs} diverged from serial")


if __name__ == "__main__":
    unittest.main()
