"""The parallel SlimIndex must be equivalent to the serial project index.

Parallel scanning builds the Python cross-module index by extracting picklable
per-file records in workers and reducing them in the parent (project.assemble_slim),
instead of the serial project.build_index. For findings to stay identical, the
reduced SlimIndex must match the serial index for every field the per-file
cross-module queries read: summaries, imports, and tool-reachability. This test
asserts that equivalence on a multi-module project with imports, a re-export chain,
and a cross-module tool sink.
"""
import tempfile
import unittest
from pathlib import Path

from orthosec.core.scanner import ScanContext
from orthosec.analysis import project as P

_FILES = {
    "app.py": (
        "from helpers.shell import run_shell\n"
        "from api import handler\n\n"
        "def main(client):\n"
        "    out = client.chat.completions.create(model='x', messages=m).choices[0].message.content\n"
        "    run_shell(out)\n"
    ),
    "helpers/__init__.py": "",
    "helpers/shell.py": (
        "import subprocess\n\n"
        "def run_shell(cmd):\n"
        "    subprocess.run(cmd, shell=True)\n"
    ),
    # re-export chain: api re-exports run_shell from helpers.shell
    "api.py": "from helpers.shell import run_shell\n\ndef handler(x):\n    run_shell(x)\n",
    "tools.py": (
        "import os\n\n"
        "def do_delete(path):\n"
        "    os.remove(path)\n\n"
        "def wrapper(p):\n"
        "    do_delete(p)\n"
    ),
    "safe.py": "def add(a, b):\n    return a + b\n",
}


class TestSlimIndexEquivalence(unittest.TestCase):
    def _indexes(self, root):
        files = [p for p in Path(root).rglob("*.py")]
        ctx = ScanContext(root=Path(root), files=files)
        serial = P.build_index(ctx)
        P._tool_reachability(serial)
        slim = P.assemble_slim(P.extract_records(Path(root), files))
        return serial, slim

    def test_equivalent(self):
        with tempfile.TemporaryDirectory() as d:
            for name, body in _FILES.items():
                p = Path(d) / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(body)
            serial, slim = self._indexes(d)

            self.assertEqual(set(serial.summaries), set(slim.summaries))
            for k, s in serial.summaries.items():
                z = slim.summaries[k]
                self.assertEqual((s.params, s.sink_params, s.prompt_params),
                                 (z.params, z.sink_params, z.prompt_params), msg=f"summary {k}")
            self.assertEqual(serial.imports, slim.imports)
            self.assertEqual(serial._tool_reach, slim._tool_reach)

    def test_slim_has_no_heavy_fields(self):
        # SlimIndex must stay lightweight/picklable — no ast trees or FunctionDef nodes.
        with tempfile.TemporaryDirectory() as d:
            for name, body in _FILES.items():
                p = Path(d) / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(body)
            _, slim = self._indexes(d)
            self.assertEqual(slim.modules, {})
            self.assertEqual(slim.func_nodes, {})
            import pickle
            pickle.loads(pickle.dumps(slim))  # must round-trip


if __name__ == "__main__":
    unittest.main()
