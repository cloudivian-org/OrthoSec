"""AST analysis tests — tool-function discovery, sink detection, confirmation gate."""
import unittest

from orthosec.analysis.pyast import (safe_parse, find_tool_functions,
                                     dangerous_sinks, has_confirmation)
from orthosec.core.scanner import Scanner


class TestPyAst(unittest.TestCase):
    def test_far_sink_tool_detected(self):
        src = (
            "import subprocess\n"
            "def register():\n"
            "    tools = [{'type': 'function', 'name': 'run'}]\n"
            + "".join(f"    x{i} = {i}\n" for i in range(20))
            + "    def run(cmd):\n"
            "        return subprocess.run(cmd, shell=True)\n"
            "    return tools\n"
        )
        tree = safe_parse(src)
        tool_fns = find_tool_functions(tree)
        self.assertIn("run", tool_fns)
        sinks = dangerous_sinks(tool_fns["run"], src.splitlines())
        self.assertTrue(any("shell" in s.capability for s in sinks))

    def test_decorator_tool_and_confirmation(self):
        src = (
            "@tool\n"
            "def deploy(target):\n"
            "    if not require_approval(target):\n"
            "        return 'denied'\n"
            "    os.system('deploy ' + target)\n"
        )
        tree = safe_parse(src)
        fns = find_tool_functions(tree)
        self.assertIn("deploy", fns)
        self.assertTrue(has_confirmation(fns["deploy"]))

    def test_non_tool_function_not_flagged(self):
        # subprocess in a plain function that is NOT registered as a tool.
        src = "import subprocess\ndef build():\n    subprocess.run(['make'])\n"
        self.assertEqual(find_tool_functions(safe_parse(src)), {})

    def test_far_sink_end_to_end_critical(self):
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        findings = Scanner().scan(root / "benchmark/adversarial/adv_tool_far_sink.py").findings
        self.assertTrue(any(f.owasp_llm == "LLM06" and f.severity.name == "CRITICAL" for f in findings))


if __name__ == "__main__":
    unittest.main()
